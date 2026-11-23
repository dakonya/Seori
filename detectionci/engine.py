"""Execution of fixture, Wazuh replay and isolated SSH/FIM checks.

Fixture results validate the evaluator only. Live results never use fixture data.
The remote helper has a fixed action catalogue and a fixed filesystem root.
"""

from __future__ import annotations

import copy
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
import uuid

from . import __version__
from .models import canonical_json, digest, evaluate, get_field, utcnow, validate_scenario
from .wazuh import WazuhClient, WazuhConfig, WazuhError


WATCH_ROOT = "/var/lib/detectionci/watch"
MAX_SSH_OUTPUT = 131072
LIVE_ACTIONS = frozenset({"file_create", "file_modify", "file_delete"})


class EngineError(RuntimeError):
    """A check could not be executed reliably."""


class EngineCancelled(EngineError):
    """Cancellation was requested, including during an external operation."""


# stdin contains only this trusted source. The sole argument is encoded JSON,
# limited to catalogue values validated a second time on the remote side.
REMOTE_HELPER = r'''
import base64, hashlib, json, os, stat, sys, uuid
p = json.loads(base64.b64decode(sys.argv[1], validate=True))
if set(p) != {"operation", "action", "run_id"}:
    raise ValueError("invalid helper payload")
run_id = str(uuid.UUID(p["run_id"]))
if run_id != p["run_id"]:
    raise ValueError("non-canonical run id")
operation, action = p["operation"], p["action"]
if operation not in {"prepare", "execute", "cleanup"} or action not in {"file_create", "file_modify", "file_delete"}:
    raise ValueError("unsupported operation")
base = "/var/lib/detectionci/watch"
if os.path.realpath(base) != base:
    raise ValueError("watch root contains a symlink")
fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
name = run_id + ".txt"
def exists():
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError("unexpected file type or hard link")
    return True
def create(content):
    f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.write(f, content)
        os.fsync(f)
    finally:
        os.close(f)
def checksum():
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        return hashlib.sha256(os.read(f, 4096)).hexdigest()
    finally:
        os.close(f)
try:
    if operation == "prepare":
        if exists():
            raise ValueError("run file already exists; refusing reuse")
        if action in {"file_modify", "file_delete"}:
            create(b"detectionci baseline\n")
        out = {"ok": True, "source_verified": True, "exists": exists()}
    elif operation == "execute":
        if action == "file_create":
            create(b"detectionci controlled change\n")
        elif action == "file_modify":
            if not exists():
                raise ValueError("missing baseline file")
            f = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                current = os.fstat(f)
                if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                    raise ValueError("unexpected opened file type or hard link")
                os.ftruncate(f, 0)
                os.write(f, b"detectionci controlled modification\n")
                os.fsync(f)
            finally:
                os.close(f)
        else:
            if not exists():
                raise ValueError("missing baseline file")
            os.unlink(name, dir_fd=fd)
        present = exists()
        expected = action != "file_delete"
        out = {"ok": present == expected, "source_verified": present == expected,
               "exists": present, "sha256": checksum() if present else None}
    else:
        if exists():
            os.unlink(name, dir_fd=fd)
        out = {"ok": not exists(), "clean": not exists(), "source_verified": True}
    print(json.dumps(out))
finally:
    os.close(fd)
'''


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _point(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _evidence(kind: str, data: Any) -> dict[str, Any]:
    return {"id": str(uuid.uuid4()), "kind": kind, "data": data, "sha256": digest(data)}


def _result(verdict: str, summary: str, checkpoints=None) -> dict[str, Any]:
    return {"verdict": verdict, "summary": summary,
            "checkpoints": checkpoints or [], "assertions": [], "evidence": [], "metadata": {}}


def _redacted_config(config: Any) -> Any:
    if isinstance(config, dict):
        return {k: "[REDACTED]" if re.search(r"password|secret|token", k, re.I)
                else _redacted_config(v) for k, v in config.items()}
    if isinstance(config, list):
        return [_redacted_config(v) for v in config]
    if isinstance(config, float) and not math.isfinite(config):
        return "[INVALID-NONFINITE]"
    if config is not None and not isinstance(config, (str, int, float, bool)):
        return "[INVALID-" + type(config).__name__ + "]"
    return config


class Engine:
    """Execute one persisted run, with injectable transports for offline tests."""

    def __init__(self, config: dict | None = None, *, client_factory: Callable | None = None,
                 action_executor: Callable | None = None):
        self.config = copy.deepcopy(config or {})
        self._client_factory = client_factory or (lambda cfg: WazuhClient(WazuhConfig.from_dict(cfg)))
        self._action_executor = action_executor or self._ssh_operation

    def execute(self, run: dict, cancel: threading.Event | None = None) -> dict:
        cancel = cancel or threading.Event()
        mode = run.get("mode", "")
        started = time.monotonic()
        checkpoints: list[dict] = []
        external_systems_contacted = False
        io_state = {"contacted": False}
        deadline_reached = threading.Event()
        replay_timer = None
        try:
            if mode not in {"fixture", "replay", "live"}:
                raise ValueError("mode must be fixture, replay, or live")
            scenario = validate_scenario(copy.deepcopy(run["scenario"]))
            if cancel.is_set():
                raise EngineCancelled("Cancelled before execution")
            if mode == "fixture":
                fixture = scenario.get("fixture")
                if not isinstance(fixture, dict):
                    raise ValueError("Scenario has no fixture")
                result = evaluate(scenario, fixture.get("alerts", []), fixture.get("checkpoints", []))
                result["metadata"].update({"fixture_only": True,
                    "fixture_fault": fixture.get("fault"), "external_systems_contacted": False})
            elif mode == "replay":
                logs = scenario.get("replay")
                if not isinstance(logs, list) or not logs:
                    raise ValueError("Replay requires at least one raw log line")
                client = self._client(scenario["timeout_seconds"])
                external_systems_contacted = True
                def timeout_replay():
                    deadline_reached.set()
                    cancel.set()
                replay_timer = threading.Timer(scenario["timeout_seconds"], timeout_replay)
                replay_timer.daemon = True
                replay_timer.start()
                alerts = client.replay(logs, cancel=cancel)
                if cancel.is_set():
                    raise EngineCancelled("Cancelled during Wazuh replay")
                check = copy.deepcopy(scenario)
                check["expect"]["required_checkpoints"] = []
                result = evaluate(check, alerts, None)
                result["evidence"].append(_evidence("replay_input_hash", {"lines": len(logs), "sha256": digest(logs)}))
                result["metadata"].update({"fixture_only": False,
                    "external_systems_contacted": True,
                    "limitation": "Checks supplied log decoding/rules only; does not validate endpoint collection or delivery."})
            else:
                result = self._live(run, scenario, cancel, io_state)
        except EngineCancelled as exc:
            result = _result("CANCELLED", self._safe_error(exc), checkpoints)
        except (ValueError, KeyError, TypeError, OSError, EngineError, WazuhError) as exc:
            if cancel.is_set():
                result = _result("CANCELLED", "Cancelled: " + self._safe_error(exc), checkpoints)
            else:
                result = _result("ERROR", self._safe_error(exc), checkpoints)
        finally:
            if replay_timer is not None:
                replay_timer.cancel()
        if deadline_reached.is_set():
            result["verdict"] = "ERROR"
            result["summary"] = "Replay scenario deadline exceeded; " + result.get("summary", "")
        scope = {"fixture": "fixture_logic", "replay": "wazuh_rules", "live": "live_fim_path"}.get(mode, "unknown")
        result.setdefault("metadata", {}).update({"mode": mode, "validation_scope": scope,
            "engine_version": __version__, "finished_at": utcnow(),
            "duration_seconds": round(time.monotonic() - started, 4),
            "operator_config_sha256": digest(_redacted_config(self.config)),
            "config_attestation": "Operator configuration hash; not an attestation of loaded SIEM rules."})
        result["metadata"].setdefault("external_systems_contacted", external_systems_contacted or io_state["contacted"])
        sanitized = self._sanitize(result)
        # Known protocol values are not secrets, even when a configured password
        # happens to equal a short word such as "PASS" or "live".
        sanitized["verdict"] = result["verdict"]
        for key in ("mode", "validation_scope", "engine_version"):
            sanitized["metadata"][key] = result["metadata"][key]
        for original, exported in zip(result.get("checkpoints", []), sanitized.get("checkpoints", [])):
            exported["status"] = original["status"]
        for original, exported in zip(result.get("assertions", []), sanitized.get("assertions", [])):
            exported["verdict"] = original["verdict"]
        for item in sanitized.get("evidence", []):
            item["sha256"] = digest(item["data"])
        sanitized["metadata"]["evidence_hash_scope"] = "SHA-256 of exported, redacted evidence data"
        return sanitized

    def _client(self, timeout_seconds=None):
        cfg = self.config.get("wazuh")
        if not isinstance(cfg, dict) or not cfg:
            raise ValueError("Mode requires a wazuh configuration; no synthetic fallback is used")
        cfg = copy.deepcopy(cfg)
        if timeout_seconds is not None:
            request_timeout = cfg.get("request_timeout", 10)
            if (isinstance(request_timeout, (int, float)) and not isinstance(request_timeout, bool)
                    and math.isfinite(request_timeout) and .1 <= request_timeout <= 60):
                cfg["request_timeout"] = max(.1, min(request_timeout, timeout_seconds))
        return self._client_factory(cfg)

    def _safe_error(self, exc: BaseException) -> str:
        message = str(exc)[:2000]
        def secrets(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if re.search(r"password|secret|token", key, re.I) and isinstance(item, str) and item:
                        yield item
                    else:
                        yield from secrets(item)
            elif isinstance(value, list):
                for item in value:
                    yield from secrets(item)
        for secret in sorted(secrets(self.config), key=len, reverse=True):
            message = message.replace(secret, "[REDACTED]")
        return message or type(exc).__name__

    def _sanitize(self, value: Any) -> Any:
        """Redact sensitive keys and configured secret values before persistence."""
        if isinstance(value, dict):
            return {k: "[REDACTED]" if re.search(r"password|secret|token|authorization|cookie", k, re.I)
                    else self._sanitize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize(v) for v in value]
        if isinstance(value, str):
            return self._safe_error(ValueError(value)) if len(value) <= 2000 else self._sanitize_long(value)
        return value

    def _sanitize_long(self, value: str) -> str:
        # Retain bounded event strings while removing literal configured secrets.
        parts = [self._safe_error(ValueError(value[i:i + 2000])) for i in range(0, len(value), 2000)]
        joined = "".join(parts)
        def replace_secrets(obj):
            nonlocal joined
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if re.search(r"password|secret|token", key, re.I) and isinstance(val, str) and val:
                        joined = joined.replace(val, "[REDACTED]")
                    else:
                        replace_secrets(val)
        replace_secrets(self.config)
        return joined

    def _target(self) -> dict:
        cfg = copy.deepcopy(self.config.get("live"))
        if not isinstance(cfg, dict):
            raise ValueError("Live mode requires an explicitly configured laboratory SSH target")
        for field in ("host", "user", "identity_file", "known_hosts", "agent_id"):
            if not isinstance(cfg.get(field), str) or not cfg[field]:
                raise ValueError(f"live.{field} is required")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}", cfg["host"]):
            raise ValueError("live.host must be a hostname or IP, without SSH options")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", cfg["user"]):
            raise ValueError("live.user is invalid")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", cfg["agent_id"]):
            raise ValueError("live.agent_id is invalid")
        cfg.setdefault("port", 22)
        if isinstance(cfg["port"], bool) or not isinstance(cfg["port"], int) or not 1 <= cfg["port"] <= 65535:
            raise ValueError("live.port must be 1..65535")
        for field in ("identity_file", "known_hosts"):
            value = cfg[field]
            if not os.path.isabs(value) or any(c in value for c in "\x00\n\r") or not Path(value).is_file():
                raise ValueError(f"live.{field} must name an existing absolute file")
        if cfg.get("watch_root", WATCH_ROOT) != WATCH_ROOT:
            raise ValueError(f"live.watch_root must be {WATCH_ROOT}")
        cfg["watch_root"] = WATCH_ROOT
        for field, default, low, high in (("poll_interval_seconds", .5, .05, 10),
                                          ("ssh_timeout_seconds", 15, 1, 60),
                                          ("clock_skew_seconds", 2, 0, 30)):
            value = cfg.get(field, default)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"live.{field} must be between {low} and {high}")
            cfg[field] = value
        return cfg

    def _live(self, run: dict, scenario: dict, cancel: threading.Event, io_state: dict) -> dict:
        target = self._target()
        action = scenario.get("action", {})
        kind = action.get("type") if isinstance(action, dict) else None
        if kind not in LIVE_ACTIONS:
            raise ValueError("Live mode supports only file_create, file_modify, and file_delete")
        try:
            run_id = str(uuid.UUID(run["id"]))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError("Live run ID must be a canonical UUID") from exc
        if run_id != run["id"]:
            raise ValueError("Live run ID must be a canonical UUID")
        client = self._client(scenario["timeout_seconds"])
        path = f"{WATCH_ROOT}/{run_id}.txt"
        deadline = time.monotonic() + scenario["timeout_seconds"]
        checkpoints: list[dict] = []
        evidence: list[dict] = []
        result = None
        cleanup_needed = False
        start = _stamp(datetime.now(timezone.utc))
        check = copy.deepcopy(scenario)
        check["expect"]["required_checkpoints"] = ["action", "source", "indexer", "cleanup"]
        check["expect"].setdefault("predicates", []).append({"field": "syscheck.path", "op": "eq", "value": path})
        observation_started = time.monotonic()
        try:
            # A successful bounded search confirms query access, not the entire collector.
            io_state["contacted"] = True
            client.search_alerts(target["agent_id"], start, utcnow(), predicates=[{"field": "syscheck.path", "op": "eq", "value": path}])
            checkpoints.append(_point("indexer", "observed", "Authenticated alert search completed; collection coverage is not implied"))
            if cancel.is_set():
                raise EngineCancelled("Cancelled before remote action")
            cleanup_needed = True  # set before prepare; timeout may leave a remote file
            prepared_at = _stamp(datetime.now(timezone.utc))
            prepared = self._operation(target, "prepare", kind, run_id, deadline, cancel)
            evidence.append(_evidence("remote_prepare", prepared))
            if prepared.get("ok") is not True or prepared.get("source_verified") is not True:
                raise EngineError("Remote preparation did not confirm the required file state")
            if kind != "file_create":
                baseline, _ = self._poll(client, target, path, prepared_at, deadline, cancel,
                                         [{"field": "syscheck.event", "op": "eq", "value": "added"}], stop_on_match=True)
                baseline = [item for item in baseline if get_field(item, "syscheck.event") == "added"]
                if not baseline:
                    checkpoints.append(_point("baseline", "missing", "FIM baseline creation was not observed before mutation"))
                    result = _result("FAIL", "Required FIM baseline was not observed before the deadline", checkpoints)
                    result["assertions"].append({"id": "baseline", "verdict": "FAIL", "message": "Baseline not indexed",
                                                  "expected": "syscheck.event=added", "actual": 0})
                else:
                    evidence.append(_evidence("baseline_alerts", baseline))
            if result is None:
                start = _stamp(datetime.now(timezone.utc))
                observation_started = time.monotonic()
                action_result = self._operation(target, "execute", kind, run_id, deadline, cancel)
                evidence.append(_evidence("remote_action", action_result))
                checkpoints.append(_point("action", "observed" if action_result.get("ok") is True else "missing", "Remote helper confirmed the requested operation"))
                checkpoints.append(_point("source", "observed" if action_result.get("source_verified") is True else "missing",
                    "Independent remote filesystem state; this is not an OS journal or manager-delivery checkpoint"))
                if action_result.get("ok") is not True or action_result.get("source_verified") is not True:
                    result = _result("FAIL", "Remote action or resulting filesystem state was not confirmed", checkpoints)
                else:
                    # Live negative cases cannot prove absence with this FIM-only adapter.
                    if scenario["expect"]["min_alerts"] == 0:
                        checkpoints.append(_point("collection-coverage", "unavailable",
                            "Absence of an alert cannot establish successful event collection in this live adapter"))
                        alerts, first_seen = self._poll(client, target, path, start, deadline, cancel,
                                                        scenario["expect"].get("predicates", []), stop_on_match=False)
                        check["expect"]["required_checkpoints"].append("collection-coverage")
                    else:
                        alerts, first_seen = self._poll(client, target, path, start, deadline, cancel,
                                                        scenario["expect"].get("predicates", []),
                                                        stop_on_match="max_alerts" not in scenario["expect"],
                                                        min_alerts=scenario["expect"]["min_alerts"])
                    # Cleanup is verified in finally before the final evaluation.
                    result = {"_alerts": alerts, "_first_seen": first_seen}
        except EngineCancelled as exc:
            result = _result("CANCELLED", self._safe_error(exc), checkpoints)
        except (OSError, ValueError, TypeError, EngineError, WazuhError) as exc:
            if cancel.is_set():
                result = _result("CANCELLED", "Cancelled during live execution", checkpoints)
            else:
                checkpoints.append(_point("execution", "unavailable", self._safe_error(exc)))
                result = _result("ERROR", self._safe_error(exc), checkpoints)
        finally:
            if cleanup_needed:
                try:
                    # Cleanup has its own deadline and intentionally ignores cancellation.
                    clean = self._operation(target, "cleanup", kind, run_id,
                                            time.monotonic() + target["ssh_timeout_seconds"], threading.Event())
                    evidence.append(_evidence("remote_cleanup", clean))
                    clean_ok = clean.get("ok") is True and clean.get("clean") is True
                    checkpoints.append(_point("cleanup", "observed" if clean_ok else "missing",
                        "Run file absence independently verified" if clean_ok else "Cleanup did not confirm file absence; restore the VM before reuse"))
                except (OSError, ValueError, EngineError) as exc:
                    clean_ok = False
                    checkpoints.append(_point("cleanup", "unavailable", self._safe_error(exc)))
            else:
                clean_ok = True
                checkpoints.append(_point("cleanup", "observed", "No remote action was started"))
        if result is None:
            result = _result("ERROR", "Live execution ended without a result", checkpoints)
        if "_alerts" in result:
            alerts = result["_alerts"]
            first_seen = result["_first_seen"]
            try:
                result = evaluate(check, alerts, checkpoints)
                result["metadata"]["observed_delay_seconds"] = round(first_seen - observation_started, 4) if first_seen is not None else None
            except ValueError as exc:
                result = _result("ERROR", self._safe_error(exc), checkpoints)
        else:
            result["checkpoints"] = checkpoints
        if not clean_ok and result["verdict"] == "PASS":
            result["verdict"] = "ERROR"
            result["summary"] = "Cleanup could not be confirmed; VM restoration is required"
        result["evidence"].extend(evidence)
        result.setdefault("metadata", {}).update({"fixture_only": False, "external_systems_contacted": True,
            "target_agent_id": target["agent_id"], "run_path": path,
            "cleanup_verified": clean_ok, "target_dirty": not clean_ok,
            "restore_required": not clean_ok,
            "time_window_start": start, "clock_skew_seconds": target["clock_skew_seconds"],
            "poll_interval_seconds": target["poll_interval_seconds"],
            "source_checkpoint_scope": "remote_filesystem_state",
            "unobserved_stages": ["OS journal", "agent delivery", "manager decoding"],
            "delay_definition": "Controller observation delay, including remote action, delivery, indexing and polling.",
            "recovery_limit": "No hypervisor snapshot API is configured; operator must restore the laboratory VM after failed cleanup or controller crash."})
        return result

    def _operation(self, target: dict, operation: str, action: str, run_id: str,
                   deadline: float, cancel: threading.Event) -> dict:
        if cancel.is_set():
            raise EngineCancelled("Cancelled before SSH operation")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EngineError("Scenario execution deadline exceeded")
        response = self._action_executor(target=target, operation=operation, action=action,
                                         run_id=run_id, timeout=min(remaining, target["ssh_timeout_seconds"]), cancel=cancel)
        if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
            raise EngineError("Remote helper returned an invalid response")
        return response

    @staticmethod
    def _matches(alert: dict, predicates: list[dict]) -> bool:
        for predicate in predicates:
            actual = get_field(alert, predicate["field"])
            expected = predicate["value"]
            op = predicate["op"]
            if op == "eq" and actual != expected:
                return False
            if op == "in" and actual not in expected:
                return False
            if op == "contains" and (not isinstance(actual, str) or expected not in actual):
                return False
            if op == "regex" and (not isinstance(actual, str) or re.search(expected, actual) is None):
                return False
        return True

    def _poll(self, client, target: dict, path: str, start: str, deadline: float,
              cancel: threading.Event, predicates: list[dict], *, stop_on_match: bool,
              min_alerts: int = 1) -> tuple[list[dict], float | None]:
        lower = _parse_time(start) - timedelta(seconds=target["clock_skew_seconds"])
        all_alerts: dict[str, dict] = {}
        evidence_bytes = 0
        first_seen = None
        while time.monotonic() < deadline:
            if cancel.is_set():
                raise EngineCancelled("Cancelled while waiting for alerts")
            upper = datetime.now(timezone.utc) + timedelta(seconds=target["clock_skew_seconds"])
            alerts = client.search_alerts(target["agent_id"], _stamp(lower), _stamp(upper),
                                          predicates=[{"field": "syscheck.path", "op": "eq", "value": path}])
            if time.monotonic() > deadline:
                # A response first observed after the scenario deadline cannot
                # establish an on-time detection, even if the search began earlier.
                break
            if not isinstance(alerts, list):
                raise EngineError("Indexer returned an invalid alert collection")
            for alert in alerts:
                if not isinstance(alert, dict):
                    raise EngineError("Indexer returned a non-object alert")
                if str(get_field(alert, "agent.id")) != target["agent_id"] or get_field(alert, "syscheck.path") != path:
                    continue
                try:
                    event_time = _parse_time(alert.get("timestamp"))
                except (ValueError, TypeError):
                    continue
                if lower <= event_time <= upper:
                    # Source fingerprint deduplicates repeated indexer polling.
                    fingerprint = digest(alert)
                    if fingerprint not in all_alerts:
                        evidence_bytes += len(canonical_json(alert).encode("utf-8"))
                        if len(all_alerts) >= 2000 or evidence_bytes > 4_194_304:
                            raise EngineError("Live evidence exceeds the bounded collection limit")
                        all_alerts[fingerprint] = alert
            matched = [a for a in all_alerts.values() if self._matches(a, predicates)]
            if matched and first_seen is None:
                first_seen = time.monotonic()
            if stop_on_match and len(matched) >= min_alerts:
                break
            cancel.wait(min(target["poll_interval_seconds"], max(0, deadline - time.monotonic())))
        return list(all_alerts.values()), first_seen

    @staticmethod
    def _ssh_operation(*, target: dict, operation: str, action: str, run_id: str,
                       timeout: float, cancel: threading.Event) -> dict:
        import base64
        payload = base64.b64encode(json.dumps({"operation": operation, "action": action,
                                               "run_id": run_id}, separators=(",", ":")).encode()).decode()
        command = ["ssh", "-p", str(target["port"]), "-i", target["identity_file"],
                   "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                   "-o", "UserKnownHostsFile=" + target["known_hosts"], "-o", "ConnectTimeout=" + str(max(1, math.ceil(timeout))),
                   "-o", "LogLevel=ERROR", "-o", "RequestTTY=no", "--", target["user"] + "@" + target["host"],
                   "python3", "-", payload]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        try:
            proc.stdin.write(REMOTE_HELPER.encode())
            proc.stdin.close()
            for name in buffers:
                stream = getattr(proc, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if cancel.is_set():
                    raise EngineCancelled("Cancelled during SSH operation")
                if time.monotonic() >= deadline:
                    raise EngineError("SSH operation timed out; remote state requires verification")
                for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 16384)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(chunk)
                        if sum(len(v) for v in buffers.values()) > MAX_SSH_OUTPUT:
                            raise EngineError("SSH helper output exceeded the size limit")
            proc.wait(timeout=max(.01, deadline - time.monotonic()))
            if proc.returncode != 0:
                raise EngineError("SSH helper failed (exit " + str(proc.returncode) + "): " +
                                  buffers["stderr"].decode("utf-8", "replace")[-1000:])
            try:
                value = json.loads(buffers["stdout"])
            except (ValueError, UnicodeError) as exc:
                raise EngineError("SSH helper returned malformed JSON") from exc
            if not isinstance(value, dict):
                raise EngineError("SSH helper returned a non-object response")
            return value
        except subprocess.TimeoutExpired as exc:
            raise EngineError("SSH process did not terminate before the deadline") from exc
        finally:
            selector.close()
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=1)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=1)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream and not stream.closed:
                    stream.close()
