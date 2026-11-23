"""Verified-TLS clients for Wazuh 4.14 manager logtest and alert indices.

Replay follows the documented ``PUT /logtest`` session protocol. Indexer
queries return a complete bounded window or raise: partial data must never
make a negative control look successful. This module does not claim to
observe raw event delivery or the manager archive.

References:
https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import http.client
import json
import math
from pathlib import Path
import re
import socket
import ssl
import threading
from typing import Any
from urllib import error, parse, request

from . import __version__


class WazuhError(RuntimeError):
    """A bounded, credential-free transport or response validation error."""


class WazuhConfigError(WazuhError, ValueError):
    """Invalid adapter configuration; no external request was made."""


class WazuhCancelled(WazuhError):
    """Replay was cancelled; its logtest session has been closed if known."""


def _validated_url(value: Any, name: str) -> str:
    if value == "":
        return ""
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise WazuhConfigError(f"{name} must be a bounded URL without whitespace")
    try:
        parts = parse.urlsplit(value)
        port = parts.port
    except ValueError:
        raise WazuhConfigError(f"{name} is invalid") from None
    if (parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or port == 0):
        raise WazuhConfigError(f"{name} must be an HTTP(S) URL without credentials, query, or fragment")
    host = parts.hostname
    if parts.scheme == "http":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise WazuhConfigError(f"{name}: HTTP is permitted only on a loopback address; use verified HTTPS")
    # Base paths are supported, but encoded separators and dot traversal are not.
    decoded_path = parse.unquote(parts.path)
    if any(p in {".", ".."} for p in decoded_path.split("/")) or "\\" in decoded_path:
        raise WazuhConfigError(f"{name} contains an unsafe base path")
    return value.rstrip("/")


@dataclass(frozen=True)
class WazuhConfig:
    manager_url: str = ""
    manager_username: str = ""
    manager_password: str = field(default="", repr=False)
    indexer_url: str = ""
    indexer_username: str = ""
    indexer_password: str = field(default="", repr=False)
    ca_file: str | None = None
    request_timeout: float = 10.0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "WazuhConfig":
        if not isinstance(value, dict):
            raise WazuhConfigError("wazuh configuration must be an object")
        allowed = set(cls.__dataclass_fields__)
        if set(value) - allowed:
            raise WazuhConfigError("Unknown wazuh configuration field")
        obj = cls(**value)
        for name in ("manager_url", "indexer_url"):
            object.__setattr__(obj, name, _validated_url(getattr(obj, name), name))
        for name in ("manager_username", "manager_password", "indexer_username", "indexer_password"):
            text = getattr(obj, name)
            if not isinstance(text, str) or len(text) > 4096 or "\r" in text or "\n" in text:
                raise WazuhConfigError(f"{name} must be a bounded string without newlines")
            if name.endswith("username") and ":" in text:
                raise WazuhConfigError(f"{name} cannot contain a colon")
        timeout = obj.request_timeout
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0.1 <= timeout <= 60):
            raise WazuhConfigError("request_timeout must be between 0.1 and 60 seconds")
        if obj.ca_file is not None:
            if not isinstance(obj.ca_file, str) or not obj.ca_file or not Path(obj.ca_file).is_file():
                raise WazuhConfigError("ca_file must name an existing CA certificate file")
        return obj


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode("ascii")


def _time(value: str, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise WazuhConfigError(f"{name} must be an ISO-8601 timestamp with a timezone")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WazuhConfigError(f"{name} must be an ISO-8601 timestamp with a timezone") from None
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise WazuhConfigError(f"{name} must include a timezone")
    return stamp


def _field(obj: dict[str, Any], dotted: str) -> Any:
    value: Any = obj
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _predicates(items: Any) -> list[tuple[str, str, Any]]:
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > 30:
        raise WazuhConfigError("predicates must be a list of at most 30 items")
    result = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"field", "op", "value"}:
            raise WazuhConfigError("Each predicate needs exactly field, op, and value")
        name, op, value = item["field"], item["op"], item["value"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,7}", name):
            raise WazuhConfigError("Invalid predicate field")
        if not isinstance(op, str) or op not in {"eq", "in", "contains", "regex"}:
            raise WazuhConfigError("Unsupported predicate operator")
        if op == "in":
            if not isinstance(value, list) or not value or len(value) > 100:
                raise WazuhConfigError("in predicate requires 1..100 scalar values")
            values = value
        else:
            values = [value]
        if any(not isinstance(v, (str, int, float, bool)) or (isinstance(v, str) and len(v) > 2048)
               or (isinstance(v, float) and not math.isfinite(v)) for v in values):
            raise WazuhConfigError("Predicate values must be bounded scalars")
        if op in {"contains", "regex"} and not isinstance(value, str):
            raise WazuhConfigError(f"{op} predicate needs a string")
        if op == "regex":
            # A deliberately small non-backtracking-prone subset. The scenario
            # evaluator validates its own regex policy too. Exact path matching
            # is recommended for live evidence correlation.
            if (len(value) > 256 or re.search(r"[(){}|]|\\[1-9gk]", value)
                    or len(re.findall(r"(?<!\\)[*+?]", value)) > 1):
                raise WazuhConfigError("regex predicate exceeds the safe subset")
            try:
                value = re.compile(value)
            except re.error:
                raise WazuhConfigError("Invalid regex predicate") from None
        result.append((name, op, value))
    return result


def _matches(alert: dict[str, Any], predicates: list[tuple[str, str, Any]]) -> bool:
    for name, op, wanted in predicates:
        value = _field(alert, name)
        if op == "eq" and (type(value) is not type(wanted) or value != wanted):
            return False
        if op == "in" and not any(type(value) is type(v) and value == v for v in wanted):
            return False
        if op == "contains" and not ((isinstance(value, str) and wanted in value)
                                     or (isinstance(value, list) and wanted in value)):
            return False
        if op == "regex" and not (isinstance(value, str) and len(value) <= 8192 and wanted.search(value)):
            return False
    return True


class WazuhClient:
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    MAX_ALERTS = 1000
    MAX_REPLAY_LOGS = 1000

    def __init__(self, config: WazuhConfig):
        if not isinstance(config, WazuhConfig):
            raise WazuhConfigError("WazuhClient requires WazuhConfig")
        # Validate direct construction as strictly as from_dict construction.
        self.config = WazuhConfig.from_dict({name: getattr(config, name) for name in config.__dataclass_fields__})
        try:
            context = ssl.create_default_context(cafile=self.config.ca_file)
        except (OSError, ssl.SSLError):
            raise WazuhConfigError("Cannot load trusted CA certificates") from None
        self._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect(), request.HTTPSHandler(context=context))
        self._token: str | None = None

    def _request(self, base: str, method: str, path: str, *, auth: str,
                 payload: Any = None, raw: bool = False, phase: str = "Wazuh request") -> Any:
        body = None if payload is None else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        headers = {"Authorization": auth, "Accept": "application/json", "User-Agent": f"Seori/{__version__}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(base + path, data=body, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.config.request_timeout) as response:
                if response.status != 200:
                    raise WazuhError(f"{phase} failed: unexpected HTTP status")
                data = response.read(self.MAX_RESPONSE_BYTES + 1)
                if len(data) > self.MAX_RESPONSE_BYTES:
                    raise WazuhError(f"{phase} failed: response exceeds size limit")
        except error.HTTPError as exc:
            # No server body, reason phrase, token, URL, or credential appears in errors.
            raise WazuhError(f"{phase} failed: HTTP {exc.code}") from None
        except (error.URLError, OSError, socket.timeout, ssl.SSLError, http.client.HTTPException):
            raise WazuhError(f"{phase} failed: connection, timeout, or TLS verification error") from None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise WazuhError(f"{phase} failed: response is not UTF-8") from None
        if raw:
            return text.strip()
        try:
            value = json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, RecursionError):
            raise WazuhError(f"{phase} failed: malformed JSON") from None
        if not isinstance(value, dict):
            raise WazuhError(f"{phase} failed: JSON object required")
        return value

    def _manager_auth(self) -> str:
        c = self.config
        if not c.manager_url or not c.manager_username or not c.manager_password:
            raise WazuhConfigError("Replay requires manager_url, manager_username, and manager_password")
        token = self._request(c.manager_url, "POST", "/security/user/authenticate?raw=true",
                              auth=_basic(c.manager_username, c.manager_password), raw=True, phase="Manager authentication")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,16384}", token):
            raise WazuhError("Manager authentication failed: malformed token")
        self._token = token
        return token

    def _manager(self, method: str, path: str, payload: Any = None) -> dict[str, Any]:
        token = self._token or self._manager_auth()
        response = self._request(self.config.manager_url, method, path, auth="Bearer " + token,
                                 payload=payload, phase="Manager API")
        if type(response.get("error")) is not int or response["error"] != 0:
            raise WazuhError("Manager API failed: nonzero or missing API error status")
        if not isinstance(response.get("data"), dict):
            raise WazuhError("Manager API failed: missing data object")
        return response["data"]

    def replay(self, logs: list[str], cancel: threading.Event | None = None) -> list[dict[str, Any]]:
        if (not isinstance(logs, list) or not 1 <= len(logs) <= self.MAX_REPLAY_LOGS
                or any(not isinstance(x, str) or not x or len(x.encode()) > 65536 or "\x00" in x for x in logs)):
            raise WazuhConfigError("replay needs 1..1000 nonempty log strings of at most 64 KiB")
        if cancel is not None and cancel.is_set():
            raise WazuhCancelled("Replay cancelled before execution")
        self._token = None
        self._manager_auth()
        sessions: set[str] = set()
        current: str | None = None
        alerts = []
        problem: BaseException | None = None
        try:
            for log in logs:
                if cancel is not None and cancel.is_set():
                    raise WazuhCancelled("Replay cancelled")
                payload = {"event": log, "log_format": "syslog", "location": "detectionci->replay"}
                if current:
                    payload["token"] = current
                data = self._manager("PUT", "/logtest", payload)
                token = data.get("token")
                if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token):
                    raise WazuhError("Logtest returned a missing or invalid session token")
                sessions.add(token)
                if current is not None and token != current:
                    raise WazuhError("Logtest session changed mid-replay; correlation state was lost")
                current = token
                if type(data.get("codemsg")) is not int or data["codemsg"] != 0:
                    raise WazuhError("Logtest reported an execution error")
                if type(data.get("alert")) is not bool or not isinstance(data.get("output"), dict):
                    raise WazuhError("Logtest returned an incomplete processing result")
                if data["alert"]:
                    output = data["output"]
                    if (not isinstance(output.get("rule"), dict)
                            or not isinstance(output["rule"].get("id"), str)
                            or not isinstance(output.get("timestamp"), str)):
                        raise WazuhError("Logtest alert is missing its rule ID or timestamp")
                    alerts.append(output)
            if cancel is not None and cancel.is_set():
                raise WazuhCancelled("Replay cancelled")
        except BaseException as exc:
            problem = exc
        cleanup_failed = False
        for token in sorted(sessions):
            try:
                self._manager("DELETE", "/logtest/sessions/" + parse.quote(token, safe=""))
            except WazuhError:
                cleanup_failed = True
        if cleanup_failed:
            raise WazuhError("Logtest session cleanup failed; replay result is not valid") from None
        if problem is not None:
            raise problem
        return alerts

    def search_alerts(self, agent_id: str, start: str, end: str,
                      predicates: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        if not isinstance(agent_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent_id):
            raise WazuhConfigError("agent_id must be a bounded identifier")
        start_time, end_time = _time(start, "start"), _time(end, "end")
        if end_time < start_time:
            raise WazuhConfigError("end must not precede start")
        compiled = _predicates(predicates)
        c = self.config
        if not c.indexer_url or not c.indexer_username or not c.indexer_password:
            raise WazuhConfigError("Live search requires indexer_url, indexer_username, and indexer_password")
        # Predicates are evaluated locally against _source. This avoids assuming
        # a .keyword subfield on custom dynamic mappings and never interpolates
        # user-controlled query-string syntax. The time/identity window is capped.
        payload = {
            "size": self.MAX_ALERTS + 1,
            "track_total_hits": True,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"filter": [
                {"term": {"agent.id": agent_id}},
                {"range": {"timestamp": {"gte": start, "lte": end}}},
            ]}},
        }
        data = self._request(c.indexer_url, "POST", "/wazuh-alerts-4.x-*/_search",
                             auth=_basic(c.indexer_username, c.indexer_password), payload=payload, phase="Indexer search")
        if data.get("timed_out") is not False or data.get("terminated_early", False) is not False:
            raise WazuhError("Indexer search is incomplete or timed out")
        shards = data.get("_shards")
        if (not isinstance(shards, dict) or type(shards.get("failed")) is not int or shards["failed"] != 0
                or type(shards.get("total")) is not int or shards["total"] < 1
                or type(shards.get("successful")) is not int or shards["successful"] != shards["total"]):
            raise WazuhError("Indexer search has missing or failed shard status")
        hits = data.get("hits")
        if not isinstance(hits, dict) or not isinstance(hits.get("hits"), list):
            raise WazuhError("Indexer search returned malformed hits")
        total = hits.get("total")
        if isinstance(total, dict):
            if total.get("relation") != "eq":
                raise WazuhError("Indexer search total is not exact")
            total = total.get("value")
        if type(total) is not int or total < 0 or total > self.MAX_ALERTS:
            raise WazuhError("Indexer search exceeds the complete-window alert limit")
        if len(hits["hits"]) != total:
            raise WazuhError("Indexer search is truncated; incomplete windows are rejected")
        output = []
        identities: set[tuple[str, str]] = set()
        for hit in hits["hits"]:
            if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                raise WazuhError("Indexer search contains malformed source documents")
            alert = hit["_source"]
            identity = (str(hit.get("_index", "")), str(hit.get("_id", "")))
            if identity[1] and identity in identities:
                raise WazuhError("Indexer search contains duplicate document IDs")
            identities.add(identity)
            try:
                stamp = _time(alert.get("timestamp"), "alert timestamp")
            except WazuhConfigError:
                raise WazuhError("Indexer alert contains an invalid timestamp") from None
            if _field(alert, "agent.id") != agent_id or not start_time <= stamp <= end_time:
                raise WazuhError("Indexer returned evidence outside the requested identity/time window")
            if _matches(alert, compiled):
                output.append(alert)
        return output

    def health(self) -> dict[str, Any]:
        output: dict[str, Any] = {"scope": "connectivity_only"}
        for kind in ("manager", "indexer"):
            url = getattr(self.config, kind + "_url")
            item: dict[str, Any] = {"configured": bool(url), "available": False}
            if not url:
                item["error"] = "Not configured"
                output[kind] = item
                continue
            try:
                if kind == "manager":
                    self._token = None
                    data = self._manager("GET", "/")
                    version = data.get("api_version")
                    if not isinstance(version, str) or not 1 <= len(version) <= 128:
                        raise WazuhError("Manager connectivity response has no valid API version")
                    item["version"] = version
                else:
                    if not self.config.indexer_username or not self.config.indexer_password:
                        raise WazuhConfigError("Indexer credentials are missing")
                    data = self._request(url, "GET", "/", auth=_basic(self.config.indexer_username, self.config.indexer_password), phase="Indexer connectivity")
                    version = data.get("version")
                    if not isinstance(version, dict):
                        raise WazuhError("Indexer connectivity response is malformed")
                    number = version.get("number")
                    if not isinstance(number, str) or not 1 <= len(number) <= 128:
                        raise WazuhError("Indexer connectivity response has no valid version")
                    item["version"] = number
                item["available"] = True
            except WazuhError as exc:
                item["error"] = str(exc)
            output[kind] = item
        return output
