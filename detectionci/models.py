"""Validated scenario contracts and deterministic detection assertions.

No network or execution happens in this module. A verdict is bounded by the
evidence supplied to it; unavailable checkpoints never become successful ones.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERDICTS = frozenset({"PASS", "FAIL", "ERROR", "INCONCLUSIVE", "CANCELLED"})
MAX_SCENARIO_BYTES = 1_048_576
MAX_ALERTS = 2_000
MAX_ALERT_BYTES = 262_144
MAX_REGEX_INPUT = 2_048
_SLUG = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(obj: Any) -> str:
    """Stable UTF-8 JSON representation; reject NaN, Infinity and non-JSON data."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _text(value: Any, label: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(f"{label} must be {'a' if empty else 'a non-empty'} string of at most {limit} characters")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain NUL")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise ValueError(f"{label} must be an object with string keys")
    return value


def _bounded_json(value: Any, label: str, maximum: int) -> None:
    def check(item: Any, depth: int = 0) -> None:
        if depth > 40:
            raise ValueError(f"{label} is nested too deeply")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError(f"{label} object keys must be strings")
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError(f"{label} contains a non-finite number")
        elif item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValueError(f"{label} contains non-JSON data")

    check(value)
    try:
        encoded = canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ValueError(f"{label} must contain finite, JSON-serializable data") from exc
    if len(encoded) > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")


def _safe_regex(pattern: str) -> re.Pattern:
    """Accept a deliberately small regex subset without nested repetition.

    Repetition can apply only to a single character/class, at most one unbounded
    repeat is permitted, branches/backreferences/lookarounds are excluded, and
    inputs are capped. Complex matching belongs in a reviewed engine extension.
    """
    _text(pattern, "regex value", 128)
    try:
        from re import _parser, _constants as constants

        tree = _parser.parse(pattern, 0)
        repeats = 0
        unbounded = 0
        simple = {constants.LITERAL, constants.NOT_LITERAL, constants.ANY, constants.IN}

        def visit(nodes: Any) -> None:
            nonlocal repeats, unbounded
            for op, arg in nodes:
                if op in {constants.LITERAL, constants.NOT_LITERAL, constants.ANY, constants.AT}:
                    continue
                if op == constants.IN:
                    for child_op, _ in arg:
                        if child_op not in {constants.LITERAL, constants.RANGE, constants.CATEGORY, constants.NEGATE}:
                            raise ValueError("regex character class is outside the supported subset")
                elif op == constants.SUBPATTERN:
                    visit(arg[3])
                elif op in {constants.MAX_REPEAT, constants.MIN_REPEAT}:
                    minimum, maximum, child = arg
                    repeats += 1
                    if len(child) != 1 or child[0][0] not in simple:
                        raise ValueError("regex repetition is supported only on one character or character class")
                    if maximum == constants.MAXREPEAT:
                        unbounded += 1
                    elif maximum > 64:
                        raise ValueError("bounded regex repetition must not exceed 64")
                    if minimum > 64 or repeats > 2 or unbounded > 1:
                        raise ValueError("regex has too much repetition")
                    visit(child)
                else:
                    raise ValueError("regex branches, lookarounds and backreferences are not supported")

        visit(tree)
        return re.compile(pattern)
    except (re.error, OverflowError) as exc:
        raise ValueError(f"invalid regex: {exc}") from exc


def validate_scenario(scenario: dict) -> dict:
    """Return an isolated normalized scenario or raise ValueError."""
    _object(scenario, "scenario")
    _bounded_json(scenario, "scenario", MAX_SCENARIO_BYTES)
    required = {"id", "version", "title", "description", "kind", "timeout_seconds", "expect"}
    absent = required - scenario.keys()
    if absent:
        raise ValueError("scenario is missing required fields: " + ", ".join(sorted(absent)))
    sid = _text(scenario["id"], "id", 96)
    if not _SLUG.fullmatch(sid):
        raise ValueError("id must be a lowercase hyphen-separated slug")
    if not _SEMVER.fullmatch(_text(scenario["version"], "version", 64)):
        raise ValueError("version must be a semantic version, for example 1.0.0")
    _text(scenario["title"], "title", 160)
    _text(scenario["description"], "description", 4_096)
    if not isinstance(scenario["kind"], str) or scenario["kind"] not in {"positive", "control"}:
        raise ValueError("kind must be positive or control")
    _integer(scenario["timeout_seconds"], "timeout_seconds", 1, 300)
    expect = _object(scenario["expect"], "expect")
    unexpected = set(expect) - {"min_alerts", "max_alerts", "predicates", "required_checkpoints"}
    if unexpected:
        raise ValueError("unknown expect fields: " + ", ".join(sorted(unexpected)))
    if "min_alerts" not in expect:
        raise ValueError("expect.min_alerts is required")
    minimum = _integer(expect["min_alerts"], "expect.min_alerts", 0, MAX_ALERTS)
    if "max_alerts" in expect:
        _integer(expect["max_alerts"], "expect.max_alerts", minimum, MAX_ALERTS)
    if scenario["kind"] == "control" and "max_alerts" not in expect:
        raise ValueError("control scenarios require expect.max_alerts")
    predicates = expect.get("predicates", [])
    if not isinstance(predicates, list) or len(predicates) > 32:
        raise ValueError("expect.predicates must be a list of at most 32 predicates")
    for i, predicate in enumerate(predicates):
        label = f"expect.predicates[{i}]"
        _object(predicate, label)
        if set(predicate) != {"field", "op", "value"}:
            raise ValueError(f"{label} requires exactly field, op and value")
        field = _text(predicate["field"], f"{label}.field", 160)
        if not _FIELD.fullmatch(field):
            raise ValueError(f"{label}.field must be a dotted object path")
        op, value = predicate["op"], predicate["value"]
        if not isinstance(op, str) or op not in {"eq", "in", "contains", "regex"}:
            raise ValueError(f"{label}.op is unsupported")
        if op == "in":
            if not isinstance(value, list) or not value or len(value) > 64:
                raise ValueError(f"{label}.value must be a non-empty list of at most 64 scalar values")
            if any(v is None or isinstance(v, (list, dict)) for v in value):
                raise ValueError(f"{label}.value must contain non-null scalar values")
        elif op in {"contains", "regex"}:
            _text(value, f"{label}.value", 4_096 if op == "contains" else 128)
            if op == "regex":
                _safe_regex(value)
        elif value is None or isinstance(value, (list, dict)):
            raise ValueError(f"{label}.value must be a non-null scalar value")
        if field == "rule.id":
            values = value if op == "in" else [value]
            if any(not isinstance(v, str) for v in values):
                raise ValueError("rule.id comparisons require string rule IDs")
    if "required_checkpoints" in expect:
        names = expect["required_checkpoints"]
        if not isinstance(names, list) or len(names) > 32 or len(names) != len(set(str(n) for n in names)):
            raise ValueError("expect.required_checkpoints must be a list of distinct names")
        for name in names:
            if not _SLUG.fullmatch(_text(name, "checkpoint name", 64)):
                raise ValueError("checkpoint name must be a slug")
    for key in ("techniques", "tags"):
        if key in scenario:
            if not isinstance(scenario[key], list) or len(scenario[key]) > 64:
                raise ValueError(f"{key} must be a list of at most 64 strings")
            for item in scenario[key]:
                _text(item, key, 128)
    if "metadata" in scenario:
        metadata = _object(scenario["metadata"], "metadata")
        if "supported_modes" in metadata:
            modes = metadata["supported_modes"]
            if (not isinstance(modes, list) or not modes or len(modes) > 3
                    or any(not isinstance(mode, str) or mode not in {"fixture", "replay", "live"} for mode in modes)
                    or len(modes) != len(set(modes))):
                raise ValueError("metadata.supported_modes must be a non-empty list of distinct fixture/replay/live values")
        if "expected_verdict" in metadata and (not isinstance(metadata["expected_verdict"], str) or metadata["expected_verdict"] not in VERDICTS):
            raise ValueError("metadata.expected_verdict must be a supported verdict")
    if "replay" in scenario:
        logs = scenario["replay"]
        if not isinstance(logs, list) or not logs or len(logs) > 200:
            raise ValueError("replay must contain between 1 and 200 log lines")
        for line in logs:
            _text(line, "replay line", 65_536)
    if "action" in scenario:
        action = _object(scenario["action"], "action")
        _text(action.get("type"), "action.type", 64)
    if "fixture" in scenario:
        fixture = _object(scenario["fixture"], "fixture")
        alerts = fixture.get("alerts", [])
        _validate_alerts(alerts)
        _validate_checkpoints(fixture.get("checkpoints", []))
        if "fault" in fixture:
            _text(fixture["fault"], "fixture.fault", 1_024)
    if "expected_verdict" in scenario and (not isinstance(scenario["expected_verdict"], str) or scenario["expected_verdict"] not in VERDICTS):
        raise ValueError("expected_verdict must be a supported verdict")
    normalized = copy.deepcopy(scenario)
    normalized["expect"].setdefault("predicates", [])
    return normalized


def load_scenario(path: str | Path) -> dict:
    """Read a bounded UTF-8 JSON scenario; JSON-only is intentional in v0.1."""
    try:
        with Path(path).open("rb") as handle:
            content = handle.read(MAX_SCENARIO_BYTES + 1)
        if len(content) > MAX_SCENARIO_BYTES:
            raise ValueError("scenario file is too large")
        def unique_keys(pairs: list[tuple[str, Any]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate scenario JSON key: {key}")
                result[key] = value
            return result

        return validate_scenario(json.loads(content.decode("utf-8"), object_pairs_hook=unique_keys))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"invalid scenario JSON: {exc}") from exc


def get_field(alert: dict, dotted_path: str) -> Any:
    current: Any = alert
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _validate_alerts(alerts: Any) -> None:
    if not isinstance(alerts, list) or len(alerts) > MAX_ALERTS:
        raise ValueError(f"alerts must be a list of at most {MAX_ALERTS} objects")
    for alert in alerts:
        _object(alert, "alert")
        _bounded_json(alert, "alert", MAX_ALERT_BYTES)
    _bounded_json(alerts, "alerts", 4_194_304)


def _validate_checkpoints(checkpoints: Any) -> None:
    if not isinstance(checkpoints, list) or len(checkpoints) > 32:
        raise ValueError("checkpoints must be a list of at most 32 objects")
    seen = set()
    for checkpoint in checkpoints:
        _object(checkpoint, "checkpoint")
        name = _text(checkpoint.get("name"), "checkpoint.name", 64)
        if not _SLUG.fullmatch(name) or name in seen:
            raise ValueError("checkpoint names must be unique slugs")
        seen.add(name)
        if not isinstance(checkpoint.get("status"), str) or checkpoint["status"] not in {"observed", "missing", "unavailable"}:
            raise ValueError("checkpoint.status must be observed, missing or unavailable")
        if "detail" in checkpoint:
            _text(checkpoint["detail"], "checkpoint.detail", 8_192, empty=True)


def _matches(alert: dict, predicates: list[dict]) -> bool:
    for predicate in predicates:
        actual = get_field(alert, predicate["field"])
        expected = predicate["value"]
        op = predicate["op"]
        if actual is None:
            return False
        if op == "eq":
            if type(actual) is not type(expected) or actual != expected:
                return False
        elif op == "in":
            if not any(type(actual) is type(item) and actual == item for item in expected):
                return False
        elif op == "contains":
            if not isinstance(actual, str) or expected not in actual:
                return False
        elif op == "regex":
            if not isinstance(actual, str):
                return False
            if len(actual) > MAX_REGEX_INPUT:
                raise ValueError(f"regex input exceeds {MAX_REGEX_INPUT} characters; comparison cannot be evaluated")
            if _safe_regex(expected).search(actual) is None:
                return False
    return True


def aggregate_verdict(verdicts: list[str]) -> str:
    if not verdicts:
        return "INCONCLUSIVE"
    if any(not isinstance(verdict, str) or verdict not in VERDICTS for verdict in verdicts):
        raise ValueError("unknown verdict")
    for verdict in ("ERROR", "CANCELLED", "FAIL", "INCONCLUSIVE", "PASS"):
        if verdict in verdicts:
            return verdict
    raise AssertionError("unreachable")


def evaluate(scenario: dict, alerts: list[dict], checkpoints: list[dict] | None = None) -> dict:
    scenario = validate_scenario(scenario)
    _validate_alerts(alerts)
    if checkpoints is not None:
        _validate_checkpoints(checkpoints)
    expect = scenario["expect"]
    matched = [alert for alert in alerts if _matches(alert, expect["predicates"])]
    minimum = expect["min_alerts"]
    maximum = expect.get("max_alerts")
    count_ok = len(matched) >= minimum and (maximum is None or len(matched) <= maximum)
    count_result = {
        "id": "matching-alert-count",
        "verdict": "PASS" if count_ok else "FAIL",
        "message": f"{len(matched)} matching alerts among {len(alerts)} observed alerts",
        "expected": {"min_alerts": minimum, "max_alerts": maximum},
        "actual": len(matched),
    }
    assertions = [count_result]
    observed = {checkpoint["name"]: checkpoint for checkpoint in checkpoints or []}
    defaults = ["action", "source", "manager", "alert"] if checkpoints is not None else []
    if minimum == 0 and maximum == 0:
        defaults = [name for name in defaults if name != "alert"]
    required = expect.get("required_checkpoints", defaults)
    for name in required:
        checkpoint = observed.get(name)
        status = checkpoint["status"] if checkpoint else "unavailable"
        verdict = {"observed": "PASS", "missing": "FAIL", "unavailable": "INCONCLUSIVE"}[status]
        assertions.append({
            "id": f"checkpoint-{name}",
            "verdict": verdict,
            "message": checkpoint.get("detail", f"{name}: {status}") if checkpoint else f"{name}: no observation supplied",
            "expected": "observed",
            "actual": status,
        })
    # A failed count cannot establish a detection failure if required observation
    # itself is unavailable and no required stage is demonstrably missing.
    statuses = [assertion["verdict"] for assertion in assertions[1:]]
    if not count_ok and "INCONCLUSIVE" in statuses and "FAIL" not in statuses:
        count_result["verdict"] = "INCONCLUSIVE"
        count_result["message"] += "; insufficient required observation to attribute a detection failure"
    verdict = aggregate_verdict([assertion["verdict"] for assertion in assertions])
    evidence = []
    for index, alert in enumerate(alerts):
        evidence.append({"id": f"alert-{index + 1}", "kind": "alert", "data": copy.deepcopy(alert), "sha256": digest(alert)})
    return {
        "verdict": verdict,
        "summary": f"{scenario['id']}: {verdict}; {len(matched)} matching alerts",
        "checkpoints": copy.deepcopy(checkpoints or []),
        "assertions": assertions,
        "evidence": evidence,
        "metadata": {"scenario_sha256": digest(scenario), "matched_alerts": len(matched), "total_alerts": len(alerts)},
    }
