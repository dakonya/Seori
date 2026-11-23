import copy
import json
import tempfile
import unittest
from pathlib import Path

from detectionci.models import (
    aggregate_verdict, canonical_json, digest, evaluate, get_field,
    load_scenario, utcnow, validate_scenario,
)


def scenario():
    return {
        "id": "ssh-test", "version": "1.0.0", "title": "SSH detection",
        "description": "A labelled detection test.", "kind": "positive",
        "timeout_seconds": 10,
        "expect": {"min_alerts": 1, "predicates": [{"field": "rule.id", "op": "eq", "value": "5710"}]},
    }


def alert(rule="5710", **fields):
    return {"timestamp": "2026-11-17T10:00:00Z", "agent": {"id": "001"}, "rule": {"id": rule}, **fields}


def checkpoints():
    return [{"name": name, "status": "observed", "detail": "Seen"} for name in ["action", "source", "manager", "alert"]]


class ScenarioValidationTests(unittest.TestCase):
    def test_normalization_is_detached_from_input(self):
        original = scenario()
        validated = validate_scenario(original)
        validated["expect"]["predicates"][0]["value"] = "other"
        self.assertEqual(original["expect"]["predicates"][0]["value"], "5710")

    def test_required_fields(self):
        for key in scenario():
            with self.subTest(key=key), self.assertRaises(ValueError):
                candidate = scenario()
                del candidate[key]
                validate_scenario(candidate)

    def test_malformed_values_raise_valueerror(self):
        values = [("id", "../../bad"), ("id", "UPPER"), ("version", "latest"),
                  ("title", ""), ("kind", []), ("kind", "unknown"),
                  ("timeout_seconds", True), ("timeout_seconds", 301), ("timeout_seconds", 0),
                  ("expect", [])]
        for key, value in values:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                candidate = scenario()
                candidate[key] = value
                validate_scenario(candidate)

    def test_invalid_expectations(self):
        values = [{"min_alerts": -1}, {"min_alerts": True}, {"min_alerts": 1, "max_alerts": 0},
                  {"min_alerts": 1, "max_alert": 1}, {"predicates": []},
                  {"min_alerts": 1, "required_checkpoints": ["source", "source"]},
                  {"min_alerts": 1, "required_checkpoints": [None]}]
        for expect in values:
            with self.subTest(expect=expect), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["expect"] = expect
                validate_scenario(candidate)

    def test_control_needs_upper_bound(self):
        candidate = scenario()
        candidate["kind"] = "control"
        candidate["expect"]["min_alerts"] = 0
        with self.assertRaisesRegex(ValueError, "max_alerts"):
            validate_scenario(candidate)

    def test_invalid_predicates(self):
        predicates = [
            {"field": "rule.id", "op": "eq", "value": 5710},
            {"field": "rule.id", "op": [], "value": "5710"},
            {"field": "rule.id", "op": "in", "value": []},
            {"field": "rule.id", "op": "in", "value": [None]},
            {"field": "rule.id", "op": "contains", "value": ""},
            {"field": "rule.id", "op": "eq", "value": None},
            {"field": "rule..id", "op": "eq", "value": "5710"},
            {"field": "rule.id", "op": "eq", "value": "5710", "typo": 1},
        ]
        for predicate in predicates:
            with self.subTest(predicate=predicate), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["expect"]["predicates"] = [predicate]
                validate_scenario(candidate)

    def test_safe_regex_subset(self):
        for pattern in ["^571[0-9]$", "^sshd.*failed$", "^\\w{1,16}$"]:
            with self.subTest(pattern=pattern):
                candidate = scenario()
                candidate["expect"]["predicates"][0].update(op="regex", value=pattern)
                validate_scenario(candidate)

    def test_expensive_or_invalid_regex_rejected(self):
        for pattern in ["(a+)+$", "(a|aa)+$", ".*a.*b", "a{10000}", "(?=x)x", "(a)\\1", "[", "a{999999999999999999999}"]:
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["expect"]["predicates"][0].update(op="regex", value=pattern)
                validate_scenario(candidate)

    def test_unbounded_or_non_json_data_rejected(self):
        for value in [float("nan"), float("inf"), {1: "bad-key"}, {"x": object()}, "x" * 1_048_576]:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["metadata"] = value
                validate_scenario(candidate)

    def test_replay_must_have_bounded_nonempty_logs(self):
        for logs in [[], [""], ["a"] * 201, ["x" * 65_537]]:
            with self.subTest(logs_type=len(logs)), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["replay"] = logs
                validate_scenario(candidate)

    def test_metadata_shape_and_modes_validated(self):
        for metadata in ["not-an-object", {"supported_modes": ["fixture", "fixture"]},
                         {"supported_modes": "fixture"}, {"supported_modes": [["fixture"]]},
                         {"supported_modes": ["mock-production"]}, {"expected_verdict": []}]:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["metadata"] = metadata
                validate_scenario(candidate)

    def test_fixture_rejects_ambiguous_checkpoints(self):
        for cp in [[{"name": "source", "status": "healthy"}],
                   [{"name": "source", "status": []}],
                   [{"name": "source", "status": "observed"}] * 2]:
            with self.subTest(cp=cp), self.assertRaises(ValueError):
                candidate = scenario()
                candidate["fixture"] = {"alerts": [], "checkpoints": cp}
                validate_scenario(candidate)

    def test_file_json_read_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            path.write_text(json.dumps(scenario()), encoding="utf-8")
            self.assertEqual(load_scenario(path)["id"], "ssh-test")
            path.write_bytes(b"\xff")
            with self.assertRaises(ValueError):
                load_scenario(path)

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            path.write_text('{"id":"one","id":"two"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_scenario(path)


class EvaluationTests(unittest.TestCase):
    def test_positive_and_missing_alert(self):
        self.assertEqual(evaluate(scenario(), [alert()])["verdict"], "PASS")
        self.assertEqual(evaluate(scenario(), [alert("999")])["verdict"], "FAIL")

    def test_predicates_are_anded_on_one_alert(self):
        candidate = scenario()
        candidate["expect"]["predicates"].append({"field": "data.user", "op": "eq", "value": "alice"})
        result = evaluate(candidate, [alert(data={"user": "bob"}), alert("999", data={"user": "alice"})])
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["metadata"]["matched_alerts"], 0)

    def test_equality_does_not_conflate_booleans_and_numbers(self):
        candidate = scenario()
        candidate["expect"]["predicates"] = [{"field": "data.value", "op": "eq", "value": 1}]
        self.assertEqual(evaluate(candidate, [alert(data={"value": True})])["verdict"], "FAIL")

    def test_operators_and_missing_field(self):
        cases = [("in", ["5710", "5712"], "5710", "PASS"),
                 ("contains", "571", "5710", "PASS"),
                 ("regex", "^571[0-9]$", "5710", "PASS"),
                 ("regex", "^571[0-9]$", "x5710", "FAIL")]
        for op, value, actual, verdict in cases:
            with self.subTest(op=op, actual=actual):
                candidate = scenario()
                candidate["expect"]["predicates"][0].update(op=op, value=value)
                self.assertEqual(evaluate(candidate, [alert(actual)])["verdict"], verdict)
        self.assertEqual(evaluate(scenario(), [{"rule": {}}])["verdict"], "FAIL")

    def test_control_zero_matches_can_pass_with_ordinary_alert(self):
        candidate = scenario()
        candidate["kind"] = "control"
        candidate["expect"].update(min_alerts=0, max_alerts=0)
        cp = [item for item in checkpoints() if item["name"] != "alert"]
        self.assertEqual(evaluate(candidate, [alert("5501")], cp)["verdict"], "PASS")
        self.assertEqual(evaluate(candidate, [alert()], cp)["verdict"], "FAIL")

    def test_missing_source_is_fail_unavailable_is_inconclusive(self):
        for status, verdict in [("missing", "FAIL"), ("unavailable", "INCONCLUSIVE")]:
            with self.subTest(status=status):
                cp = checkpoints()
                cp[1]["status"] = status
                self.assertEqual(evaluate(scenario(), [alert()], cp)["verdict"], verdict)

    def test_absent_required_checkpoint_is_not_pass(self):
        self.assertEqual(evaluate(scenario(), [alert()], [])["verdict"], "INCONCLUSIVE")

    def test_missing_alert_without_observability_is_inconclusive(self):
        cp = checkpoints()
        cp[1]["status"] = "unavailable"
        self.assertEqual(evaluate(scenario(), [], cp)["verdict"], "INCONCLUSIVE")

    def test_known_missing_stage_remains_fail_with_unavailable_stage(self):
        cp = checkpoints()
        cp[1]["status"] = "unavailable"
        cp[2]["status"] = "missing"
        self.assertEqual(evaluate(scenario(), [], cp)["verdict"], "FAIL")

    def test_explicit_empty_checkpoints_honored(self):
        candidate = scenario()
        candidate["expect"]["required_checkpoints"] = []
        self.assertEqual(evaluate(candidate, [alert()], [])["verdict"], "PASS")

    def test_evidence_hash_and_copy(self):
        original = alert()
        result = evaluate(scenario(), [original])
        evidence = result["evidence"][0]
        self.assertEqual(evidence["sha256"], digest(original))
        evidence["data"]["rule"]["id"] = "other"
        self.assertEqual(original["rule"]["id"], "5710")

    def test_aggregation_and_stable_json(self):
        self.assertEqual(aggregate_verdict([]), "INCONCLUSIVE")
        self.assertEqual(aggregate_verdict(["PASS", "INCONCLUSIVE", "FAIL"]), "FAIL")
        self.assertEqual(aggregate_verdict(["FAIL", "ERROR"]), "ERROR")
        self.assertEqual(digest({"a": 1, "b": 2}), digest({"b": 2, "a": 1}))
        self.assertTrue(utcnow().endswith("Z"))
        self.assertIsNone(get_field({"a": 1}, "a.b"))

    def test_invalid_aggregation_rejected(self):
        with self.assertRaises(ValueError):
            aggregate_verdict(["green"])

    def test_oversized_regex_input_is_not_silently_a_nonmatch(self):
        candidate = scenario()
        candidate["expect"]["predicates"] = [{"field": "data.value", "op": "regex", "value": "^a+$"}]
        with self.assertRaisesRegex(ValueError, "regex input"):
            evaluate(candidate, [alert(data={"value": "a" * 2049})])


if __name__ == "__main__":
    unittest.main()
