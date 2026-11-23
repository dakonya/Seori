"""Cross-module regression checks using real SQLite and report serializers."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from detectionci.cli import main
from detectionci.models import digest, evaluate
from detectionci.reporting import compare_runs, export_run, render_html, sanitize_result, write_reports
from detectionci.store import Store


def scenario(sid="contract-case"):
    return {
        "id": sid, "version": "1.0.0", "title": "Contract test",
        "description": "A cross-module fixture check", "kind": "positive", "timeout_seconds": 10,
        "expect": {"min_alerts": 1, "predicates": [{"field": "rule.id", "op": "eq", "value": "100200"}]},
    }


class IntegrationContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "runs.sqlite"
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def completed(self, *, definition=None, verdict="PASS", mode="fixture", config_hash="same"):
        definition = definition or scenario()
        run = self.store.create_run(definition, mode)
        self.store.claim_next()
        alerts = [{"rule": {"id": "100200"}, "agent": {"id": "001"}}] if verdict == "PASS" else []
        payload = evaluate(definition, alerts)
        payload["metadata"].update(mode=mode, operator_config_sha256=config_hash)
        self.assertEqual(payload["verdict"], verdict)
        return self.store.finish_run(run["id"], sanitize_result(payload))

    def test_snapshot_comparison_and_reports_roundtrip(self):
        before = self.completed()
        self.store.save_baseline("baseline", [before["id"]])
        after = self.completed()
        comparison = compare_runs(self.store.get_baseline("baseline"), [after])
        self.assertEqual(comparison["verdict"], "PASS")
        self.assertEqual(comparison["rows"][0]["change"], "unchanged")
        paths = write_reports(after, Path(self.temp.name) / "reports")
        saved = json.loads(Path(paths[0]).read_text())
        self.assertEqual(saved["report_schema"], "detectionci.run.v1")
        self.assertEqual(saved["run"]["id"], after["id"])
        self.assertEqual(saved["run"]["verdict"], "PASS")
        self.assertIn("Fixture", saved["notice"])
        self.assertTrue(Path(paths[1]).is_file())

    def test_confirmed_regression_fails_comparison(self):
        before = self.completed()
        base = self.store.save_baseline("baseline", [before["id"]])
        after = self.completed(verdict="FAIL")
        comparison = compare_runs(base, [after])
        self.assertEqual(comparison["verdict"], "FAIL")
        self.assertEqual(comparison["rows"][0]["change"], "regression")

    def test_missing_baseline_scenario_is_failure(self):
        before = self.completed()
        second = self.completed(definition=scenario("another-case"))
        base = self.store.save_baseline("baseline", [before["id"], second["id"]])
        comparison = compare_runs(base, [self.completed()])
        self.assertEqual(comparison["verdict"], "FAIL")
        self.assertEqual(sum(row["change"] == "missing" for row in comparison["rows"]), 1)

    def test_changed_oracle_is_not_unqualified_comparison_pass(self):
        before = self.completed()
        base = self.store.save_baseline("baseline", [before["id"]])
        changed = scenario()
        changed["version"] = "1.1.0"
        changed["description"] = "New oracle version"
        comparison = compare_runs(base, [self.completed(definition=changed)])
        self.assertEqual(comparison["verdict"], "INCONCLUSIVE")
        self.assertTrue(comparison["warnings"])

    def test_config_changes_are_visible_in_comparison(self):
        before = self.completed(config_hash="before")
        base = self.store.save_baseline("baseline", [before["id"]])
        after = self.completed(config_hash="after")
        comparison = compare_runs(base, [after])
        self.assertTrue(any("config" in warning.lower() for warning in comparison["warnings"]))

    def test_mode_is_not_interchangeable(self):
        before = self.completed()
        base = self.store.save_baseline("baseline", [before["id"]])
        with self.assertRaisesRegex(ValueError, "mode"):
            compare_runs(base, [self.completed(mode="replay")])

    def test_redacted_evidence_hashes_describe_stored_bytes(self):
        payload = evaluate(scenario(), [{"rule": {"id": "100200"}, "data": {"password": "do-not-share", "message": "Bearer sensitive-session"}}])
        sanitized = sanitize_result(payload)
        item = sanitized["evidence"][0]
        self.assertEqual(item["data"]["data"]["password"], "[REDACTED]")
        self.assertNotIn("sensitive-session", item["data"]["data"]["message"])
        self.assertEqual(item["sha256"], digest(item["data"]))
        self.assertIn("redacted", item["hash_scope"])

    def test_export_escapes_untrusted_alert_content(self):
        run = self.completed()
        run["result"]["summary"] = '<script>alert("x")</script>'
        html = render_html(run)
        self.assertNotIn('<script>alert("x")</script>', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("Fixture validates local logic", export_run(run)["notice"])

    def test_cli_baseline_missing_run_is_operator_error(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(["--db", str(self.path), "baseline", "save", "baseline", "missing"])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
