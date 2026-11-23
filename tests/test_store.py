import concurrent.futures
from contextlib import closing
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from detectionci.store import Store


def scenario(sid="ssh-test"):
    return {"id": sid, "version": "1.0.0", "title": "SSH test", "description": "Test fixture", "kind": "positive", "timeout_seconds": 10, "expect": {"min_alerts": 1}}


def result(verdict="PASS"):
    return {"verdict": verdict, "summary": "Test result", "checkpoints": [], "assertions": [], "evidence": [], "metadata": {"mode": "fixture"}}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "nested" / "runs.sqlite"
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def completed(self, sid="ssh-test", mode="fixture", verdict="PASS"):
        run = self.store.create_run(scenario(sid), mode)
        self.assertEqual(self.store.claim_next()["id"], run["id"])
        return self.store.finish_run(run["id"], result(verdict))

    def test_database_permissions(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_run_state_and_reopen(self):
        created = self.store.create_run(scenario(), "fixture", "suite1")
        self.assertEqual(str(uuid.UUID(created["id"])), created["id"])
        self.assertEqual(created["status"], "queued")
        self.assertIsNone(created["started_at"])
        claimed = self.store.claim_next()
        self.assertEqual(claimed["id"], created["id"])
        self.assertEqual(claimed["status"], "running")
        self.assertIsNotNone(claimed["started_at"])
        final = self.store.finish_run(created["id"], result())
        reopened = Store(self.path)
        self.assertEqual(reopened.get_run(final["id"])["result"], final["result"])
        self.assertEqual(final["suite_id"], "suite1")
        self.assertEqual(final["status"], "completed")
        self.assertIsNotNone(final["finished_at"])
        reopened.close()

    def test_no_work(self):
        self.assertIsNone(self.store.claim_next())
        self.assertIsNone(self.store.get_run("missing"))

    def test_invalid_mode_and_scenario(self):
        with self.assertRaises(ValueError):
            self.store.create_run(scenario(), "pretend")
        with self.assertRaises(ValueError):
            self.store.create_run({}, "fixture")

    def test_scenario_snapshot_cannot_change(self):
        source = scenario()
        created = self.store.create_run(source, "fixture")
        source["expect"]["min_alerts"] = 99
        created["scenario"]["expect"]["min_alerts"] = 33
        self.assertEqual(self.store.get_run(created["id"])["scenario"]["expect"]["min_alerts"], 1)

    def test_atomic_claim_under_concurrency(self):
        expected = {self.store.create_run(scenario(), "fixture")["id"] for _ in range(24)}
        def claim(_):
            return self.store.claim_next()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            claimed = [run for run in executor.map(claim, range(40)) if run]
        self.assertEqual({run["id"] for run in claimed}, expected)
        self.assertEqual(len(claimed), len(expected))

    def test_cancel_queued_never_executes(self):
        run = self.store.create_run(scenario(), "fixture")
        cancelled = self.store.request_cancel(run["id"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["verdict"], "CANCELLED")
        self.assertTrue(self.store.is_cancel_requested(run["id"]))
        self.assertIsNone(self.store.claim_next())
        self.assertEqual(self.store.request_cancel(run["id"]), cancelled)

    def test_cancel_race_cannot_finish_pass(self):
        run = self.store.create_run(scenario(), "fixture")
        self.store.claim_next()
        self.assertEqual(self.store.request_cancel(run["id"])["status"], "cancelling")
        payload = result()
        payload["metadata"]["cleanup_verified"] = False
        payload["evidence"] = [{"kind": "cleanup-error", "data": "target unavailable"}]
        final = self.store.finish_run(run["id"], payload)
        self.assertEqual(final["verdict"], "CANCELLED")
        self.assertEqual(final["status"], "cancelled")
        self.assertEqual(final["result"]["metadata"]["execution_verdict_before_cancel"], "PASS")
        self.assertFalse(final["result"]["metadata"]["cleanup_verified"])
        self.assertEqual(final["result"]["evidence"], payload["evidence"])

    def test_terminal_result_cannot_be_overwritten(self):
        run = self.completed()
        with self.assertRaises(ValueError):
            self.store.finish_run(run["id"], result("FAIL"))
        self.assertEqual(self.store.request_cancel(run["id"])["verdict"], "PASS")

    def test_finish_before_claim_rejected(self):
        run = self.store.create_run(scenario(), "fixture")
        with self.assertRaises(ValueError):
            self.store.finish_run(run["id"], result())

    def test_recovery_is_explicit_error_and_leaves_queued_work(self):
        first = self.store.create_run(scenario(), "live")
        self.store.claim_next()
        queued = self.store.create_run(scenario("other-test"), "fixture")
        self.assertEqual(self.store.recover_interrupted(), 1)
        recovered = self.store.get_run(first["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["verdict"], "ERROR")
        self.assertFalse(recovered["result"]["metadata"]["cleanup_verified"])
        self.assertEqual(self.store.get_run(queued["id"])["status"], "queued")
        self.assertEqual(self.store.recover_interrupted(), 0)

    def test_baseline_is_immutable_snapshot_with_digest(self):
        run = self.completed()
        saved = self.store.save_baseline("before-fix", [run["id"]])
        saved["runs"][0]["result"]["verdict"] = "modified"
        stored = self.store.get_baseline("before-fix")
        self.assertEqual(stored["runs"][0]["result"]["verdict"], "PASS")
        self.assertEqual(len(stored["runs"][0]["scenario_digest"]), 64)
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.store.save_baseline("before-fix", [run["id"]])
        self.assertEqual(len(self.store.list_baselines()), 1)
        self.assertIsNone(self.store.get_baseline("missing"))

    def test_baseline_rejects_pending_and_duplicate_runs(self):
        run = self.store.create_run(scenario(), "fixture")
        for ids in [[], [run["id"]], [run["id"], run["id"]]]:
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.store.save_baseline("invalid", ids)

    def test_baseline_rejects_mixed_modes_or_duplicate_scenarios(self):
        first = self.completed()
        duplicate = self.completed()
        live = self.completed("other-test", "live")
        with self.assertRaisesRegex(ValueError, "one run per scenario"):
            self.store.save_baseline("duplicate", [first["id"], duplicate["id"]])
        with self.assertRaisesRegex(ValueError, "mix"):
            self.store.save_baseline("mixed", [first["id"], live["id"]])

    def test_baseline_rejects_bad_name_and_missing_run(self):
        with self.assertRaises(ValueError):
            self.store.save_baseline("../../bad", ["missing"])
        with self.assertRaises(KeyError):
            self.store.save_baseline("good", ["missing"])

    def test_missing_run_mutations_raise(self):
        for operation in [lambda: self.store.request_cancel("missing"), lambda: self.store.is_cancel_requested("missing"), lambda: self.store.finish_run("missing", result())]:
            with self.assertRaises(KeyError):
                operation()

    def test_pagination(self):
        for _ in range(4):
            self.store.create_run(scenario(), "fixture")
        first = self.store.list_runs(2, 0)
        second = self.store.list_runs(2, 2)
        self.assertEqual(len(first + second), 4)
        self.assertFalse({r["id"] for r in first} & {r["id"] for r in second})
        with self.assertRaises(ValueError):
            self.store.list_runs(501)
        with self.assertRaises(ValueError):
            self.store.list_runs(offset=-1)

    def test_newer_schema_not_downgraded(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "newer"):
            Store(self.path)

    def test_symlink_database_rejected(self):
        link = Path(self.directory.name) / "link.sqlite"
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            Store(link)

    def test_memory_database_support(self):
        memory = Store(":memory:")
        created = memory.create_run(scenario(), "fixture")
        self.assertEqual(memory.claim_next()["id"], created["id"])
        self.assertEqual(memory.finish_run(created["id"], result())["verdict"], "PASS")
        memory.close()


if __name__ == "__main__":
    unittest.main()
