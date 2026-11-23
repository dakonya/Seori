from __future__ import annotations

import copy
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import threading
import time
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

from detectionci.engine import Engine, EngineError, REMOTE_HELPER, WATCH_ROOT
from detectionci.models import digest, utcnow
from detectionci.wazuh import WazuhError


def scenario():
    return {"id": "fim-create", "version": "1.0.0", "title": "Controlled FIM creation",
            "description": "An isolated laboratory file must generate the configured alert.",
            "kind": "positive", "timeout_seconds": 1, "action": {"type": "file_create"},
            "expect": {"min_alerts": 1, "predicates": [{"field": "rule.id", "op": "eq", "value": "100200"}]},
            "replay": ["sample log"],
            "fixture": {"alerts": [{"rule": {"id": "100200"}}],
                        "checkpoints": [{"name": name, "status": "observed", "detail": "test fixture"}
                                        for name in ("action", "source", "manager", "alert")]}}


def run(sc=None, mode="fixture"):
    return {"id": str(uuid.uuid4()), "mode": mode, "scenario": sc or scenario()}


class Actions:
    def __init__(self, *, fail_cleanup=False, cancel=None):
        self.calls = []
        self.stage = "untouched"
        self.at = utcnow()
        self.fail_cleanup = fail_cleanup
        self.cancel = cancel

    def __call__(self, **kwargs):
        op = kwargs["operation"]
        self.calls.append(op)
        if op == "prepare":
            self.stage = "prepared"
            self.at = utcnow()
            return {"ok": True, "source_verified": True}
        if op == "execute":
            self.stage = "executed"
            self.at = utcnow()
            if self.cancel:
                self.cancel.set()
            return {"ok": True, "source_verified": True, "sha256": "ab" * 32}
        if self.fail_cleanup:
            raise EngineError("cleanup disconnected")
        self.stage = "cleaned"
        return {"ok": True, "clean": True}


class Client:
    def __init__(self, actions=None, *, variant="normal", fail_search=False, duplicate=False):
        self.actions = actions
        self.variant = variant
        self.calls = []
        self.fail_search = fail_search
        self.duplicate = duplicate
        self.replayed = []

    def replay(self, logs, cancel=None):
        self.replayed = logs
        return [{"rule": {"id": "100200"}}]

    def search_alerts(self, agent_id, start, end, predicates=None):
        self.calls.append((agent_id, start, end, predicates))
        if self.fail_search and self.actions.stage == "executed":
            raise WazuhError("indexer failed: hidden-password")
        if self.actions.stage == "untouched":
            return []
        if self.variant == "late-response" and self.actions.stage == "executed":
            time.sleep(1.05)
        path = predicates[0]["value"]
        stage = self.actions.stage
        event = "added" if stage == "prepared" else "modified" if self.variant == "modify" else "deleted" if self.variant == "delete" else "added"
        rule = {"added": "100200", "modified": "100201", "deleted": "100202"}[event]
        alert = {"id": "event-1", "timestamp": self.actions.at, "agent": {"id": agent_id},
                 "rule": {"id": rule}, "syscheck": {"path": path, "event": event}}
        if self.variant == "stale":
            alert["timestamp"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        if self.variant == "wrong-agent":
            alert["agent"]["id"] = "other-agent"
        if self.variant == "wrong-path":
            alert["syscheck"]["path"] = "/var/lib/detectionci/watch/not-this-run.txt"
        if self.variant == "no-alert":
            return []
        if self.variant == "wrong-baseline-event":
            alert["syscheck"]["event"] = "modified"
            alert["rule"]["id"] = "100201"
        if self.variant == "too-many":
            second = copy.deepcopy(alert)
            second["id"] = "event-2"
            return [alert, second]
        return [alert, copy.deepcopy(alert)] if self.duplicate else [alert]


class EngineFixtureReplayTests(unittest.TestCase):
    def test_fixture_has_explicit_scope_and_contacts_nothing(self):
        with patch("detectionci.engine.WazuhClient", side_effect=AssertionError("network")), \
             patch("detectionci.engine.subprocess.Popen", side_effect=AssertionError("execution")):
            result = Engine().execute(run())
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["metadata"]["validation_scope"], "fixture_logic")
        self.assertFalse(result["metadata"]["external_systems_contacted"])

    def test_fixture_missing_alert_is_failure(self):
        sc = scenario()
        sc["fixture"]["alerts"] = []
        self.assertEqual(Engine().execute(run(sc))["verdict"], "FAIL")

    def test_fixture_unavailable_checkpoint_never_passes(self):
        sc = scenario()
        sc["fixture"]["checkpoints"][1]["status"] = "unavailable"
        self.assertEqual(Engine().execute(run(sc))["verdict"], "INCONCLUSIVE")

    def test_missing_fixture_is_error_not_success(self):
        sc = scenario()
        del sc["fixture"]
        self.assertEqual(Engine().execute(run(sc))["verdict"], "ERROR")

    def test_replay_never_uses_fixture_alerts_or_checkpoints(self):
        sc = scenario()
        sc["fixture"]["alerts"] = []
        client = Client()
        result = Engine({"wazuh": {"manager_url": "https://manager.invalid"}}, client_factory=lambda c: client).execute(run(sc, "replay"))
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(client.replayed, ["sample log"])
        self.assertEqual(result["metadata"]["validation_scope"], "wazuh_rules")
        self.assertIn("does not validate endpoint", result["metadata"]["limitation"])

    def test_replay_missing_configuration_does_not_fallback(self):
        result = Engine().execute(run(mode="replay"))
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("no synthetic fallback", result["summary"])

    def test_replay_cleanup_error_and_password_are_not_hidden(self):
        class Broken(Client):
            def replay(self, logs, cancel=None):
                raise WazuhError("session cleanup failed: hidden-password")
        result = Engine({"wazuh": {"manager_password": "hidden-password"}}, client_factory=lambda c: Broken()).execute(run(mode="replay"))
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("cleanup failed", result["summary"])
        self.assertNotIn("hidden-password", json.dumps(result))

    def test_cancellation_before_execution(self):
        event = threading.Event()
        event.set()
        result = Engine().execute(run(), event)
        self.assertEqual(result["verdict"], "CANCELLED")

    def test_unknown_mode_is_error(self):
        self.assertEqual(Engine().execute(run(mode="invented"))["verdict"], "ERROR")

    def test_source_scenario_is_not_mutated(self):
        sc = scenario()
        original = copy.deepcopy(sc)
        Engine().execute(run(sc))
        self.assertEqual(sc, original)

    def test_replay_deadline_cannot_turn_into_success(self):
        class Slow(Client):
            def replay(self, logs, cancel=None):
                cancel.wait(2)
                return [{"rule": {"id": "100200"}}]
        result = Engine({"wazuh": {"manager_url": "https://manager.invalid"}},
                        client_factory=lambda c: Slow()).execute(run(mode="replay"))
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("deadline exceeded", result["summary"])

    def test_replay_request_timeout_is_clamped_to_scenario_budget(self):
        configs = []
        def factory(config):
            configs.append(config)
            return Client()
        Engine({"wazuh": {"manager_url": "https://manager.invalid", "request_timeout": 60}},
               client_factory=factory).execute(run(mode="replay"))
        self.assertEqual(configs[0]["request_timeout"], 1)

    def test_redacted_evidence_hashes_match_exported_data(self):
        sc = scenario()
        sc["fixture"]["alerts"][0].update({"password": "unrelated-private-value", "message": "hidden-password"})
        result = Engine({"wazuh": {"manager_password": "hidden-password"}}).execute(run(sc))
        self.assertNotIn("hidden-password", json.dumps(result))
        self.assertNotIn("unrelated-private-value", json.dumps(result))
        for item in result["evidence"]:
            self.assertEqual(item["sha256"], digest(item["data"]))

    def test_secret_equal_to_protocol_word_does_not_corrupt_verdict(self):
        result = Engine({"wazuh": {"manager_password": "PASS"}}).execute(run())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(all(a["verdict"] == "PASS" for a in result["assertions"]))


class EngineLiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.identity = Path(self.tmp.name) / "identity"
        self.hosts = Path(self.tmp.name) / "known_hosts"
        self.identity.write_text("not-an-actual-key")
        self.hosts.write_text("not-an-actual-host-key")
        self.config = {"wazuh": {"indexer_url": "https://indexer.invalid", "indexer_password": "hidden-password"},
                       "live": {"host": "lab.invalid", "user": "detectionci", "agent_id": "001", "port": 22,
                                "identity_file": str(self.identity), "known_hosts": str(self.hosts),
                                "poll_interval_seconds": .05, "clock_skew_seconds": 0}}

    def engine(self, actions=None, **client_kwargs):
        actions = actions or Actions()
        client = Client(actions, **client_kwargs)
        engine = Engine(self.config, client_factory=lambda c: client, action_executor=actions)
        return engine, actions, client

    def test_live_matches_real_adapter_output_and_checks_cleanup(self):
        engine, actions, client = self.engine()
        item = run(mode="live")
        result = engine.execute(item)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(actions.calls, ["prepare", "execute", "cleanup"])
        self.assertTrue(result["metadata"]["cleanup_verified"])
        self.assertEqual(result["metadata"]["run_path"], f"{WATCH_ROOT}/{item['id']}.txt")
        self.assertEqual(result["metadata"]["source_checkpoint_scope"], "remote_filesystem_state")
        self.assertIn("manager decoding", result["metadata"]["unobserved_stages"])

    def test_stale_or_other_target_alerts_cannot_pass(self):
        for variant in ("stale", "wrong-agent", "wrong-path"):
            with self.subTest(variant=variant):
                engine, actions, _ = self.engine(variant=variant)
                result = engine.execute(run(mode="live"))
                self.assertEqual(result["verdict"], "FAIL")
                self.assertEqual(actions.calls[-1], "cleanup")

    def test_alert_observed_after_deadline_cannot_pass(self):
        engine, actions, _ = self.engine(variant="late-response")
        result = engine.execute(run(mode="live"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(actions.calls[-1], "cleanup")

    def test_modify_requires_observed_baseline_before_mutation(self):
        sc = scenario()
        sc["action"]["type"] = "file_modify"
        sc["expect"]["predicates"][0]["value"] = "100201"
        engine, actions, client = self.engine(variant="modify")
        result = engine.execute(run(sc, "live"))
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(any(e["kind"] == "baseline_alerts" for e in result["evidence"]))

    def test_missing_baseline_blocks_mutation_and_fails(self):
        sc = scenario()
        sc["action"]["type"] = "file_modify"
        engine, actions, _ = self.engine(variant="no-alert")
        result = engine.execute(run(sc, "live"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(actions.calls, ["prepare", "cleanup"])

    def test_wrong_baseline_event_cannot_authorize_mutation(self):
        sc = scenario()
        sc["action"]["type"] = "file_modify"
        engine, actions, _ = self.engine(variant="wrong-baseline-event")
        result = engine.execute(run(sc, "live"))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(actions.calls, ["prepare", "cleanup"])
        self.assertIn("baseline", result["summary"])

    def test_delete_confirms_baseline_then_deletion(self):
        sc = scenario()
        sc["action"]["type"] = "file_delete"
        sc["expect"]["predicates"][0]["value"] = "100202"
        engine, _, _ = self.engine(variant="delete")
        self.assertEqual(engine.execute(run(sc, "live"))["verdict"], "PASS")

    def test_negative_live_cannot_pass_without_collection_coverage(self):
        sc = scenario()
        sc["kind"] = "control"
        sc["expect"] = {"min_alerts": 0, "max_alerts": 0,
                        "predicates": [{"field": "rule.id", "op": "eq", "value": "100201"}]}
        engine, actions, _ = self.engine(variant="no-alert")
        result = engine.execute(run(sc, "live"))
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(actions.calls[-1], "cleanup")

    def test_maximum_alerts_is_enforced_and_poll_duplicates_do_not_count(self):
        sc = scenario()
        sc["expect"]["max_alerts"] = 1
        engine, _, _ = self.engine(duplicate=True)
        self.assertEqual(engine.execute(run(sc, "live"))["verdict"], "PASS")
        engine, _, _ = self.engine(variant="too-many")
        self.assertEqual(engine.execute(run(sc, "live"))["verdict"], "FAIL")

    def test_cleanup_failure_marks_target_dirty_and_prevents_success(self):
        engine, _, _ = self.engine(Actions(fail_cleanup=True))
        result = engine.execute(run(mode="live"))
        self.assertNotEqual(result["verdict"], "PASS")
        self.assertTrue(result["metadata"]["target_dirty"])
        self.assertTrue(result["metadata"]["restore_required"])

    def test_cancel_after_action_still_cleans_up(self):
        event = threading.Event()
        engine, actions, _ = self.engine(Actions(cancel=event))
        result = engine.execute(run(mode="live"), event)
        self.assertEqual(result["verdict"], "CANCELLED")
        self.assertEqual(actions.calls[-1], "cleanup")
        self.assertTrue(result["metadata"]["cleanup_verified"])

    def test_indexer_failure_still_cleans_and_redacts_secrets(self):
        engine, actions, _ = self.engine(fail_search=True)
        result = engine.execute(run(mode="live"))
        self.assertEqual(result["verdict"], "ERROR")
        self.assertEqual(actions.calls[-1], "cleanup")
        self.assertNotIn("hidden-password", json.dumps(result))

    def test_invalid_host_user_port_and_root_rejected_before_io(self):
        bad = [("host", "-oProxyCommand=evil"), ("host", "lab;evil"), ("user", "root;evil"),
               ("port", True), ("port", 0), ("watch_root", "/etc"),
               ("clock_skew_seconds", float("nan")), ("identity_file", "relative")]
        for key, value in bad:
            with self.subTest(key=key, value=value):
                cfg = copy.deepcopy(self.config)
                cfg["live"][key] = value
                factory = unittest.mock.Mock(side_effect=AssertionError("IO before validation"))
                result = Engine(cfg, client_factory=factory).execute(run(mode="live"))
                self.assertEqual(result["verdict"], "ERROR")
                self.assertFalse(result["metadata"]["external_systems_contacted"])
                factory.assert_not_called()

    def test_unsupported_action_rejected_before_io(self):
        sc = scenario()
        sc["action"] = {"type": "shell", "command": "danger"}
        factory = unittest.mock.Mock(side_effect=AssertionError("external IO"))
        result = Engine(self.config, client_factory=factory).execute(run(sc, "live"))
        self.assertEqual(result["verdict"], "ERROR")
        factory.assert_not_called()

    def test_invalid_run_id_rejected_before_external_io(self):
        item = run(mode="live")
        item["id"] = "../../etc/passwd"
        factory = unittest.mock.Mock(side_effect=AssertionError("external IO"))
        self.assertEqual(Engine(self.config, client_factory=factory).execute(item)["verdict"], "ERROR")
        factory.assert_not_called()

    def test_remote_helper_compiles_and_does_not_embed_credentials(self):
        compile(REMOTE_HELPER, "remote_helper", "exec")
        self.assertIn("O_NOFOLLOW", REMOTE_HELPER)
        self.assertNotIn("hidden-password", REMOTE_HELPER)


class RemoteHelperIntegrationTests(unittest.TestCase):
    """Execute the exact helper against a substituted temporary lab root."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "watch"
        self.root.mkdir()
        self.helper = REMOTE_HELPER.replace('base = "/var/lib/detectionci/watch"', "base = " + repr(str(self.root)))
        self.run_id = str(uuid.uuid4())
        self.path = self.root / (self.run_id + ".txt")

    def execute(self, operation, action, run_id=None):
        payload = base64.b64encode(json.dumps({"operation": operation, "action": action,
                                              "run_id": run_id or self.run_id}).encode()).decode()
        proc = subprocess.run([sys.executable, "-c", self.helper, payload], capture_output=True, timeout=3)
        return proc, json.loads(proc.stdout) if proc.returncode == 0 else None

    def test_create_and_cleanup_confirm_real_filesystem_state(self):
        self.assertTrue(self.execute("prepare", "file_create")[1]["ok"])
        result = self.execute("execute", "file_create")[1]
        self.assertTrue(result["source_verified"])
        self.assertTrue(self.path.exists())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.execute("cleanup", "file_create")[1]["clean"])
        self.assertFalse(self.path.exists())

    def test_modify_and_delete_real_baselines(self):
        for kind in ("file_modify", "file_delete"):
            with self.subTest(kind=kind):
                self.execute("prepare", kind)
                self.assertTrue(self.path.exists())
                result = self.execute("execute", kind)[1]
                self.assertTrue(result["source_verified"])
                if kind == "file_modify":
                    self.assertIn("modification", self.path.read_text())
                else:
                    self.assertFalse(self.path.exists())
                self.assertTrue(self.execute("cleanup", kind)[1]["clean"])

    def test_symlink_run_file_cannot_modify_another_file(self):
        outside = Path(self.tmp.name) / "outside"
        outside.write_text("untouched")
        self.path.symlink_to(outside)
        proc, _ = self.execute("execute", "file_modify")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(outside.read_text(), "untouched")

    def test_traversal_and_unknown_operation_rejected(self):
        for operation, kind, rid in (("execute", "file_create", "../../outside"),
                                     ("shell", "file_create", self.run_id),
                                     ("execute", "exec", self.run_id)):
            with self.subTest(operation=operation, kind=kind):
                self.assertNotEqual(self.execute(operation, kind, rid)[0].returncode, 0)

    def test_hard_link_cannot_modify_another_file(self):
        import os
        outside = Path(self.tmp.name) / "outside"
        outside.write_text("untouched")
        os.link(outside, self.path)
        proc, _ = self.execute("execute", "file_modify")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(outside.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
