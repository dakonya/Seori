import copy
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from detectionci.catalog import load_catalog
from detectionci.cli import main
from detectionci.config import load_config
from detectionci.reporting import render_html, sanitize_result
from detectionci.server import DetectionServer, Handler, supports_mode
from detectionci.store import Store
from detectionci.worker import Worker


def scenario():
    return {"id": "test-example", "version": "1.0.0", "title": "Test", "description": "Application contract test",
            "kind": "positive", "timeout_seconds": 2,
            "expect": {"min_alerts": 1, "predicates": [{"field": "rule.id", "op": "eq", "value": "100200"}], "required_checkpoints": []},
            "fixture": {"alerts": [{"timestamp": "2026-11-17T00:00:00Z", "agent": {"id": "001"}, "rule": {"id": "100200"}}], "checkpoints": []}}


class ConfigTests(unittest.TestCase):
    def test_env_expansion_and_missing_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            p.write_text('{"wazuh":{"manager_password":"${DCI_TEST_PASSWORD}"}}')
            with patch.dict(os.environ, {"DCI_TEST_PASSWORD": "secret"}):
                self.assertEqual(load_config(p)["wazuh"]["manager_password"], "secret")
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
                load_config(p)

    def test_arbitrary_env_and_unknown_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.json"
            for text in ['{"wazuh":{"x":"${HOME}"}}', '{"danger":{}}', '[]']:
                p.write_text(text)
                with self.assertRaises(ValueError):
                    load_config(p)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.store = Store(self.path)
        self.workers = []

    def tearDown(self):
        for w in self.workers:
            w.stop()
        self.temp.cleanup()

    def start(self, engine=None):
        w = Worker(self.store, self.path, engine=engine)
        w.start()
        self.workers.append(w)
        return w

    def test_real_fixture_job_persists_report(self):
        w = self.start()
        r = self.store.create_run(scenario(), "fixture")
        result = w.wait_for([r["id"]], 5)[0]
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["result"]["metadata"]["validation_scope"], "fixture_logic")
        self.assertIn("Fixture", render_html(result))

    def test_exclusive_lock_prevents_false_crash_recovery(self):
        self.start()
        other = Worker(self.store, self.path)
        with self.assertRaisesRegex(RuntimeError, "Another"):
            other.start()

    def test_crashed_active_run_recovered_as_error(self):
        r = self.store.create_run(scenario(), "fixture")
        self.store.claim_next()
        self.start()
        recovered = self.store.get_run(r["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["verdict"], "ERROR")

    def test_dirty_target_persists_and_blocks_next_live_run(self):
        class DirtyEngine:
            config = {}
            calls = 0
            def execute(self, run, cancel):
                self.calls += 1
                return {"verdict": "ERROR", "summary": "cleanup failed", "metadata": {"cleanup_verified": False}}
        engine = DirtyEngine()
        w = self.start(engine)
        first = self.store.create_run(scenario(), "live")
        w.wait_for([first["id"]], 5)
        self.assertTrue(w.target_status()["blocked"])
        second = self.store.create_run(scenario(), "live")
        run = w.wait_for([second["id"]], 5)[0]
        self.assertEqual(run["verdict"], "ERROR")
        self.assertEqual(engine.calls, 1)
        with self.assertRaises(RuntimeError):
            w.clear_target_state()
        w.stop()
        w.clear_target_state()
        self.assertFalse(w.target_status()["blocked"])

    def test_successful_cleanup_clears_crash_marker(self):
        class CleanEngine:
            config = {}
            def execute(self, run, cancel):
                return {"verdict": "PASS", "summary": "test", "metadata": {"cleanup_verified": True}}
        w = self.start(CleanEngine())
        r = self.store.create_run(scenario(), "live")
        w.wait_for([r["id"]], 5)
        self.assertFalse(w.target_status()["blocked"])

    def test_engine_exception_does_not_leak_credentials(self):
        class Broken:
            config = {}
            def execute(self, run, cancel):
                raise RuntimeError("password is sensitive")
        w = self.start(Broken())
        r = self.store.create_run(scenario(), "fixture")
        run = w.wait_for([r["id"]], 5)[0]
        self.assertEqual(run["verdict"], "ERROR")
        self.assertNotIn("sensitive", json.dumps(run["result"]))

    def test_cancellation_survives_engine_attempt_to_pass(self):
        started = threading.Event()
        class Slow:
            config = {}
            def execute(self, run, cancel):
                started.set()
                cancel.wait(2)
                return {"verdict": "PASS", "summary": "late success", "metadata": {}}
        w = self.start(Slow())
        r = self.store.create_run(scenario(), "fixture")
        self.assertTrue(started.wait(2))
        w.cancel(r["id"])
        result = w.wait_for([r["id"]], 5)[0]
        self.assertEqual(result["verdict"], "CANCELLED")


class WireSocket:
    """Exercise BaseHTTPRequestHandler's actual wire parser without network permissions."""
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = io.BytesIO()
    def makefile(self, *args, **kwargs):
        return self.input
    def sendall(self, data):
        self.output.write(data)
    def settimeout(self, value):
        pass


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "api.sqlite3"
        self.store = Store(self.path)
        self.worker = Worker(self.store, self.path)
        self.worker.start()
        class Server:
            server_port = 8787
            local_only = True
            token = None
        self.server = Server()
        self.server.store, self.server.worker = self.store, self.worker
        self.server.catalog = {"test-example": scenario()}

    def tearDown(self):
        self.worker.stop()
        self.temp.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        payload = json.dumps(body).encode() if body is not None else b""
        hs = {"Host": "127.0.0.1:8787", "Content-Length": str(len(payload))}
        if body is not None:
            hs["Content-Type"] = "application/json"
        hs.update(headers or {})
        request = (method + " " + path + " HTTP/1.0\r\n" + "".join(k + ": " + v + "\r\n" for k, v in hs.items()) + "\r\n").encode() + payload
        wire = WireSocket(request)
        Handler(wire, ("127.0.0.1", 10000), self.server)
        raw = wire.output.getvalue()
        head, data = raw.split(b"\r\n\r\n", 1)
        status = int(head.split(b" ")[1])
        return status, head, data

    def test_full_run_report_baseline_comparison_flow(self):
        status, _, body = self.request("/api/runs", "POST", {"scenario_id": "test-example", "mode": "fixture"})
        self.assertEqual(status, 202)
        run_id = json.loads(body)["run"]["id"]
        self.worker.wait_for([run_id], 5)
        self.assertEqual(self.request("/api/runs/" + run_id)[0], 200)
        status, headers, report = self.request("/api/runs/" + run_id + "/report?format=html")
        self.assertEqual(status, 200)
        self.assertIn(b"Content-Security-Policy", headers)
        self.assertIn(b"Fixture", report)
        status, _, _ = self.request("/api/baselines", "POST", {"name": "first", "run_ids": [run_id]})
        self.assertEqual(status, 201)
        status, _, body = self.request("/api/compare?baseline=first&run_ids=" + run_id)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["comparison"]["verdict"], "PASS")

    def test_cross_origin_and_rebinding_blocked(self):
        self.assertEqual(self.request("/api/health", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request("/api/health", headers={"Host": "evil.example:8787"})[0], 403)
        self.assertEqual(self.request("/api/health", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_remote_plaintext_binding_rejected_before_socket_creation(self):
        with self.assertRaisesRegex(ValueError, "remote binding"):
            DetectionServer(("0.0.0.0", 8787), self.store, {}, self.worker, "a" * 32)

    def test_api_token_required_but_static_page_available(self):
        self.server.token = "a" * 32
        self.assertEqual(self.request("/api/health")[0], 401)
        self.assertEqual(self.request("/api/health", headers={"Authorization": "Bearer " + self.server.token})[0], 200)
        self.assertEqual(self.request("/")[0], 200)

    def test_absolute_and_network_path_targets_cannot_bypass_auth(self):
        self.server.token = "a" * 32
        for path in ["http://127.0.0.1:8787/api/runs", "//127.0.0.1:8787/api/runs", "/api/runs#ignored"]:
            self.assertEqual(self.request(path)[0], 400)
            self.assertEqual(self.request(path, "POST", {"scenario_id": "test-example", "mode": "fixture"})[0], 400)

    def test_malformed_requests_and_arbitrary_actions_rejected(self):
        for body in [{"scenario_id": "test-example", "mode": "fixture", "command": "rm"}, {"scenario_id": [], "mode": "fixture"}, {"scenario_id": "test-example", "mode": "other"}]:
            self.assertEqual(self.request("/api/runs", "POST", body)[0], 400)
        self.assertEqual(self.request("/api/runs", "POST", {}, {"Content-Type": "text/plain"})[0], 400)
        self.assertEqual(self.request("/api/runs", "POST", {}, {"Content-Length": "999999"})[0], 400)
        self.assertEqual(self.request("/../../etc/passwd")[0], 404)
        self.assertEqual(self.request("/api/runs?limit=-1")[0], 400)


class ReportingTests(unittest.TestCase):
    def test_untrusted_html_and_sensitive_values(self):
        run = {"id": "abc", "scenario_id": "<script>alert(1)</script>", "mode": "fixture", "result": {"summary": "<img src=x onerror=alert(1)>"}}
        text = render_html(run)
        self.assertNotIn("<script>", text)
        self.assertNotIn("<img ", text)
        clean = sanitize_result({"password": "hide", "evidence": [{"data": {"authorization": "Bearer abc", "text": "Bearer abc"}, "sha256": "old"}]})
        self.assertNotIn("Bearer abc", json.dumps(clean))
        self.assertNotEqual(clean["evidence"][0]["sha256"], "old")

    def test_cli_missing_baseline_run_is_controlled_error(self):
        with tempfile.TemporaryDirectory() as d, patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(["--db", str(Path(d) / "a.sqlite3"), "baseline", "save", "x", "absent"]), 2)


if __name__ == "__main__":
    unittest.main()
