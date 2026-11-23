"""Transport contract tests. These tests use fake or loopback HTTP servers,
not a real Wazuh installation, and do not validate Wazuh detection content.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.message import Message
import io
import json
from pathlib import Path
import ssl
import threading
import unittest
from unittest.mock import Mock, patch
from urllib import error, request
from urllib.response import addinfourl

from detectionci.wazuh import WazuhCancelled, WazuhClient, WazuhConfig, WazuhConfigError, WazuhError, _NoRedirect


START = "2026-11-17T10:00:00Z"
END = "2026-11-17T10:00:30Z"
ALERT = {"timestamp": "2026-11-17T10:00:01Z", "agent": {"id": "001"},
         "rule": {"id": "100200"}, "syscheck": {"path": "/var/lib/detectionci/watch/test.txt"}}


def configured(**changes):
    values = {"manager_url": "http://127.0.0.1:55000", "manager_username": "manager-user",
              "manager_password": "manager-secret", "indexer_url": "http://127.0.0.1:9200",
              "indexer_username": "index-user", "indexer_password": "index-secret"}
    values.update(changes)
    return WazuhConfig.from_dict(values)


def response(alerts=None, **changes):
    alerts = [] if alerts is None else alerts
    result = {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
              "hits": {"total": {"value": len(alerts), "relation": "eq"},
                       "hits": [{"_index": "wazuh-alerts-4.x-test", "_id": str(i), "_source": a}
                                for i, a in enumerate(alerts)]}}
    result.update(changes)
    return result


def logtest(token="session-1", alert=True):
    return {"token": token, "codemsg": 0, "alert": alert,
            "output": deepcopy(ALERT) if alert else {"decoder": {"name": "sshd"}}}


class ConfigTests(unittest.TestCase):
    def test_https_and_loopback(self):
        for url in ("https://siem.internal:55000", "http://127.0.0.1:55000", "http://localhost:55000", "http://[::1]:55000"):
            with self.subTest(url=url):
                self.assertEqual(WazuhConfig.from_dict({"manager_url": url}).manager_url, url)

    def test_refuses_unverified_remote_http(self):
        for url in ("http://192.168.1.20:55000", "http://localhost.evil/", "ftp://127.0.0.1/"):
            with self.subTest(url=url), self.assertRaises(WazuhConfigError):
                WazuhConfig.from_dict({"manager_url": url})

    def test_refuses_credentials_query_fragment_and_traversal(self):
        for url in ("https://user:secret@siem/", "https://siem/?secret=yes", "https://siem/#x",
                    "https://siem/../path", "https://siem/%2e%2e/path", "https://siem:0/", "https://siem:bad/"):
            with self.subTest(url=url), self.assertRaises(WazuhConfigError):
                WazuhConfig.from_dict({"manager_url": url})

    def test_rejects_invalid_timeouts(self):
        for value in (True, False, 0, -1, 61, float("nan"), float("inf"), "10"):
            with self.subTest(value=value), self.assertRaises(WazuhConfigError):
                WazuhConfig.from_dict({"request_timeout": value})

    def test_rejects_bad_credentials_without_echoing_them(self):
        for field in ("manager_username", "manager_password"):
            with self.subTest(field=field), self.assertRaises(WazuhConfigError) as cm:
                WazuhConfig.from_dict({field: "private-value\r\nInjected: x"})
            self.assertNotIn("private-value", str(cm.exception))

    def test_no_insecure_tls_configuration_option(self):
        with self.assertRaises(WazuhConfigError):
            WazuhConfig.from_dict({"verify_tls": False})

    def test_passwords_absent_from_repr(self):
        value = repr(configured())
        self.assertNotIn("manager-secret", value)
        self.assertNotIn("index-secret", value)

    def test_missing_ca_is_rejected(self):
        with self.assertRaises(WazuhConfigError):
            WazuhConfig.from_dict({"ca_file": "/nonexistent/dci-ca.pem"})

    def test_direct_construction_revalidated(self):
        with self.assertRaises(WazuhConfigError):
            WazuhClient(WazuhConfig(manager_url="http://192.168.1.20"))


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhClient(configured())
        self.client._manager_auth = Mock(return_value="jwt-secret")

    def test_reuses_one_session_within_run_and_closes_it(self):
        self.client._manager = Mock(side_effect=[logtest(), logtest(), {"messages": []}])
        alerts = self.client.replay(["line one", "line two"])
        self.assertEqual(len(alerts), 2)
        calls = self.client._manager.call_args_list
        self.assertNotIn("token", calls[0].args[2])
        self.assertEqual(calls[1].args[2]["token"], "session-1")
        self.assertEqual(calls[2].args, ("DELETE", "/logtest/sessions/session-1"))

    def test_no_alert_is_valid_processing_result(self):
        self.client._manager = Mock(side_effect=[logtest(alert=False), {"messages": []}])
        self.assertEqual(self.client.replay(["ordinary line"]), [])

    def test_new_replay_does_not_reuse_old_session(self):
        self.client._manager = Mock(side_effect=[logtest(), {}, logtest("session-2"), {}])
        self.client.replay(["first"])
        self.client.replay(["second"])
        calls = self.client._manager.call_args_list
        self.assertNotIn("token", calls[2].args[2])

    def test_session_change_is_error_and_both_sessions_are_closed(self):
        self.client._manager = Mock(side_effect=[logtest(), logtest("session-2"), {}, {}])
        with self.assertRaisesRegex(WazuhError, "state was lost"):
            self.client.replay(["first", "second"])
        deletes = [c.args[1] for c in self.client._manager.call_args_list if c.args[0] == "DELETE"]
        self.assertEqual(set(deletes), {"/logtest/sessions/session-1", "/logtest/sessions/session-2"})

    def test_exception_during_processing_still_closes_session(self):
        self.client._manager = Mock(side_effect=[logtest(), WazuhError("request failed"), {}])
        with self.assertRaisesRegex(WazuhError, "request failed"):
            self.client.replay(["first", "second"])
        self.assertEqual(self.client._manager.call_args_list[-1].args[0], "DELETE")

    def test_failed_cleanup_invalidates_success(self):
        self.client._manager = Mock(side_effect=[logtest(), WazuhError("cleanup failed")])
        with self.assertRaisesRegex(WazuhError, "cleanup failed"):
            self.client.replay(["line"])

    def test_cancel_before_execution_has_no_network_effect(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(WazuhCancelled):
            self.client.replay(["line"], event)
        self.client._manager_auth.assert_not_called()

    def test_cancel_after_event_closes_session(self):
        event = threading.Event()
        def manager(method, path, payload=None):
            if method == "PUT":
                event.set()
                return logtest()
            return {}
        self.client._manager = Mock(side_effect=manager)
        with self.assertRaises(WazuhCancelled):
            self.client.replay(["line"], event)
        self.assertEqual(self.client._manager.call_args_list[-1].args[0], "DELETE")

    def test_malformed_processing_data_is_not_zero_alert_success(self):
        for data in ({"token": "session-1", "codemsg": 0, "output": {}},
                     {"token": "session-1", "codemsg": 3, "alert": False, "output": {}},
                     {"token": "session-1", "codemsg": 0, "alert": True, "output": {}},
                     {"token": "../../secret", "codemsg": 0, "alert": True, "output": ALERT}):
            with self.subTest(data=data):
                self.client._manager = Mock(side_effect=[data, {}])
                with self.assertRaises(WazuhError):
                    self.client.replay(["line"])

    def test_replay_inputs_bounded_before_io(self):
        for logs in ([], "line", [""], ["x\x00y"], ["x" * 65537], ["x"] * 1001):
            with self.subTest(logs_type=type(logs).__name__), self.assertRaises(WazuhConfigError):
                self.client.replay(logs)
        self.client._manager_auth.assert_not_called()


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhClient(configured())

    def search(self, data, predicates=None):
        self.client._request = Mock(return_value=data)
        return self.client.search_alerts("001", START, END, predicates)

    def test_source_documents_returned_and_exact_predicate_applied_locally(self):
        another = deepcopy(ALERT)
        another["syscheck"]["path"] = "/var/lib/detectionci/watch/other.txt"
        result = self.search(response([ALERT, another]), [{"field": "syscheck.path", "op": "eq", "value": ALERT["syscheck"]["path"]}])
        self.assertEqual(result, [ALERT])
        payload = self.client._request.call_args.kwargs["payload"]
        self.assertTrue(payload["track_total_hits"])
        self.assertEqual(payload["query"]["bool"]["filter"][0], {"term": {"agent.id": "001"}})
        self.assertEqual(payload["query"]["bool"]["filter"][1]["range"]["timestamp"], {"gte": START, "lte": END})

    def test_zero_alerts_require_complete_successful_search(self):
        self.assertEqual(self.search(response()), [])

    def test_partial_or_timed_out_search_never_returns_zero_success(self):
        cases = [response(timed_out=True), response(terminated_early=True),
                 response(_shards={"total": 2, "successful": 1, "failed": 1}),
                 response(_shards={"total": 2, "successful": 1, "failed": 0}),
                 response(_shards={"total": 0, "successful": 0, "failed": 0}),
                 response(_shards={}), {}]
        for data in cases:
            with self.subTest(data=data), self.assertRaises(WazuhError):
                self.search(data)

    def test_truncated_and_inexact_totals_rejected(self):
        for total in ({"value": 1, "relation": "eq"}, {"value": 0, "relation": "gte"},
                      {"value": 1001, "relation": "eq"}, -1, True):
            data = response()
            data["hits"]["total"] = total
            with self.subTest(total=total), self.assertRaises(WazuhError):
                self.search(data)

    def test_out_of_window_or_different_agent_rejected(self):
        for field, value in (("timestamp", "2020-01-01T00:00:00Z"), ("agent", {"id": "002"}),
                             ("timestamp", "not-a-time")):
            alert = deepcopy(ALERT)
            alert[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(WazuhError):
                self.search(response([alert]))

    def test_duplicate_document_ids_rejected(self):
        data = response([ALERT, ALERT])
        data["hits"]["hits"][1]["_id"] = "0"
        with self.assertRaisesRegex(WazuhError, "duplicate"):
            self.search(data)

    def test_malformed_source_documents_rejected(self):
        data = response([ALERT])
        del data["hits"]["hits"][0]["_source"]
        with self.assertRaises(WazuhError):
            self.search(data)

    def test_bad_times_and_predicates_rejected_before_io(self):
        self.client._request = Mock()
        for args in (("001", END, START), ("001", "2026-11-17T10:00:00", END), ("bad id", START, END)):
            with self.subTest(args=args), self.assertRaises(WazuhConfigError):
                self.client.search_alerts(*args)
        for predicates in ([{"field": "rule.id;DROP", "op": "eq", "value": "1"}],
                           [{"field": "rule.id", "op": "regex", "value": "(a+)+$"}],
                           [{"field": "rule.id", "op": "query_string", "value": "*"}]):
            with self.subTest(predicates=predicates), self.assertRaises(WazuhConfigError):
                self.client.search_alerts("001", START, END, predicates)
        self.client._request.assert_not_called()

    def test_scalar_type_comparison_does_not_equate_boolean_with_number(self):
        alert = deepcopy(ALERT)
        alert["data"] = {"value": 1}
        self.assertEqual(self.search(response([alert]), [{"field": "data.value", "op": "eq", "value": True}]), [])


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.client = WazuhClient(configured())

    def test_tls_context_is_verified(self):
        with patch("detectionci.wazuh.ssl.create_default_context", wraps=ssl.create_default_context) as create:
            WazuhClient(configured())
            create.assert_called_once_with(cafile=None)

    def test_external_error_bodies_and_reason_phrases_are_not_exposed(self):
        self.client._opener.open = Mock(side_effect=error.HTTPError("https://siem", 401, "manager-secret", {}, None))
        with self.assertRaises(WazuhError) as cm:
            self.client._manager_auth()
        self.assertNotIn("manager-secret", str(cm.exception))
        self.assertIn("HTTP 401", str(cm.exception))

    def test_connection_exception_is_sanitized(self):
        self.client._opener.open = Mock(side_effect=error.URLError("index-secret"))
        with self.assertRaises(WazuhError) as cm:
            self.client._manager_auth()
        self.assertNotIn("index-secret", str(cm.exception))

    def test_malformed_json_rejected(self):
        result = Mock()
        result.status = 200
        result.read.return_value = b"not-json"
        result.__enter__ = Mock(return_value=result)
        result.__exit__ = Mock(return_value=False)
        self.client._opener.open = Mock(return_value=result)
        with self.assertRaisesRegex(WazuhError, "malformed JSON"):
            self.client._request(self.client.config.manager_url, "GET", "/", auth="Bearer token")

    def test_oversized_response_rejected(self):
        result = Mock()
        result.status = 200
        result.read.return_value = b"x" * (self.client.MAX_RESPONSE_BYTES + 1)
        result.__enter__ = Mock(return_value=result)
        result.__exit__ = Mock(return_value=False)
        self.client._opener.open = Mock(return_value=result)
        with self.assertRaisesRegex(WazuhError, "size limit"):
            self.client._request(self.client.config.manager_url, "GET", "/", auth="Bearer token")


class InMemoryHTTPTests(unittest.TestCase):
    """Actual urllib request/response pipeline with an in-memory HTTP handler.

    This covers method/header/body and redirect behavior even where sandbox
    policy prohibits binding a loopback socket.
    """

    def setUp(self):
        self.calls = []
        calls = self.calls
        self.behavior = {"redirect": False, "bad_json": False, "api_error": False}
        behavior = self.behavior

        class Transport(request.HTTPHandler):
            def http_open(self, req):
                data = req.data
                calls.append((req.get_method(), req.selector, dict(req.header_items()), json.loads(data) if data else None))
                headers = Message()
                headers["Content-Type"] = "application/json"
                code = 200
                if behavior["redirect"]:
                    code = 302
                    headers["Location"] = "/redirected"
                    body = b""
                elif req.selector.startswith("/security/user/authenticate"):
                    body = b"test.jwt.token"
                elif behavior["bad_json"]:
                    body = b"{bad"
                elif req.selector == "/logtest":
                    body = json.dumps({"error": 1 if behavior["api_error"] else 0, "data": logtest()}).encode()
                elif req.selector.startswith("/logtest/sessions/"):
                    body = b'{"error":0,"data":{"messages":[]}}'
                elif req.selector.endswith("/_search"):
                    body = json.dumps(response([ALERT])).encode()
                else:
                    body = b'{"error":0,"data":{"api_version":"4.14.10"}}'
                headers["Content-Length"] = str(len(body))
                reply = addinfourl(io.BytesIO(body), headers, req.full_url, code)
                reply.msg = "Fake transport"
                return reply

        self.client = WazuhClient(configured())
        self.client._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect(), Transport())

    def test_complete_replay_http_protocol(self):
        self.assertEqual(len(self.client.replay(["first", "second"])), 2)
        self.assertEqual([c[0] for c in self.calls], ["POST", "PUT", "PUT", "DELETE"])
        self.assertEqual(self.calls[0][2]["Authorization"], "Basic " + base64.b64encode(b"manager-user:manager-secret").decode())
        self.assertEqual(self.calls[1][2]["Authorization"], "Bearer test.jwt.token")
        self.assertEqual(self.calls[2][3]["token"], "session-1")

    def test_indexer_http_method_and_basic_credentials(self):
        self.assertEqual(self.client.search_alerts("001", START, END), [ALERT])
        self.assertEqual(self.calls[0][0], "POST")
        self.assertEqual(self.calls[0][1], "/wazuh-alerts-4.x-*/_search")
        self.assertEqual(self.calls[0][2]["Authorization"], "Basic " + base64.b64encode(b"index-user:index-secret").decode())

    def test_redirect_not_followed_and_credentials_not_forwarded(self):
        self.behavior["redirect"] = True
        with self.assertRaisesRegex(WazuhError, "HTTP 302"):
            self.client.replay(["line"])
        self.assertEqual(len(self.calls), 1)

    def test_bad_json_over_http_pipeline(self):
        self.behavior["bad_json"] = True
        with self.assertRaisesRegex(WazuhError, "malformed JSON"):
            self.client.search_alerts("001", START, END)

    def test_api_error_over_http_pipeline(self):
        self.behavior["api_error"] = True
        with self.assertRaisesRegex(WazuhError, "API error status"):
            self.client.replay(["line"])


class LoopbackHTTPTests(unittest.TestCase):
    """Exercise urllib methods, headers, JSON bodies and redirect rejection."""

    def setUp(self):
        self.calls = []
        calls = self.calls
        self.behavior = {"redirect": False, "bad_json": False, "api_error": False}
        behavior = self.behavior
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                calls.append((self.command, self.path, dict(self.headers), json.loads(data) if data else None))
                if behavior["redirect"]:
                    self.send_response(302)
                    self.send_header("Location", "/redirected")
                    self.end_headers()
                    return
                if self.path.startswith("/security/user/authenticate"):
                    body = b"test.jwt.token"
                elif behavior["bad_json"]:
                    body = b"{bad"
                elif self.path == "/logtest":
                    body = json.dumps({"error": 1 if behavior["api_error"] else 0, "data": logtest()}).encode()
                elif self.path.startswith("/logtest/sessions/"):
                    body = b'{"error":0,"data":{"messages":[]}}'
                elif self.path.endswith("/_search"):
                    body = json.dumps(response([ALERT])).encode()
                else:
                    body = b'{"error":0,"data":{"api_version":"4.14.10"}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = handle_request
            do_PUT = handle_request
            do_DELETE = handle_request
            do_GET = handle_request

        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except OSError as exc:
            self.skipTest(f"Loopback HTTP unavailable: {type(exc).__name__}")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        url = f"http://127.0.0.1:{self.server.server_port}"
        self.client = WazuhClient(configured(manager_url=url, indexer_url=url))

    def tearDown(self):
        if hasattr(self, "server"):
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)

    def test_complete_replay_http_protocol(self):
        self.assertEqual(len(self.client.replay(["first", "second"])), 2)
        self.assertEqual([c[0] for c in self.calls], ["POST", "PUT", "PUT", "DELETE"])
        auth = self.calls[0][2]["Authorization"]
        self.assertEqual(auth, "Basic " + base64.b64encode(b"manager-user:manager-secret").decode())
        self.assertEqual(self.calls[1][2]["Authorization"], "Bearer test.jwt.token")
        self.assertEqual(self.calls[2][3]["token"], "session-1")

    def test_indexer_http_method_and_basic_credentials(self):
        self.assertEqual(self.client.search_alerts("001", START, END), [ALERT])
        self.assertEqual(self.calls[0][0], "POST")
        self.assertEqual(self.calls[0][1], "/wazuh-alerts-4.x-*/_search")
        self.assertEqual(self.calls[0][2]["Authorization"], "Basic " + base64.b64encode(b"index-user:index-secret").decode())

    def test_redirect_not_followed_and_credentials_not_forwarded(self):
        self.behavior["redirect"] = True
        with self.assertRaisesRegex(WazuhError, "HTTP 302"):
            self.client.replay(["line"])
        self.assertEqual(len(self.calls), 1)

    def test_bad_json_over_http(self):
        self.behavior["bad_json"] = True
        with self.assertRaisesRegex(WazuhError, "malformed JSON"):
            self.client.search_alerts("001", START, END)

    def test_api_error_over_http(self):
        self.behavior["api_error"] = True
        with self.assertRaisesRegex(WazuhError, "API error status"):
            self.client.replay(["line"])


if __name__ == "__main__":
    unittest.main()
