"""Local-first HTTP API. No arbitrary commands or user-selected filesystem paths."""
from __future__ import annotations

import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .reporting import compare_runs, export_run, redact, render_html

MODES = {"fixture", "replay", "live"}
STATIC_ROOT = Path(__file__).resolve().parent / "static"


def supports_mode(scenario: dict, mode: str) -> bool:
    if mode not in MODES:
        return False
    declared = scenario.get("metadata", {}).get("supported_modes")
    if declared is not None and mode not in declared:
        return False
    return bool(scenario.get({"fixture": "fixture", "replay": "replay", "live": "action"}[mode]))


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class DetectionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, store, catalog, worker, token=None):
        host, _ = address
        if not is_loopback(host):
            raise ValueError("Direct remote binding is disabled in v0.1; use an SSH tunnel to the loopback server")
        if token is not None and (len(token) < 32 or any(c.isspace() for c in token)):
            raise ValueError("API token must contain at least 32 characters and no whitespace")
        self.store, self.catalog, self.worker, self.token = store, catalog, worker, token
        self.local_only = is_loopback(host)
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "DetectionCI/" + __version__
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, fmt, *args):
        # API URLs may contain user-supplied data. Console access logging is off.
        pass

    def _reply(self, status, data, content_type="application/json; charset=utf-8", filename=None):
        if isinstance(data, (dict, list)):
            payload = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = data
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, status, message):
        self._reply(status, {"error": message})

    def _guard(self):
        # Routing and authentication must use the same request-target grammar.
        # Absolute-form / network-path targets otherwise bypass a raw /api/ check.
        try:
            target = urlsplit(self.path)
        except ValueError:
            self._error(400, "Invalid request target")
            return False
        raw_target = self.requestline.split()[1]
        if not self.path.startswith("/") or raw_target.startswith("//") or target.scheme or target.netloc or target.fragment:
            self._error(400, "Only origin-form request targets are accepted")
            return False
        raw_host = self.headers.get("Host", "")
        try:
            host = urlsplit("http://" + raw_host)
            if not host.hostname or host.username or host.password or host.path or host.query or host.fragment:
                raise ValueError()
            if self.server.local_only and not is_loopback(host.hostname):
                raise ValueError()
            if host.port != self.server.server_port:
                raise ValueError()
        except ValueError:
            self._error(403, "Host is not permitted")
            return False
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + raw_host:
            self._error(403, "Cross-origin requests are not permitted")
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._error(403, "Cross-site requests are not permitted")
            return False
        if target.path.startswith("/api/") and self.server.token:
            auth = self.headers.get("Authorization", "")
            expected = "Bearer " + self.server.token
            if not hmac.compare_digest(auth.encode(), expected.encode()):
                self._error(401, "A valid API token is required")
                return False
        return True

    def _body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        raw = self.headers.get("Content-Length", "")
        if not raw.isdigit() or not 0 < int(raw) <= 65536:
            raise ValueError("A body of 1..65536 bytes is required")
        length = int(raw)
        payload = self.rfile.read(length)
        if len(payload) != length:
            raise ValueError("Incomplete request body")
        obj = json.loads(payload)
        if not isinstance(obj, dict):
            raise ValueError("Request must be a JSON object")
        return obj

    def do_GET(self):
        if not self._guard():
            return
        try:
            parsed = urlsplit(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            if path in {"/", "/index.html", "/app.js", "/style.css"}:
                name = "index.html" if path == "/" else path[1:]
                content_type = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}[name]
                return self._reply(200, (STATIC_ROOT / name).read_bytes(), content_type)
            if path == "/api/health":
                modes = ["fixture"]
                config = self.server.worker.engine.config
                if config.get("wazuh"):
                    modes.append("replay")
                    if config.get("live"):
                        modes.append("live")
                return self._reply(200, {"status": "ok" if self.server.worker.running else "degraded", "worker": "running" if self.server.worker.running else "stopped", "configured_modes": modes, "live_target_state": self.server.worker.target_status(), "version": __version__, "scope_notice": "Worker status does not attest SIEM health. Fixture runs use local test data only."})
            if path == "/api/scenarios":
                return self._reply(200, {"scenarios": redact(list(self.server.catalog.values()))})
            if path == "/api/runs":
                limit = int(query.get("limit", ["50"])[0])
                offset = int(query.get("offset", ["0"])[0])
                if not 1 <= limit <= 100 or offset < 0:
                    raise ValueError("Invalid pagination")
                return self._reply(200, {"runs": redact(self.server.store.list_runs(limit, offset))})
            if path == "/api/baselines":
                return self._reply(200, {"baselines": redact(self.server.store.list_baselines())})
            if path == "/api/compare":
                baseline = self.server.store.get_baseline(query.get("baseline", [""])[0])
                if not baseline:
                    return self._error(404, "Baseline does not exist")
                ids = query.get("run_ids", [""])[0].split(",")
                if not 1 <= len(ids) <= 50 or len(set(ids)) != len(ids):
                    raise ValueError("Select 1..50 unique run IDs")
                runs = [self.server.store.get_run(i) for i in ids]
                if any(r is None for r in runs):
                    return self._error(404, "A selected run does not exist")
                return self._reply(200, {"comparison": compare_runs(baseline, runs)})
            match = re.fullmatch(r"/api/runs/([A-Za-z0-9_-]{1,100})(/report)?", path)
            if match:
                run = self.server.store.get_run(match.group(1))
                if not run:
                    return self._error(404, "Run does not exist")
                if match.group(2):
                    fmt = query.get("format", ["json"])[0]
                    if fmt == "html":
                        return self._reply(200, render_html(run), "text/html; charset=utf-8", run["id"] + ".html")
                    if fmt != "json":
                        raise ValueError("Report format must be json or html")
                    return self._reply(200, export_run(run), filename=run["id"] + ".json")
                return self._reply(200, {"run": redact(run)})
            return self._error(404, "Endpoint does not exist")
        except (ValueError, KeyError, UnicodeDecodeError) as exc:
            self._error(400, str(exc)[:300])
        except Exception:
            self._error(500, "Internal error; no successful validation was recorded")

    def do_POST(self):
        if not self._guard():
            return
        try:
            body = self._body()
            path = urlsplit(self.path).path
            if path == "/api/runs":
                if set(body) != {"scenario_id", "mode"}:
                    raise ValueError("Expected scenario_id and mode")
                scenario = self.server.catalog.get(body["scenario_id"])
                if not scenario:
                    return self._error(404, "Scenario does not exist")
                if not supports_mode(scenario, body["mode"]):
                    raise ValueError("Scenario does not support this validation mode")
                if not self.server.worker.running:
                    return self._error(503, "Worker is not running")
                return self._reply(202, {"run": redact(self.server.store.create_run(scenario, body["mode"]))})
            match = re.fullmatch(r"/api/runs/([A-Za-z0-9_-]{1,100})/cancel", path)
            if match:
                if body:
                    raise ValueError("Cancel request body must be an empty object")
                if not self.server.store.get_run(match.group(1)):
                    return self._error(404, "Run does not exist")
                return self._reply(200, {"run": redact(self.server.worker.cancel(match.group(1)))})
            if path == "/api/baselines":
                if set(body) != {"name", "run_ids"} or not isinstance(body["run_ids"], list):
                    raise ValueError("Expected name and run_ids array")
                if not 1 <= len(body["run_ids"]) <= 50:
                    raise ValueError("Select 1..50 run IDs")
                return self._reply(201, {"baseline": redact(self.server.store.save_baseline(body["name"], body["run_ids"]))})
            return self._error(404, "Endpoint does not exist")
        except (ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
            self._error(400, str(exc)[:300])
        except TimeoutError:
            self._error(408, "Request timed out")
        except Exception:
            self._error(500, "Internal error; no successful validation was recorded")
