"""Seori command line. Only verified passing runs return exit status zero."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

from . import __version__
from .catalog import DEFAULT_SCENARIOS, load_catalog, resolve_scenario
from .config import load_config
from .engine import Engine
from .models import load_scenario
from .reporting import compare_runs, export_run, render_html, write_reports
from .server import DetectionServer, supports_mode
from .store import Store
from .worker import Worker


def parser():
    p = argparse.ArgumentParser(prog="seori", description="Reproducible detection validation. Fixture results do not attest a real SIEM.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--db", default=".detectionci/runs.sqlite3", help="Local SQLite state (default: .detectionci/runs.sqlite3)")
    p.add_argument("--config", default=os.environ.get("DCI_CONFIG"), help="JSON configuration; supports complete ${DCI_*} environment references")
    p.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS), help="Scenario directory")
    sub = p.add_subparsers(dest="command", required=True)
    ls = sub.add_parser("scenarios", help="List scenarios and supported modes")
    ls.add_argument("--json", action="store_true")
    validate = sub.add_parser("validate", help="Validate scenario contracts without external I/O")
    validate.add_argument("paths", nargs="*")
    validate.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify-fixtures", help="Self-test fixture verdicts, including deliberate failures; does not verify Wazuh")
    verify.add_argument("--json", action="store_true")
    run = sub.add_parser("run", help="Execute one scenario")
    run.add_argument("scenario")
    suite = sub.add_parser("suite", help="Execute all scenarios supporting the requested mode")
    for child in (run, suite):
        child.add_argument("--mode", choices=["fixture", "replay", "live"], default="fixture")
        child.add_argument("--json", action="store_true")
        child.add_argument("--output", help="Write redacted JSON and self-contained HTML reports")
    serve = sub.add_parser("serve", help="Serve the local dashboard and API")
    serve.add_argument("--host", default="127.0.0.1", help="Loopback address only; remote access uses an SSH tunnel")
    serve.add_argument("--port", type=int, default=8787)
    report = sub.add_parser("report", help="Export a stored run")
    report.add_argument("run_id")
    report.add_argument("--format", choices=["json", "html"], default="json")
    baseline = sub.add_parser("baseline", help="Manage immutable comparison baselines")
    base_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    save = base_sub.add_parser("save")
    save.add_argument("name")
    save.add_argument("run_ids", nargs="+")
    base_sub.add_parser("list")
    compare = sub.add_parser("compare", help="Compare current runs with an immutable baseline")
    compare.add_argument("name")
    compare.add_argument("run_ids", nargs="+")
    target = sub.add_parser("target", help="Inspect live target recovery status")
    target_sub = target.add_subparsers(dest="target_command", required=True)
    target_sub.add_parser("status")
    reset = target_sub.add_parser("reset", help="Clear guard only after independently restoring the laboratory VM")
    reset.add_argument("--acknowledge-restored", action="store_true", required=True)
    return p


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False))


def execute_runs(args, catalog, config):
    if args.command == "run":
        scenario = resolve_scenario(args.scenario, catalog)
        if not supports_mode(scenario, args.mode):
            raise ValueError("This scenario does not support the requested mode")
        scenarios = [scenario]
    else:
        scenarios = [s for s in catalog.values() if supports_mode(s, args.mode)]
    if not scenarios:
        raise ValueError("No scenarios support this mode")
    if args.mode in {"replay", "live"} and not config.get("wazuh"):
        raise ValueError("This mode requires a real Wazuh configuration (--config); no synthetic fallback is available")
    if args.mode == "live" and not config.get("live"):
        raise ValueError("Live mode requires a registered laboratory SSH target")
    store = Store(args.db)
    worker = Worker(store, args.db, config)
    worker.start()
    ids = []
    try:
        suite_id = str(uuid.uuid4()) if args.command == "suite" else None
        ids = [store.create_run(s, args.mode, suite_id)["id"] for s in scenarios]
        runs = worker.wait_for(ids, sum(s["timeout_seconds"] + 50 for s in scenarios))
    except KeyboardInterrupt:
        for run_id in ids:
            worker.cancel(run_id)
        print("Cancellation requested; waiting for bounded cleanup.", file=sys.stderr)
        raise
    finally:
        worker.stop()
    files = []
    for run in runs:
        if args.output:
            files.extend(write_reports(run, args.output))
    if args.json:
        emit({"runs": [export_run(r)["run"] for r in runs], "report_files": files,
              "scope": {"fixture": "local test logic only", "replay": "Wazuh rules on supplied logs", "live": "real action and observed telemetry stages"}[args.mode]})
    else:
        print(f"Mode: {args.mode}. " + ("LOCAL FIXTURE LOGIC ONLY; Wazuh was not contacted." if args.mode == "fixture" else "External laboratory systems are used."))
        for run in runs:
            print(f"{run['verdict']:12} {run['scenario_id']:34} {run['id']}")
            print("  " + (run.get("result") or {}).get("summary", ""))
        for path in files:
            print("Report: " + path)
    return 0 if all(r["verdict"] == "PASS" for r in runs) else 1


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "validate":
            paths = [Path(p) for p in args.paths] if args.paths else sorted(Path(args.scenarios).glob("*.json"))
            if not paths:
                raise ValueError("No scenario files found")
            rows = [{"path": str(p), "id": load_scenario(p)["id"], "valid": True} for p in paths]
            if args.json:
                emit({"scenarios": rows})
            else:
                for row in rows:
                    print("VALID " + row["id"])
            return 0
        if args.command == "verify-fixtures":
            paths = sorted(Path(args.scenarios).glob("*.json"))
            paths += sorted((Path(args.scenarios).parent / "fixtures" / "fault-scenarios").glob("*.json"))
            rows = []
            for path in paths:
                scenario = load_scenario(path)
                if not scenario.get("fixture"):
                    continue
                result = Engine().execute({"id": str(uuid.uuid4()), "mode": "fixture", "scenario": scenario})
                expected = scenario.get("expected_verdict", scenario.get("metadata", {}).get("expected_verdict", "PASS"))
                rows.append({"scenario_id": scenario["id"], "expected_verdict": expected,
                             "actual_verdict": result["verdict"], "matches_expectation": expected == result["verdict"]})
            if not rows:
                raise ValueError("No fixture cases found")
            if args.json:
                emit({"scope": "Self-test of local result logic, not SIEM validation", "cases": rows})
            else:
                print("Fixture logic self-test; deliberate FAIL/INCONCLUSIVE results are expected cases.")
                for row in rows:
                    print(f"{'OK' if row['matches_expectation'] else 'MISMATCH':8} {row['scenario_id']:38} expected={row['expected_verdict']} actual={row['actual_verdict']}")
            return 0 if all(r["matches_expectation"] for r in rows) else 1
        # State-only commands must remain usable even if a scenario was removed.
        if args.command == "report":
            run = Store(args.db).get_run(args.run_id)
            if not run:
                raise ValueError("Run does not exist")
            if args.format == "html":
                print(render_html(run))
            else:
                emit(export_run(run))
            return 0
        if args.command == "baseline":
            store = Store(args.db)
            emit(store.save_baseline(args.name, args.run_ids) if args.baseline_command == "save" else store.list_baselines())
            return 0
        if args.command == "compare":
            store = Store(args.db)
            baseline = store.get_baseline(args.name)
            if not baseline:
                raise ValueError("Baseline does not exist")
            runs = [store.get_run(i) for i in args.run_ids]
            if any(r is None for r in runs):
                raise ValueError("A selected run does not exist")
            result = compare_runs(baseline, runs)
            emit(result)
            return 0 if result["verdict"] == "PASS" else 1
        config = load_config(args.config)
        if args.command == "target":
            worker = Worker(Store(args.db), args.db, config)
            if args.target_command == "reset":
                worker.clear_target_state()
            emit(worker.target_status())
            return 0
        catalog = load_catalog(args.scenarios)
        if args.command == "scenarios":
            if args.json:
                emit({"scenarios": list(catalog.values())})
            else:
                for s in catalog.values():
                    modes = ", ".join(m for m in ("fixture", "replay", "live") if supports_mode(s, m))
                    print(f"{s['id']:36} [{modes}] {s['title']}")
            return 0
        if args.command in {"run", "suite"}:
            return execute_runs(args, catalog, config)
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                raise ValueError("Port must be 0..65535")
            store = Store(args.db)
            worker = Worker(store, args.db, config)
            server = DetectionServer((args.host, args.port), store, catalog, worker, os.environ.get("DCI_API_TOKEN"))
            try:
                worker.start()
                print(f"Seori {__version__}: http://{args.host}:{server.server_port}", flush=True)
                print("Fixture runs validate local logic only. Live Wazuh verification requires a configured laboratory.", flush=True)
                server.serve_forever(poll_interval=.2)
            finally:
                server.server_close()
                worker.stop()
            return 0
        raise ValueError("Unknown command")
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, RuntimeError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
        # Config and operator errors must not print credential-bearing values.
        print(f"Seori: {str(exc)[:400]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
