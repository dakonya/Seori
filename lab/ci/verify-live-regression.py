"""Collect independent Indexer evidence and verify the three live FIM runs."""

import argparse
from contextlib import redirect_stdout
from datetime import datetime
import hashlib
import json
from pathlib import Path
import runpy
import sys

from detectionci.config import load_config
from detectionci.engine import WATCH_ROOT
from detectionci.models import digest, get_field
from detectionci.wazuh import WazuhClient, WazuhConfig, WazuhError


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "Evidence timestamps must include a time zone")
    return parsed


def verify_regression(run, agent_id):
    require((run["scenario_id"], run["mode"], run["status"], run["verdict"]) ==
            ("fim-file-created", "live", "completed", "FAIL"), "Expected a completed live fim-file-created FAIL")
    result = run["result"]
    metadata = result["metadata"]
    path = Path(WATCH_ROOT) / f"{run['id']}.txt"
    require(result["verdict"] == "FAIL" and metadata["fixture_only"] is False
            and metadata["external_systems_contacted"] is True, "Expected an actual live FAIL")
    require(metadata["target_agent_id"] == agent_id and metadata["run_path"] == str(path),
            "Regression report agent or path differs from the registered agent and run UUID")

    assertions = {item["id"]: item for item in result["assertions"]}
    count = assertions.pop("matching-alert-count")
    require(count["verdict"] == "FAIL" and count["actual"] == 0
            and count["expected"] == {"min_alerts": 1, "max_alerts": None},
            "The live FAIL must report zero matches for the unchanged positive assertion")
    require(all(item["verdict"] == "PASS" for item in assertions.values()),
            "A live assertion other than matching-alert-count failed")
    checkpoints = {entry["name"]: entry["status"] for entry in result["checkpoints"]}
    require(all(checkpoints.get(name) == "observed" for name in ("action", "source", "indexer", "cleanup")),
            "Regression run is missing an action, source, Indexer or cleanup observation")

    evidence = result["evidence"]
    require(all(digest(item["data"]) == item["sha256"] for item in evidence), "Evidence SHA-256 did not match")
    states = {"remote_prepare": {"exists": False}, "remote_action": {"exists": True},
              "remote_cleanup": {"clean": True}}
    for kind, fields in states.items():
        records = [item["data"] for item in evidence if item["kind"] == kind]
        expected = {"ok": True, "source_verified": True, **fields}
        require(len(records) == 1 and all(records[0].get(key) is value for key, value in expected.items()),
                f"Regression report is missing confirmed {kind} evidence")
    require(metadata["cleanup_verified"] is True and path.parent.is_dir(),
            "Expected confirmed cleanup and the monitored directory on the runner")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("The regression test file still exists on the runner")

    return count["actual"]


def indexer_window(run, agent_id):
    metadata = run["result"]["metadata"]
    start, end = metadata["time_window_start"], run["finished_at"]
    require(timestamp(run["started_at"]) <= timestamp(start) <= timestamp(end),
            "The regression report contains an invalid observation window")
    return {"agent_id": agent_id, "path": metadata["run_path"], "event": "added", "start": start, "end": end}


def query_added_alerts(config_path, window):
    config = load_config(config_path)
    require(config["live"]["agent_id"] == window["agent_id"], "Indexer proof agent differs from the live configuration")
    indexer = WazuhClient(WazuhConfig.from_dict(config["wazuh"]))
    alerts = indexer.search_alerts(window["agent_id"], window["start"], window["end"], predicates=[
        {"field": "syscheck.path", "op": "eq", "value": window["path"]},
        {"field": "syscheck.event", "op": "eq", "value": window["event"]},
    ])
    # Store only the correlation fields from the independent Indexer response.
    return [{"rule_id": get_field(alert, "rule.id"), "agent_id": get_field(alert, "agent.id"),
             "path": get_field(alert, "syscheck.path"), "event": get_field(alert, "syscheck.event"),
             "timestamp": alert["timestamp"]} for alert in alerts]


def verify_indexer_evidence(evidence, run_id, report_sha256, window):
    require(evidence["run_id"] == run_id and evidence["native_json_sha256"] == report_sha256
            and evidence["query"] == window, "Independent Indexer proof is for a different report or window")
    alerts = evidence["alerts"]
    require({alert["rule_id"] for alert in alerts} == {"554"},
            "The independent Indexer search must return stock rule 554 for the added event")
    start, end = timestamp(window["start"]), timestamp(window["end"])
    require(all(alert["agent_id"] == window["agent_id"] and alert["path"] == window["path"]
                and alert["event"] == window["event"] and start <= timestamp(alert["timestamp"]) <= end
                for alert in alerts), "Indexer proof does not match the regression agent, path, event and time window")


def verify_sequence(directory, regression, agent_id, regression_matches):
    baseline = read_reports(directory / "baseline")
    restored = read_reports(directory / "restored")
    with redirect_stdout(sys.stderr):
        verify_live(baseline, agent_id)
        verify_live(restored, agent_id)

    require(len({baseline["id"], regression["id"], restored["id"]}) == 3, "The phases must have distinct run IDs")
    require(baseline["scenario"] == regression["scenario"] == restored["scenario"],
            "The DetectionCI scenario changed between phases")
    require(timestamp(baseline["finished_at"]) <= timestamp(regression["started_at"])
            and timestamp(regression["finished_at"]) <= timestamp(restored["started_at"]),
            "The three phases were not run sequentially")
    require(len({run["result"]["metadata"]["operator_config_sha256"] for run in (baseline, regression, restored)}) == 1,
            "The DetectionCI operator configuration changed between phases")

    rows = []
    for phase, run, rule in (("Baseline", baseline, "100200"), ("Regression", regression, "554"),
                             ("Restored", restored, "100200")):
        matches = regression_matches if phase == "Regression" else next(
            item["actual"] for item in run["result"]["assertions"] if item["id"] == "matching-alert-count")
        rows.append(f'| {phase} | {run["verdict"]} | `100200` | `{rule}` | {matches} | Confirmed |')
    return "\n".join([
        "### Live FIM rule regression", "",
        "| Phase | DetectionCI verdict | Expected rule | Observed rule | Matches | Cleanup |",
        "| --- | --- | --- | --- | ---: | --- |", *rows, "",
        f"All phases used Wazuh agent `{agent_id}` and a separate file named for the run ID.", "",
        f'- Baseline run ID `{baseline["id"]}`',
        f'- Regression run ID `{regression["id"]}`',
        f'- Restored run ID `{restored["id"]}`', "",
        "Matches counts alerts for rule `100200`. The independent Indexer query found rule `554` "
        "for the regression file's `added` event during that run.", "",
    ])


helpers = runpy.run_path(str(Path(__file__).with_name("verify-live-report.py")))
require = helpers["require"]
read_reports = helpers["read_reports"]
verify_live = helpers["verify_live"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    parser.add_argument("agent_id")
    parser.add_argument("config", type=Path)
    parser.add_argument("--capture-regression", action="store_true", help="Query Indexer before restoring the original XML")
    args = parser.parse_args()
    require(args.agent_id.isascii() and args.agent_id.isdecimal() and int(args.agent_id) > 0,
            "Expected a registered Wazuh agent ID")

    try:
        regression_dir = args.reports / "regression"
        regression = read_reports(regression_dir)
        regression_matches = verify_regression(regression, args.agent_id)
        run_id = regression["id"]
        report_sha256 = hashlib.sha256((regression_dir / f"{run_id}.json").read_bytes()).hexdigest()
        window = indexer_window(regression, args.agent_id)
        evidence_path = args.reports / "regression-evidence.json"
        if args.capture_regression:
            evidence = {"run_id": run_id, "native_json_sha256": report_sha256,
                        "query": window, "alerts": query_added_alerts(args.config, window)}
            verify_indexer_evidence(evidence, run_id, report_sha256, window)
            evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            print(f"Independent Indexer query confirmed rule 554 for agent {args.agent_id} and {window['path']}")
            return

        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        verify_indexer_evidence(evidence, run_id, report_sha256, window)
        summary = verify_sequence(args.reports, regression, args.agent_id, regression_matches)
        (args.reports / "results.md").write_text(summary, encoding="utf-8")
        print(summary, end="")
    except WazuhError as exc:
        raise SystemExit(f"Independent Indexer query failed: {exc}") from None
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise SystemExit(f"Could not validate live regression evidence ({type(exc).__name__})") from None


if __name__ == "__main__":
    main()
