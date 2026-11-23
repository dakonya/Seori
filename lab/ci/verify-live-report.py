"""Verify the published report pair and the single live FIM run on this host."""

import argparse
from html import unescape
import json
import os
from pathlib import Path
import re
import uuid

from detectionci.engine import WATCH_ROOT
from detectionci.models import digest, get_field
from detectionci.reporting import export_run, render_html


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def read_reports(directory):
    json_paths = sorted(directory.glob("*.json"))
    html_paths = sorted(directory.glob("*.html"))
    require(len(json_paths) == len(html_paths) == 1, "Expected one JSON and one HTML report")
    json_path = json_paths[0]
    html_path = html_paths[0]

    json_text = json_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")
    document = json.loads(json_text)
    run = document["run"]
    run_id = run["id"]
    require(str(uuid.UUID(run_id)) == run_id, "Expected a canonical run UUID")
    require(json_path.stem == html_path.stem == run_id, "Report filenames do not match the run UUID")
    require(document == export_run(run), "JSON report differs from the native redacted export")
    require(html_text == render_html(run), "HTML report differs from the paired JSON export")

    content = json_text + "\n" + unescape(html_text)
    require(not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", content), "Report contains a private key")
    require(not re.search(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", content),
            "Report contains a JWT")
    for name, value in os.environ.items():
        if len(value) >= 8 and re.fullmatch(r"(?:DCI_|WAZUH_).*?(?:PASSWORD|TOKEN|SECRET)|(?:GH|GITHUB)_TOKEN", name):
            forms = {value, json.dumps(value, ensure_ascii=False)[1:-1]}
            require(all(form not in content for form in forms), "Report contains a configured credential")
    return run


def verify_live(run, agent_id):
    require(re.fullmatch(r"[0-9]{3,}", agent_id) and agent_id != "000", "Expected a registered Wazuh agent ID")
    require((run["scenario_id"], run["mode"], run["status"], run["verdict"]) ==
            ("fim-file-created", "live", "completed", "PASS"), "Expected a completed live fim-file-created PASS")
    path = Path(WATCH_ROOT) / f"{run['id']}.txt"
    result = run["result"]
    metadata = result["metadata"]
    require(result["verdict"] == "PASS" and metadata["fixture_only"] is False
            and metadata["external_systems_contacted"] is True, "Expected actual live evidence")
    require(metadata["target_agent_id"] == agent_id and metadata["run_path"] == str(path),
            "Reported agent ID or path differs from the registered agent and this run UUID")

    checkpoints = {entry["name"]: entry["status"] for entry in result["checkpoints"]}
    require(all(checkpoints.get(name) == "observed" for name in ("action", "source", "indexer", "cleanup")),
            "Required live checkpoints were not observed")
    evidence = result["evidence"]
    require(all(digest(entry["data"]) == entry["sha256"] for entry in evidence), "Evidence SHA-256 did not match")
    expected_fields = {"rule.id": "100200", "syscheck.event": "added", "agent.id": agent_id,
                       "syscheck.path": str(path)}
    alerts = [entry["data"] for entry in evidence if entry["kind"] == "alert"]
    matched = sum(all(get_field(alert, field) == value for field, value in expected_fields.items()) for alert in alerts)
    count = next((item for item in result["assertions"] if item["id"] == "matching-alert-count"), {})
    require(matched > 0 and count.get("actual") == matched and count.get("verdict") == "PASS",
            "Indexer evidence did not confirm rule 100200, event added, registered agent and the run path")

    expected_states = {"remote_prepare": {"exists": False}, "remote_action": {"exists": True},
                       "remote_cleanup": {"clean": True}}
    for kind, fields in expected_states.items():
        items = [entry["data"] for entry in evidence if entry["kind"] == kind]
        expected = {"ok": True, "source_verified": True, **fields}
        require(len(items) == 1 and all(items[0].get(key) is value for key, value in expected.items()),
                f"Missing confirmed {kind} evidence")
    require(metadata["cleanup_verified"] is True, "Report did not confirm cleanup")

    require(path.parent.is_dir(), "Expected the runner's monitored directory to remain present")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise SystemExit("The test file still exists on the runner")

    print(f"Live PASS, rule 100200, event added, agent {agent_id}, {path}, cleanup confirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_directory", type=Path)
    parser.add_argument("agent_id")
    parser.add_argument("--artifacts-only", action="store_true", help="Check the export pair for publication")
    args = parser.parse_args()
    try:
        run = read_reports(args.report_directory)
        if not args.artifacts_only:
            verify_live(run, args.agent_id)
    except (KeyError, TypeError, ValueError, OSError):
        raise SystemExit("Could not verify the report and runner file state") from None


if __name__ == "__main__":
    main()
