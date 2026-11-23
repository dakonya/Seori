#!/usr/bin/env python3
"""Prepare official pinned Wazuh Docker files; never deploy or change host sysctls."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

VERSION = "v4.14.10"
REPOSITORY = "https://github.com/wazuh/wazuh-docker.git"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parent / "vendor" / "wazuh-docker")
    parser.add_argument("--fetch", action="store_true", help="download the official pinned repository; default prints the plan only")
    args = parser.parse_args()
    destination = args.destination.expanduser().resolve()
    command = ["git", "clone", "--depth", "1", "--branch", VERSION, REPOSITORY, str(destination)]
    if not args.fetch:
        print(json.dumps({"mode": "plan", "repository": REPOSITORY, "version": VERSION, "command": command,
                          "deploys_services": False, "changes_host_configuration": False}, indent=2))
        return 0
    if destination.exists():
        parser.error("destination already exists; use a new directory rather than overwriting an installation")
    if shutil.which("git") is None:
        parser.error("git is required to fetch the official files")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(command, check=True, timeout=180)
        revision = subprocess.run(["git", "-C", str(destination), "rev-parse", "HEAD"],
                                  check=True, capture_output=True, text=True, timeout=15).stdout.strip()
        single = destination / "single-node"
        required = [single / "docker-compose.yml", single / "generate-indexer-certs.yml"]
        if not all(path.is_file() for path in required):
            raise RuntimeError("the pinned checkout does not contain the expected official single-node files")
        source = Path(__file__).resolve().parent / "detectionci_fim.xml"
        shutil.copyfile(source, single / "config" / "detectionci_fim.xml")
        overlay = ("services:\n  wazuh.manager:\n    volumes:\n"
                   "      - ./config/detectionci_fim.xml:/var/ossec/etc/rules/detectionci_fim.xml:ro\n")
        (single / "compose.detectionci.yml").write_text(overlay, encoding="utf-8")
        record = {"repository": REPOSITORY, "version": VERSION, "commit": revision,
                  "prepared_directory": str(single), "services_started": False,
                  "configuration_note": "Review credentials, certificates and published ports before deployment."}
        (destination / "detectionci-preparation.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(record, indent=2))
        return 0
    except (subprocess.SubprocessError, OSError, RuntimeError) as exc:
        print(f"Preparation failed: {exc}")
        print("No services were started. Inspect the destination before retrying with a new directory.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
