"""Scenario loading with API-safe identifiers and no implicit recursion."""
from __future__ import annotations

from pathlib import Path
import sys

from .models import load_scenario

_SOURCE_SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"
DEFAULT_SCENARIOS = _SOURCE_SCENARIOS if _SOURCE_SCENARIOS.is_dir() else Path(sys.prefix) / "share" / "detectionci" / "scenarios"


def load_catalog(directory: str | Path | None = None) -> dict[str, dict]:
    root = Path(directory) if directory else DEFAULT_SCENARIOS
    if not root.is_dir():
        raise ValueError(f"Scenario directory does not exist: {root}")
    paths = sorted(root.glob("*.json"))
    if len(paths) > 200:
        raise ValueError("At most 200 scenarios can be loaded")
    result = {}
    for path in paths:
        scenario = load_scenario(path)
        if scenario["id"] in result:
            raise ValueError(f"Duplicate scenario ID: {scenario['id']}")
        result[scenario["id"]] = scenario
    return result


def resolve_scenario(value: str, catalog: dict[str, dict]) -> dict:
    if value in catalog:
        return catalog[value]
    path = Path(value)
    if path.is_file():
        return load_scenario(path)
    raise ValueError(f"Unknown scenario: {value}")
