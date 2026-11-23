"""Explicit, bounded configuration loading. Secrets are never API responses."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

ENV_REF = re.compile(r"^\$\{(DCI_[A-Z0-9_]+)\}$")


def load_config(path: str | Path | None = None) -> dict:
    if path is None:
        return {}
    p = Path(path).expanduser()
    if p.stat().st_size > 65536:
        raise ValueError("Configuration exceeds 64 KiB")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"wazuh", "live"}:
        raise ValueError("Configuration must contain only wazuh and live objects")

    def expand(value):
        if isinstance(value, dict):
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        if isinstance(value, str):
            match = ENV_REF.fullmatch(value)
            if match:
                key = match.group(1)
                if not os.environ.get(key):
                    raise ValueError(f"Required environment variable {key} is not set")
                return os.environ[key]
            if "${" in value:
                raise ValueError("Only complete ${DCI_VARIABLE} references are supported")
        return value

    data = expand(data)
    if any(not isinstance(v, dict) for v in data.values()):
        raise ValueError("wazuh and live configuration must be objects")
    return data
