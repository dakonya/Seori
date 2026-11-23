"""Self-contained, escaped reports and explicitly scoped comparisons."""
from __future__ import annotations

import copy
import hashlib
import html
import json
import re
from pathlib import Path

from . import __version__

SENSITIVE = re.compile(r"password|passwd|token|secret|authorization|cookie|private.?key|credential", re.I)
BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/_.=\-]+")


def redact(value, key: str = "", depth: int = 0):
    if depth > 24:
        return "[depth limit]"
    if SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k), depth + 1) for k, v in list(value.items())[:1000]}
    if isinstance(value, list):
        return [redact(v, depth=depth + 1) for v in value[:1000]]
    if isinstance(value, str):
        value = BEARER.sub(lambda m: m.group(1) + " [REDACTED]", value)
        if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
            return "[REDACTED PRIVATE KEY]"
        return value[:16384] + ("… [truncated]" if len(value) > 16384 else "")
    return value


def sanitize_result(result: dict) -> dict:
    clean = redact(result)
    for item in clean.get("evidence", []):
        if isinstance(item, dict) and "data" in item:
            raw = json.dumps(item["data"], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            item["sha256"] = hashlib.sha256(raw).hexdigest()
            item["hash_scope"] = "stored redacted evidence data"
    return clean


def export_run(run: dict) -> dict:
    return {"report_schema": "detectionci.run.v1", "tool_version": __version__, "run": redact(run),
            "notice": "Fixture validates local logic; replay validates Wazuh rules on supplied logs; live validates only observed stages. Redaction is best effort; review before sharing."}


def render_html(run: dict) -> str:
    document = export_run(run)
    r = document["run"]
    result = r.get("result") or {}
    esc = lambda value: html.escape(str(value), quote=True)
    chunks = ["<!doctype html><html lang='en'><meta charset='utf-8'>",
              "<meta name='viewport' content='width=device-width,initial-scale=1'>",
              "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'\">",
              "<title>Seori (서리) · validation report</title><style>body{font:15px system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 24px;color:#172333;background:#f5f7fa}h1{letter-spacing:-1px}table{width:100%;border-collapse:collapse;background:white;margin:16px 0}td,th{text-align:left;padding:10px;border:1px solid #dce1e8}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#e8edf3;padding:16px;border-radius:8px}small{color:#536174}.notice{border-left:4px solid #ae7100;padding:14px;background:#fff4d9}</style>",
              "<h1>Seori <span lang='ko'>서리</span> · validation report</h1>",
              f"<p><strong>{esc(r.get('scenario_id',''))}</strong> · {esc(r.get('mode',''))} · <strong>{esc(r.get('verdict') or r.get('status',''))}</strong></p>",
              f"<p class='notice'>{esc(document['notice'])}</p>",
              f"<p>{esc(result.get('summary','This run has not produced a terminal result.'))}</p>",
              f"<small>Run {esc(r.get('id',''))} · created {esc(r.get('created_at',''))}</small>"]
    for title, key, fields in [("Checkpoints", "checkpoints", ["name", "status", "detail"]),
                               ("Assertions", "assertions", ["id", "verdict", "message"])]:
        chunks.append(f"<h2>{title}</h2><table><tr>" + "".join(f"<th>{esc(f)}</th>" for f in fields) + "</tr>")
        for item in result.get(key, []):
            chunks.append("<tr>" + "".join(f"<td>{esc(item.get(f,''))}</td>" for f in fields) + "</tr>")
        chunks.append("</table>")
    chunks.extend(["<h2>Evidence and metadata</h2><pre>", esc(json.dumps(document, indent=2, ensure_ascii=False)), "</pre></html>"])
    return "".join(chunks)


def write_reports(run: dict, directory: str | Path) -> list[str]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    # Run IDs are generated internally; never use scenario titles as paths.
    run_id = str(run["id"])
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", run_id):
        raise ValueError("Unsafe report identifier")
    paths = [out / (run_id + ".json"), out / (run_id + ".html")]
    paths[0].write_text(json.dumps(export_run(run), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    paths[1].write_text(render_html(run), encoding="utf-8")
    return [str(p) for p in paths]


def compare_runs(baseline: dict, current_runs: list[dict]) -> dict:
    previous = baseline.get("runs", [])
    if isinstance(previous, dict):
        previous = list(previous.values())
    old = {r["scenario_id"]: r for r in previous}
    new = {}
    for run in current_runs:
        key = run["scenario_id"]
        if key in new:
            raise ValueError("Comparison requires one current run per scenario")
        if run["mode"] != baseline.get("mode", previous[0]["mode"] if previous else run["mode"]):
            raise ValueError("Cannot compare runs from different validation modes")
        new[key] = run
    if not new:
        raise ValueError("Select at least one current run")
    rows, warnings = [], []
    all_pass, comparable = True, True
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        av, bv = a.get("verdict") if a else None, b.get("verdict") if b else None
        change = "new" if not a else "missing" if not b else "unchanged"
        if a and b and av != bv:
            change = "improvement" if bv == "PASS" else "regression" if av == "PASS" else "changed"
        if not b or bv != "PASS":
            all_pass = False
        if a and b:
            # Scenario changes can change the test oracle: make non-comparability visible.
            if a.get("scenario") != b.get("scenario"):
                comparable = False
                warnings.append(f"Scenario definition changed: {key}")
            old_config = (a.get("result") or {}).get("metadata", {}).get("operator_config_sha256")
            new_config = (b.get("result") or {}).get("metadata", {}).get("operator_config_sha256")
            if old_config and new_config and old_config != new_config:
                warnings.append(f"Operator configuration changed: {key}; this hash does not attest loaded SIEM rules")
            if b.get("status") not in {"completed", "cancelled", "interrupted"}:
                all_pass = False
                warnings.append(f"Current run is not terminal: {key}")
        rows.append({"scenario_id": key, "baseline_verdict": av, "current_verdict": bv,
                     "change": change, "baseline_run_id": a["id"] if a else None,
                     "current_run_id": b["id"] if b else None})
    verdict = "FAIL" if not all_pass else "INCONCLUSIVE" if not comparable else "PASS"
    return {"baseline": baseline["name"], "verdict": verdict,
            "summary": f"{sum(r['change']=='regression' for r in rows)} regressions; {sum(r['change']=='missing' for r in rows)} missing scenarios; {len(warnings)} comparison warnings.",
            "rows": rows, "warnings": warnings,
            "scope": "Comparison of these explicit test runs; not a production coverage estimate."}
