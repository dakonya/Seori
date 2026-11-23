"""SQLite-backed run state machine and immutable baseline snapshots."""

from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import VERDICTS, canonical_json, digest, utcnow, validate_scenario

_TERMINAL = {"completed", "interrupted", "cancelled"}
_MODES = {"fixture", "replay", "live"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._keeper: sqlite3.Connection | None = None
        self._uri = self.path == ":memory:"
        if self._uri:
            self._connection_path = f"file:detectionci-{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._keeper = self._connect()
        else:
            target = Path(path).expanduser().absolute()
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError("database path must not be a symbolic link")
            existed = target.exists()
            self._connection_path = str(target)
            self.path = str(target)
            if not existed:
                try:
                    descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(descriptor)
                except FileExistsError:
                    if target.is_symlink():
                        raise ValueError("database path must not be a symbolic link")
                    existed = True
        with self._connection() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise ValueError("database schema is newer than this DetectionCI version")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    scenario_version TEXT NOT NULL,
                    scenario TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('fixture','replay','live')),
                    status TEXT NOT NULL CHECK(status IN ('queued','running','cancelling','completed','interrupted','cancelled')),
                    verdict TEXT,
                    result TEXT,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    suite_id TEXT
                );
                CREATE INDEX IF NOT EXISTS runs_status_created ON runs(status, created_at, id);
                CREATE TABLE IF NOT EXISTS baselines (
                    name TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    snapshot TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transitions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    at TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    note TEXT NOT NULL
                );
                PRAGMA user_version = 1;
            """)
        if not self._uri and not existed:
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._connection_path, timeout=10, isolation_level=None, uri=self._uri)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        if not self._uri:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def close(self) -> None:
        if self._keeper is not None:
            self._keeper.close()
            self._keeper = None

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        data = dict(row)
        data["scenario"] = json.loads(data["scenario"])
        data["result"] = json.loads(data["result"]) if data["result"] is not None else None
        data["cancel_requested"] = bool(data["cancel_requested"])
        return data

    @staticmethod
    def _transition(connection: sqlite3.Connection, run_id: str, old: str | None, new: str, note: str) -> None:
        connection.execute("INSERT INTO transitions(run_id,at,old_status,new_status,note) VALUES(?,?,?,?,?)",
                           (run_id, utcnow(), old, new, note))

    @staticmethod
    def _require(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"run not found: {run_id}")
        return row

    def create_run(self, scenario: dict, mode: str, suite_id: str | None = None) -> dict:
        scenario = validate_scenario(scenario)
        if not isinstance(mode, str) or mode not in _MODES:
            raise ValueError("mode must be fixture, replay or live")
        if suite_id is not None and (not isinstance(suite_id, str) or len(suite_id) > 128 or "\x00" in suite_id):
            raise ValueError("suite_id must be a string of at most 128 characters")
        run_id, created = str(uuid.uuid4()), utcnow()
        with self._connection(write=True) as connection:
            connection.execute("INSERT INTO runs(id,scenario_id,scenario_version,scenario,mode,status,created_at,suite_id) VALUES(?,?,?,?,?,'queued',?,?)",
                               (run_id, scenario["id"], scenario["version"], canonical_json(scenario), mode, created, suite_id))
            self._transition(connection, run_id, None, "queued", "created")
            return self._row(self._require(connection, run_id))

    def claim_next(self) -> dict | None:
        with self._connection(write=True) as connection:
            row = connection.execute("SELECT * FROM runs WHERE status='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if row is None:
                return None
            connection.execute("UPDATE runs SET status='running',started_at=? WHERE id=? AND status='queued'", (utcnow(), row["id"]))
            self._transition(connection, row["id"], "queued", "running", "claimed")
            return self._row(self._require(connection, row["id"]))

    def get_run(self, run_id: str) -> dict | None:
        with self._connection() as connection:
            return self._row(connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def list_runs(self, limit: int = 50, offset: int = 0) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be non-negative")
        with self._connection() as connection:
            return [self._row(row) for row in connection.execute("SELECT * FROM runs ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", (limit, offset))]

    def finish_run(self, run_id: str, result: dict) -> dict:
        if not isinstance(result, dict) or not isinstance(result.get("verdict"), str) or result["verdict"] not in VERDICTS:
            raise ValueError("result must contain a valid verdict")
        result = copy.deepcopy(result)
        for key in ("checkpoints", "assertions", "evidence"):
            if key not in result:
                result[key] = []
            if not isinstance(result[key], list):
                raise ValueError(f"result.{key} must be a list")
        result.setdefault("summary", "")
        result.setdefault("metadata", {})
        if not isinstance(result["metadata"], dict) or not isinstance(result["summary"], str):
            raise ValueError("result metadata/summary have invalid types")
        if len(canonical_json(result).encode()) > 8_388_608:
            raise ValueError("result exceeds 8 MiB")
        with self._connection(write=True) as connection:
            row = self._require(connection, run_id)
            if row["status"] not in {"running", "cancelling"}:
                raise ValueError(f"cannot finish run in {row['status']} state")
            if row["cancel_requested"]:
                result["metadata"]["execution_verdict_before_cancel"] = result["verdict"]
                result["verdict"] = "CANCELLED"
                result["summary"] = "Run cancelled; " + result["summary"]
            status = "cancelled" if result["verdict"] == "CANCELLED" else "completed"
            connection.execute("UPDATE runs SET status=?,verdict=?,result=?,finished_at=? WHERE id=?",
                               (status, result["verdict"], canonical_json(result), utcnow(), run_id))
            self._transition(connection, run_id, row["status"], status, result["verdict"])
            return self._row(self._require(connection, run_id))

    def request_cancel(self, run_id: str) -> dict:
        with self._connection(write=True) as connection:
            row = self._require(connection, run_id)
            if row["status"] in _TERMINAL:
                return self._row(row)
            if row["status"] == "queued":
                result = {"verdict": "CANCELLED", "summary": "Cancelled before execution", "checkpoints": [], "assertions": [], "evidence": [], "metadata": {"mode": row["mode"], "action_executed": False}}
                connection.execute("UPDATE runs SET cancel_requested=1,status='cancelled',verdict='CANCELLED',result=?,finished_at=? WHERE id=?",
                                   (canonical_json(result), utcnow(), run_id))
                self._transition(connection, run_id, "queued", "cancelled", "cancel requested")
            elif row["status"] == "running":
                connection.execute("UPDATE runs SET cancel_requested=1,status='cancelling' WHERE id=?", (run_id,))
                self._transition(connection, run_id, "running", "cancelling", "cancel requested")
            return self._row(self._require(connection, run_id))

    def is_cancel_requested(self, run_id: str) -> bool:
        with self._connection() as connection:
            return bool(self._require(connection, run_id)["cancel_requested"])

    def recover_interrupted(self) -> int:
        with self._connection(write=True) as connection:
            rows = connection.execute("SELECT * FROM runs WHERE status IN ('running','cancelling')").fetchall()
            for row in rows:
                result = {"verdict": "ERROR", "summary": "Controller stopped during execution; target cleanup must be verified before live reuse", "checkpoints": [], "assertions": [], "evidence": [], "metadata": {"mode": row["mode"], "recovered_after_restart": True, "cleanup_verified": False}}
                connection.execute("UPDATE runs SET status='interrupted',verdict='ERROR',result=?,finished_at=? WHERE id=?",
                                   (canonical_json(result), utcnow(), row["id"]))
                self._transition(connection, row["id"], row["status"], "interrupted", "startup recovery; no automatic retry")
            return len(rows)

    def save_baseline(self, name: str, run_ids: list[str]) -> dict:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("baseline name must be 1..64 letters, digits, dot, underscore or hyphen")
        if not isinstance(run_ids, list) or not 1 <= len(run_ids) <= 100 or any(not isinstance(i, str) for i in run_ids):
            raise ValueError("baseline needs between 1 and 100 run IDs")
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("baseline run IDs must be unique")
        with self._connection(write=True) as connection:
            if connection.execute("SELECT 1 FROM baselines WHERE name=?", (name,)).fetchone():
                raise ValueError("baseline name already exists; baselines are immutable")
            runs = [self._row(self._require(connection, run_id)) for run_id in run_ids]
            if any(run["status"] not in _TERMINAL for run in runs):
                raise ValueError("baseline requires terminal runs")
            if len({run["mode"] for run in runs}) != 1:
                raise ValueError("baseline must not mix validation modes")
            if len({run["scenario_id"] for run in runs}) != len(runs):
                raise ValueError("baseline requires one run per scenario")
            for run in runs:
                run["scenario_digest"] = digest(run["scenario"])
            snapshot = {"name": name, "created_at": utcnow(), "run_ids": list(run_ids), "mode": runs[0]["mode"], "runs": runs}
            connection.execute("INSERT INTO baselines(name,created_at,snapshot) VALUES(?,?,?)", (name, snapshot["created_at"], canonical_json(snapshot)))
            return snapshot

    def get_baseline(self, name: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute("SELECT snapshot FROM baselines WHERE name=?", (name,)).fetchone()
            return json.loads(row["snapshot"]) if row else None

    def list_baselines(self) -> list[dict]:
        with self._connection() as connection:
            return [json.loads(row["snapshot"]) for row in connection.execute("SELECT snapshot FROM baselines ORDER BY created_at DESC,name")]
