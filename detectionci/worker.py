"""Single-worker execution with durable claims and fail-closed crash recovery."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
import threading
import time
from pathlib import Path

from .engine import Engine
from .reporting import sanitize_result


def error_result(summary: str) -> dict:
    return {"verdict": "ERROR", "summary": summary, "checkpoints": [], "assertions": [],
            "evidence": [], "metadata": {"execution_error": True}}


class Worker:
    def __init__(self, store, db_path, config=None, engine=None):
        self.store = store
        self.db_path = Path(getattr(store, "path", db_path)).expanduser().resolve()
        self.target_state_path = Path(str(self.db_path) + ".target-state.json")
        self.engine = engine or Engine(config or {})
        self.stop_event = threading.Event()
        self.active_id = None
        self.active_cancel = None
        self.thread = None
        self.lock_file = None
        self.last_error = None

    def target_status(self):
        if not self.target_state_path.exists():
            return {"blocked": False, "reason": "No unverified live target mutation recorded"}
        try:
            if self.target_state_path.stat().st_size > 8192:
                raise ValueError("Invalid state size")
            data = json.loads(self.target_state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("blocked") is not True:
                raise ValueError("Invalid target state")
            return data
        except (OSError, ValueError):
            return {"blocked": True, "reason": "Target recovery state is unreadable; independently restore the VM before resetting"}

    def _mark_target(self, run_id):
        from .models import utcnow
        data = {"blocked": True, "run_id": run_id, "at": utcnow(),
                "reason": "Live execution started; cleanup has not yet been verified. A crash requires independent VM restoration."}
        self.target_state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp = tempfile.mkstemp(prefix=".dci-target-", dir=self.target_state_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.target_state_path)
            self._sync_directory()
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def _sync_directory(self):
        fd = os.open(self.target_state_path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _clear_target(self):
        self.target_state_path.unlink(missing_ok=True)
        self._sync_directory()

    def clear_target_state(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Recovery cannot race with a worker, even one started in another process.
        with open(str(self.db_path) + ".worker.lock", "a", encoding="utf-8") as guard:
            try:
                fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("Stop the worker before acknowledging target restoration") from exc
            self._clear_target()
            fcntl.flock(guard.fileno(), fcntl.LOCK_UN)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_file = open(str(self.db_path) + ".worker.lock", "a", encoding="utf-8")
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.lock_file.close()
            self.lock_file = None
            raise RuntimeError("Another DetectionCI worker owns this database") from exc
        try:
            self.store.recover_interrupted()
            self.stop_event.clear()
            self.thread = threading.Thread(target=self._loop, name="detectionci-worker", daemon=True)
            self.thread.start()
        except BaseException:
            self.lock_file.close()
            self.lock_file = None
            raise

    def cancel(self, run_id):
        run = self.store.request_cancel(run_id)
        if self.active_id == run_id and self.active_cancel:
            self.active_cancel.set()
        return run

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                run = self.store.claim_next()
                if not run:
                    self.stop_event.wait(.1)
                    continue
                self.active_id = run["id"]
                self.active_cancel = threading.Event()
                watcher_done = threading.Event()

                def watch_cancel():
                    while not watcher_done.wait(.1):
                        try:
                            if self.stop_event.is_set() or self.store.is_cancel_requested(run["id"]):
                                self.active_cancel.set()
                                return
                        except Exception:
                            self.active_cancel.set()
                            return

                watcher = threading.Thread(target=watch_cancel, name="detectionci-cancel", daemon=True)
                watcher.start()
                try:
                    try:
                        if run["mode"] == "live" and self.target_status()["blocked"]:
                            result = error_result("Live target is blocked pending independent VM restoration; inspect target status")
                        else:
                            if run["mode"] == "live":
                                self._mark_target(run["id"])
                            result = self.engine.execute(run, self.active_cancel)
                            if run["mode"] == "live" and result.get("metadata", {}).get("cleanup_verified") is True:
                                self._clear_target()
                    except Exception as exc:
                        # Do not include exception content: transport errors can contain secrets.
                        result = error_result(f"Engine failed ({type(exc).__name__}); inspect local diagnostics.")
                    if not isinstance(result, dict) or result.get("verdict") not in {"PASS", "FAIL", "ERROR", "INCONCLUSIVE", "CANCELLED"}:
                        result = error_result("Engine returned an invalid result")
                    self.store.finish_run(run["id"], sanitize_result(result))
                finally:
                    watcher_done.set()
                    watcher.join(timeout=1)
                    self.active_id = None
                    self.active_cancel = None
            except Exception as exc:
                self.last_error = type(exc).__name__
                self.stop_event.set()

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive() and not self.last_error)

    def stop(self, timeout=20):
        self.stop_event.set()
        if self.active_cancel:
            self.active_cancel.set()
        if self.thread:
            self.thread.join(timeout)
            if self.thread.is_alive():
                raise RuntimeError("Worker is still cleaning up; its database lock remains held")
        if self.lock_file:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()
            self.lock_file = None

    def wait_for(self, run_ids, timeout=330):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            runs = [self.store.get_run(i) for i in run_ids]
            if all(r and r["status"] in {"completed", "cancelled", "interrupted"} for r in runs):
                return runs
            if not self.running:
                raise RuntimeError("Worker stopped before the requested runs completed")
            self.stop_event.wait(.05)
        for run_id in run_ids:
            self.cancel(run_id)
        raise TimeoutError("Run deadline exceeded; cancellation requested")
