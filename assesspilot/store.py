"""SQLite persistence: assessment runs and a hash-chained, append-only audit log.

Each audit row stores sha256(prev_hash + canonical JSON of the row). Editing or
deleting any past row breaks the chain, which verify_chain() detects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, created REAL, status TEXT, source TEXT,
                backend TEXT, artifacts TEXT);
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run_id TEXT, actor TEXT,
                action TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
        """)

    # ------------------------------------------------------------------ runs
    def new_run(self, source: str, backend: str) -> str:
        run_id = uuid.uuid4().hex[:12]
        with self._lock:
            self.db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)",
                            (run_id, time.time(), "ingested", source, backend, "{}"))
            self.db.commit()
        return run_id

    def get_run(self, run_id: str) -> dict | None:
        row = self.db.execute("SELECT run_id, created, status, source, backend, artifacts FROM runs "
                              "WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        return {"run_id": row[0], "created": row[1], "status": row[2], "source": row[3],
                "backend": row[4], "artifacts": json.loads(row[5])}

    def put_artifact(self, run_id: str, key: str, value, status: str | None = None) -> None:
        with self._lock:
            run = self.get_run(run_id)
            if run is None:
                raise KeyError(run_id)
            arts = run["artifacts"]
            arts[key] = value
            self.db.execute("UPDATE runs SET artifacts=?, status=COALESCE(?, status) WHERE run_id=?",
                            (_canon(arts), status, run_id))
            self.db.commit()

    def set_status(self, run_id: str, status: str) -> None:
        with self._lock:
            self.db.execute("UPDATE runs SET status=? WHERE run_id=?", (status, run_id))
            self.db.commit()

    # ----------------------------------------------------------------- audit
    def audit(self, run_id: str, actor: str, action: str, detail: dict) -> str:
        with self._lock:
            last = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last[0] if last else GENESIS
            ts = time.time()
            body = {"ts": ts, "run_id": run_id, "actor": actor, "action": action, "detail": detail}
            h = sha256(prev + _canon(body))
            self.db.execute("INSERT INTO audit (ts, run_id, actor, action, detail, prev_hash, hash) "
                            "VALUES (?,?,?,?,?,?,?)", (ts, run_id, actor, action, _canon(detail), prev, h))
            self.db.commit()
            return h

    def audit_log(self, run_id: str | None = None) -> list[dict]:
        q = "SELECT seq, ts, run_id, actor, action, detail, prev_hash, hash FROM audit"
        rows = self.db.execute(q + (" WHERE run_id=?" if run_id else "") + " ORDER BY seq",
                               (run_id,) if run_id else ()).fetchall()
        return [{"seq": r[0], "ts": r[1], "run_id": r[2], "actor": r[3], "action": r[4],
                 "detail": json.loads(r[5]), "prev_hash": r[6], "hash": r[7]} for r in rows]

    def verify_chain(self) -> dict:
        prev = GENESIS
        rows = self.db.execute("SELECT seq, ts, run_id, actor, action, detail, prev_hash, hash "
                               "FROM audit ORDER BY seq").fetchall()
        for seq, ts, run_id, actor, action, detail, prev_hash, h in rows:
            body = {"ts": ts, "run_id": run_id, "actor": actor, "action": action,
                    "detail": json.loads(detail)}
            if prev_hash != prev or sha256(prev + _canon(body)) != h:
                return {"ok": False, "broken_at": seq, "entries": len(rows)}
            prev = h
        return {"ok": True, "entries": len(rows), "head": prev}
