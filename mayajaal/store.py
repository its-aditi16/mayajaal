"""SQLite state shared by the app, worker and dashboard. One connection per thread."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .models import Activity, Fix, Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity(ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, payload TEXT NOT NULL, consumed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, created REAL, status TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fixes (id TEXT PRIMARY KEY, incident_id TEXT, status TEXT, created REAL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shadow_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, fix_id TEXT, activity_id INTEGER);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS local_memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, bank TEXT, document_id TEXT, text TEXT, metadata TEXT);
CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source TEXT, text TEXT);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._local = threading.local()
        self._conn().executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # Activity ------------------------------------------------------------------
    def add_activity(self, a: Activity) -> int:
        cur = self._conn().execute(
            "INSERT INTO activity (ts, data) VALUES (?,?)", (a.ts, a.model_dump_json(exclude={"id"})))
        return int(cur.lastrowid)

    @staticmethod
    def _activity(row: sqlite3.Row) -> Activity:
        return Activity.model_validate({**json.loads(row["data"]), "id": row["id"]})

    def get_activity(self, activity_id: int) -> Activity | None:
        row = self._conn().execute("SELECT * FROM activity WHERE id=?", (activity_id,)).fetchone()
        return self._activity(row) if row else None

    def activity_since(self, since: float, limit: int = 20000) -> list[Activity]:
        rows = self._conn().execute(
            "SELECT * FROM activity WHERE ts>=? ORDER BY id LIMIT ?", (since, limit)).fetchall()
        return [self._activity(r) for r in rows]

    def activity_by_ids(self, ids: list[int]) -> list[Activity]:
        out: list[Activity] = []
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            rows = self._conn().execute(
                f"SELECT * FROM activity WHERE id IN ({marks}) ORDER BY id", chunk).fetchall()
            out.extend(self._activity(r) for r in rows)
        return out

    def purge_older_than(self, days: int) -> int:
        cutoff = time.time() - days * 86400
        conn = self._conn()
        count = conn.execute("DELETE FROM activity WHERE ts<?", (cutoff,)).rowcount
        conn.execute("DELETE FROM events WHERE ts<?", (cutoff,))
        conn.execute("DELETE FROM shadow_hits WHERE ts<?", (cutoff,))
        conn.execute("DELETE FROM used_nonces WHERE ts<?", (cutoff,))
        return count

    # Durable event fallback ----------------------------------------------------
    def add_event(self, payload: dict) -> None:
        self._conn().execute("INSERT INTO events (ts, payload) VALUES (?,?)", (time.time(), json.dumps(payload)))

    def take_events(self, limit: int = 50) -> list[dict]:
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            rows = conn.execute(
                "SELECT id, payload FROM events WHERE consumed=0 ORDER BY id LIMIT ?", (limit,)).fetchall()
            conn.executemany("UPDATE events SET consumed=1 WHERE id=?", [(r["id"],) for r in rows])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return [json.loads(r["payload"]) for r in rows]

    # Incidents and fixes -------------------------------------------------------
    def save_incident(self, inc: Incident) -> None:
        self._conn().execute(
            "INSERT INTO incidents (id, created, status, data) VALUES (?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
            (inc.id, inc.created, inc.status, inc.model_dump_json()),
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        row = self._conn().execute("SELECT data FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return Incident.model_validate_json(row["data"]) if row else None

    def incidents(self, statuses: tuple[str, ...] | None = None) -> list[Incident]:
        query, args = "SELECT data FROM incidents", ()
        if statuses:
            query += f" WHERE status IN ({','.join('?' * len(statuses))})"
            args = statuses
        rows = self._conn().execute(query + " ORDER BY created", args).fetchall()
        return [Incident.model_validate_json(r["data"]) for r in rows]

    def save_fix(self, fix: Fix) -> None:
        self._conn().execute(
            "INSERT INTO fixes (id, incident_id, status, created, data) VALUES (?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, data=excluded.data",
            (fix.id, fix.incident_id, fix.status, fix.created, fix.model_dump_json()),
        )

    def get_fix(self, fix_id: str) -> Fix | None:
        row = self._conn().execute("SELECT data FROM fixes WHERE id=?", (fix_id,)).fetchone()
        return Fix.model_validate_json(row["data"]) if row else None

    def fixes(self, statuses: tuple[str, ...] | None = None) -> list[Fix]:
        query, args = "SELECT data FROM fixes", ()
        if statuses:
            query += f" WHERE status IN ({','.join('?' * len(statuses))})"
            args = statuses
        rows = self._conn().execute(query + " ORDER BY created", args).fetchall()
        return [Fix.model_validate_json(r["data"]) for r in rows]

    def add_shadow_hit(self, fix_id: str, activity_id: int) -> None:
        self._conn().execute(
            "INSERT INTO shadow_hits (ts, fix_id, activity_id) VALUES (?,?,?)", (time.time(), fix_id, activity_id))

    def shadow_hit_activity_ids(self, fix_id: str) -> list[int]:
        rows = self._conn().execute("SELECT activity_id FROM shadow_hits WHERE fix_id=?", (fix_id,)).fetchall()
        return [r["activity_id"] for r in rows]

    # Audit, approvals, memory --------------------------------------------------
    def audit(self, actor: str, action: str, target: str, detail: str = "") -> None:
        self._conn().execute(
            "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (time.time(), actor, action, target, detail))

    def audit_rows(self, limit: int = 200) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def use_nonce(self, nonce: str) -> bool:
        """True the first time a nonce is seen: approval links work exactly once."""
        try:
            self._conn().execute("INSERT INTO used_nonces (nonce, ts) VALUES (?,?)", (nonce, time.time()))
            return True
        except sqlite3.IntegrityError:
            return False

    def memory_add(self, bank: str, document_id: str, text: str, metadata: dict) -> None:
        conn = self._conn()
        conn.execute("DELETE FROM local_memory WHERE bank=? AND document_id=?", (bank, document_id))
        conn.execute("INSERT INTO local_memory (ts, bank, document_id, text, metadata) VALUES (?,?,?,?,?)",
                     (time.time(), bank, document_id, text, json.dumps(metadata)))

    def memory_all(self, bank: str) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM local_memory WHERE bank=? ORDER BY id", (bank,)).fetchall()
        return [{**dict(r), "metadata": json.loads(r["metadata"])} for r in rows]

    def add_observation(self, source: str, text: str) -> None:
        self._conn().execute("INSERT INTO observations (ts, source, text) VALUES (?,?,?)", (time.time(), source, text))

    def observations(self, limit: int = 20) -> list[dict]:
        rows = self._conn().execute("SELECT * FROM observations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
