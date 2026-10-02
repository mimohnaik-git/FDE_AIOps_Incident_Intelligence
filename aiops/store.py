"""SQLite stores only sanitized contracts and explicit event/incident relationships."""

import sqlite3
import threading
from pathlib import Path

from aiops.models import Incident, NormalizedEvent, RunState, Status


class Store:
    def __init__(self, path: str | Path = "incidents.sqlite3"):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, timestamp TEXT NOT NULL,
                incident_id TEXT REFERENCES incidents(id), duplicate INTEGER NOT NULL,
                document TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_fingerprint ON events(fingerprint);
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, document TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    def incidents(self) -> list[Incident]:
        with self.lock:
            return [
                Incident.model_validate_json(row[0])
                for row in self.db.execute("SELECT document FROM incidents ORDER BY id")
            ]

    def get(self, incident_id: str) -> Incident | None:
        with self.lock:
            row = self.db.execute(
                "SELECT document FROM incidents WHERE id=?", (incident_id,)
            ).fetchone()
            return Incident.model_validate_json(row[0]) if row else None

    def save_incident(self, incident: Incident):
        self.db.execute(
            "INSERT INTO incidents VALUES (?, ?) ON CONFLICT(id) DO UPDATE "
            "SET document=excluded.document",
            (incident.incident_id, incident.model_dump_json()),
        )

    def save_event(self, event: NormalizedEvent, incident_id: str | None, duplicate: bool):
        self.db.execute(
            "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.fingerprint.value,
                event.timestamp.isoformat(),
                incident_id,
                int(duplicate),
                event.model_dump_json(),
            ),
        )

    def event_exists(self, event_id: str) -> bool:
        return (
            self.db.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone() is not None
        )

    def events(self, incident_id: str) -> list[NormalizedEvent]:
        with self.lock:
            return [
                NormalizedEvent.model_validate_json(row[0])
                for row in self.db.execute(
                    "SELECT document FROM events WHERE incident_id=? ORDER BY timestamp",
                    (incident_id,),
                )
            ]

    def save_run(self, run: RunState):
        self.db.execute("INSERT INTO runs VALUES (?, ?)", (run.run_id, run.model_dump_json()))

    def runs(self) -> list[RunState]:
        with self.lock:
            return [
                RunState.model_validate_json(row[0])
                for row in self.db.execute(
                    "SELECT document FROM runs ORDER BY rowid DESC LIMIT 100"
                )
            ]

    def transition(self, incident_id: str, status: Status) -> Incident | None:
        with self.lock, self.db:
            incident = self.get(incident_id)
            if incident is None:
                return None
            allowed = {
                Status.OPEN: {Status.INVESTIGATING, Status.RESOLVED, Status.SUPPRESSED},
                Status.INVESTIGATING: {Status.RESOLVED, Status.SUPPRESSED},
                Status.RESOLVED: {Status.OPEN},
                Status.SUPPRESSED: {Status.OPEN},
            }
            if status != incident.status and status not in allowed[incident.status]:
                raise ValueError("invalid lifecycle transition")
            incident.status = status
            self.save_incident(incident)
            return incident
