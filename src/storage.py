"""SQLite persistence and query helpers for the unified forensic timeline."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional

from src.schema import ForensicEvent


class TimelineStore:
    """Stores normalized events without discarding provenance metadata."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                timestamp_desc TEXT NOT NULL,
                artifact_source TEXT NOT NULL,
                source_file TEXT NOT NULL,
                target_path TEXT NOT NULL,
                message TEXT NOT NULL,
                data_type TEXT NOT NULL,
                parser TEXT NOT NULL,
                user_sid TEXT,
                username TEXT,
                confidence_level TEXT NOT NULL,
                extra_attributes TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact_source);
            CREATE INDEX IF NOT EXISTS idx_events_target ON events(target_path);
            CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
        """)
        self.connection.commit()

    @staticmethod
    def fingerprint(event: ForensicEvent) -> str:
        values = (
            event.timestamp, event.timestamp_desc, event.artifact_source,
            event.source_file, event.target_path, event.message, event.data_type,
            event.parser, event.user_sid or "", event.username or "",
            event.confidence_level,
            json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True),
        )
        return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()

    def insert_events(self, events: Iterable[ForensicEvent]) -> int:
        rows = []
        for event in events:
            rows.append((
                event.event_id, self.fingerprint(event), event.timestamp,
                event.timestamp_desc, event.artifact_source, event.source_file,
                event.target_path, event.message, event.data_type, event.parser,
                event.user_sid, event.username, event.confidence_level,
                json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True),
            ))
        before = self.connection.total_changes
        self.connection.executemany("""
            INSERT OR IGNORE INTO events (
                event_id, fingerprint, timestamp, timestamp_desc, artifact_source,
                source_file, target_path, message, data_type, parser, user_sid,
                username, confidence_level, extra_attributes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        self.connection.commit()
        return self.connection.total_changes - before

    def query(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        artifact: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[ForensicEvent]:
        clauses: List[str] = []
        parameters: List[Any] = []
        if start:
            clauses.append("timestamp >= ?")
            parameters.append(start.isoformat())
        if end:
            clauses.append("timestamp <= ?")
            parameters.append(end.isoformat())
        if artifact:
            clauses.append("lower(artifact_source) = lower(?)")
            parameters.append(artifact)
        if keyword:
            clauses.append("(lower(target_path) LIKE lower(?) OR lower(message) LIKE lower(?))")
            pattern = f"%{keyword}%"
            parameters.extend([pattern, pattern])
        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp, id"
        if limit is not None:
            if limit < 1:
                raise ValueError("limit must be positive")
            sql += " LIMIT ?"
            parameters.append(limit)
        return [self._row_to_event(row) for row in self.connection.execute(sql, parameters)]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> ForensicEvent:
        data = dict(row)
        data.pop("id")
        data.pop("fingerprint")
        data["extra_attributes"] = json.loads(data["extra_attributes"])
        return ForensicEvent(**data)

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "TimelineStore":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()
