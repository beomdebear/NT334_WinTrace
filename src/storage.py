"""SQLite persistence and query helpers for the unified forensic timeline."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, List, Optional

from src.schema import ForensicEvent


PROVENANCE_FIELDS = ("timestamp_type", "evidence_reference", "validation_status", "case_id")


class TimelineStore:
    """Stores normalized events without discarding provenance metadata."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            self._initialize_schema()

    def _initialize_schema(self) -> None:
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                schema_version TEXT NOT NULL DEFAULT 'v2',
                event_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                timestamp_type TEXT,
                timestamp_desc TEXT NOT NULL,
                artifact_source TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                source_file TEXT NOT NULL,
                target_path TEXT NOT NULL,
                object_path TEXT NOT NULL,
                message TEXT NOT NULL,
                data_type TEXT NOT NULL,
                parser TEXT NOT NULL,
                user_sid TEXT,
                username TEXT,
                confidence_level TEXT NOT NULL,
                evidence_reference TEXT,
                validation_status TEXT,
                case_id TEXT,
                extra_attributes TEXT NOT NULL
            )
        """)
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(events)")
        }
        migrations = {
            "schema_version": "TEXT NOT NULL DEFAULT 'v2'",
            "timestamp_type": "TEXT",
            "artifact_type": "TEXT NOT NULL DEFAULT ''",
            "object_path": "TEXT NOT NULL DEFAULT ''",
            "evidence_reference": "TEXT",
            "validation_status": "TEXT",
            "case_id": "TEXT",
        }
        for name, definition in migrations.items():
            if name not in columns:
                self.connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")
        indexes = {
            "timestamp": "timestamp",
            "artifact": "artifact_source",
            "target": "target_path",
            "username": "username",
            "validation": "validation_status",
        }
        for name, column in indexes.items():
            self.connection.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{name} ON events({column})")

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
        provenance_rows = []
        for event in events:
            fingerprint = self.fingerprint(event)
            provenance = {
                field: getattr(event, field)
                for field in PROVENANCE_FIELDS
            }
            for field, value in provenance.items():
                if value is None:
                    provenance[field] = event.extra_attributes.get(field)
            if any(value is not None for value in provenance.values()):
                provenance_rows.append({"fingerprint": fingerprint, **provenance})

            rows.append((
                "v2", event.event_id, fingerprint, event.timestamp,
                provenance["timestamp_type"],
                event.timestamp_desc, event.artifact_source, event.artifact_source,
                event.source_file, event.target_path, event.target_path,
                event.message, event.data_type, event.parser, event.user_sid,
                event.username, event.confidence_level,
                provenance["evidence_reference"], provenance["validation_status"],
                provenance["case_id"],
                json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True),
            ))
        with self.connection:
            inserted = self.connection.executemany("""
                INSERT OR IGNORE INTO events (
                    schema_version, event_id, fingerprint, timestamp, timestamp_type,
                    timestamp_desc, artifact_source, artifact_type, source_file,
                    target_path, object_path, message, data_type, parser, user_sid,
                    username, confidence_level, evidence_reference, validation_status,
                    case_id, extra_attributes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows).rowcount

            # Re-import can restore provenance that an older writer omitted.
            if inserted < len(rows) and provenance_rows:
                self.connection.executemany("""
                    UPDATE events SET
                        timestamp_type = COALESCE(timestamp_type, :timestamp_type),
                        evidence_reference = COALESCE(evidence_reference, :evidence_reference),
                        validation_status = COALESCE(validation_status, :validation_status),
                        case_id = COALESCE(case_id, :case_id)
                    WHERE fingerprint = :fingerprint AND (case_id IS NULL OR case_id = :case_id)
                      AND ((timestamp_type IS NULL AND :timestamp_type IS NOT NULL)
                        OR (evidence_reference IS NULL AND :evidence_reference IS NOT NULL)
                        OR (validation_status IS NULL AND :validation_status IS NOT NULL)
                        OR (case_id IS NULL AND :case_id IS NOT NULL))
                """, provenance_rows)
        return inserted

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
        data["extra_attributes"] = json.loads(data["extra_attributes"])
        for field in PROVENANCE_FIELDS:
            if data[field] is None:
                data[field] = data["extra_attributes"].get(field)
        return ForensicEvent.from_dict(data)

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "TimelineStore":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()
