import sqlite3

import pytest

from src.schema import ForensicEvent
from src.storage import TimelineStore


def make_event(event_id="E01", timestamp="2026-10-25T02:10:00+00:00"):
    return ForensicEvent(
        event_id=event_id,
        timestamp=timestamp,
        timestamp_desc="Event Generated Time",
        artifact_source="EVTX",
        source_file="Security.evtx",
        target_path=r"C:\Users\Alice\report.docx",
        message="Object access",
        parser="winevtx",
        username="Alice",
        extra_attributes={"evidence_reference": "Security.evtx:1"},
    )


def test_storage_deduplicates_and_preserves_provenance(tmp_path):
    database = tmp_path / "timeline.db"
    with TimelineStore(str(database)) as store:
        assert store.insert_events([make_event(), make_event("E02")]) == 1
        assert store.count() == 1
        events = store.query(artifact="evtx", keyword="report")

    assert len(events) == 1
    assert events[0].extra_attributes["evidence_reference"] == "Security.evtx:1"


def test_storage_rejects_non_positive_limit(tmp_path):
    with TimelineStore(str(tmp_path / "timeline.db")) as store:
        with pytest.raises(ValueError, match="limit"):
            store.query(limit=0)


def test_storage_exposes_schema_v2_columns(tmp_path):
    database = tmp_path / "timeline.db"
    event = ForensicEvent(
        event_id="CASE01-SB0001",
        timestamp="2015-03-22T14:52:22+00:00",
        timestamp_desc="ShellItem Target Accessed",
        artifact_source="ShellBags",
        source_file="UsrClass.dat",
        target_path=r"E:\Secret Project Data",
        message="Shell item accessed",
        data_type="windows:registry:bagmru",
        parser="sbecmd",
        username="informant",
        confidence_level="LOW",
        extra_attributes={
            "timestamp_type": "ShellItem_FolderAccessed",
            "evidence_reference": "Deduplicated.csv:L10",
            "validation_status": "verified",
            "case_id": "CASE01",
        },
    )
    with TimelineStore(str(database)) as store:
        assert store.insert_events([event]) == 1
        row = store.connection.execute(
            "SELECT schema_version, timestamp_type, artifact_type, object_path, "
            "evidence_reference, validation_status, case_id FROM events"
        ).fetchone()
        restored, = store.query()

    assert tuple(row) == (
        "v2", "ShellItem_FolderAccessed", "ShellBags", r"E:\Secret Project Data",
        "Deduplicated.csv:L10", "verified", "CASE01",
    )
    for field, expected in event.extra_attributes.items():
        assert getattr(restored, field) == expected


@pytest.mark.parametrize(("field", "value", "legacy_value"), [
    ("timestamp_type", "ShellBag_LastInteracted", "Generic"),
    ("evidence_reference", "Deduplicated.csv:L59", "Legacy.csv:L1"),
    ("validation_status", "verified", "unverified"),
    ("case_id", "CASE01", "LEGACY"),
])
def test_storage_round_trip_prefers_direct_schema_v2_fields(tmp_path, field, value, legacy_value):
    database = tmp_path / "timeline.db"
    event = make_event()
    setattr(event, field, value)
    event.extra_attributes[field] = legacy_value

    with TimelineStore(str(database)) as store:
        assert store.insert_events([event]) == 1

    with TimelineStore(str(database)) as store:
        restored, = store.query()
        assert getattr(restored, field) == value
        assert restored.extra_attributes[field] == legacy_value


@pytest.mark.parametrize("legacy_columns", [
    ("case_id",),
    ("case_id", "schema_version", "timestamp_type", "artifact_type",
     "object_path", "evidence_reference", "validation_status"),
])
def test_storage_migrates_legacy_database_and_recovers_provenance_on_reimport(tmp_path, legacy_columns):
    database = tmp_path / "timeline.db"
    event = make_event()
    event.extra_attributes = {"case_id": "CASE01"}
    with TimelineStore(str(database)) as store:
        assert store.insert_events([event]) == 1

    connection = sqlite3.connect(database)
    try:
        with connection:
            if "validation_status" in legacy_columns:
                connection.execute("DROP INDEX idx_events_validation")
            for column in legacy_columns:
                connection.execute(f"ALTER TABLE events DROP COLUMN {column}")
    finally:
        connection.close()

    expected = {
        "timestamp_type": "ShellBag_LastInteracted",
        "evidence_reference": "Deduplicated.csv:L59",
        "validation_status": "verified",
        "case_id": "CASE01",
    }
    for field, value in expected.items():
        setattr(event, field, value)

    with TimelineStore(str(database)) as store:
        original, = store.query()
        assert original.event_id == event.event_id
        assert original.case_id == "CASE01"
        assert store.insert_events([event]) == 0
        assert store.count() == 1

    with TimelineStore(str(database)) as store:
        restored, = store.query()
        for field, value in expected.items():
            assert getattr(restored, field) == value
