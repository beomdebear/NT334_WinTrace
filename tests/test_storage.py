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
        },
    )
    with TimelineStore(str(database)) as store:
        assert store.insert_events([event]) == 1
        row = store.connection.execute(
            "SELECT schema_version, timestamp_type, artifact_type, object_path, "
            "evidence_reference, validation_status FROM events"
        ).fetchone()

    assert tuple(row) == (
        "v2", "ShellItem_FolderAccessed", "ShellBags", r"E:\Secret Project Data",
        "Deduplicated.csv:L10", "verified",
    )
