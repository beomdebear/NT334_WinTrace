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
