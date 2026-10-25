"""
Unit tests for WinTrace Forensic Event Schema and Path Normalization.
"""

import pytest
from datetime import datetime, timezone
from src.schema import (
    ForensicEvent,
    CorrelationFinding,
    normalize_windows_path,
    parse_iso_utc
)


def test_normalize_windows_path():
    assert normalize_windows_path("C:/Users/Alice/Documents/file.txt") == "C:\\Users\\Alice\\Documents\\file.txt"
    assert normalize_windows_path("C:\\\\Windows\\\\System32\\\\cmd.exe") == "C:\\Windows\\System32\\cmd.exe"
    assert normalize_windows_path(' "C:\\Folder\\Data" ') == "C:\\Folder\\Data"
    assert normalize_windows_path(None) == ""


def test_parse_iso_utc():
    dt = parse_iso_utc("2026-10-25T02:14:00+00:00")
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 25
    assert dt.hour == 2
    assert dt.minute == 14
    assert dt.tzinfo == timezone.utc

    # Test invalid string raises ValueError
    with pytest.raises(ValueError):
        parse_iso_utc("invalid-timestamp")


def test_forensic_event_valid_instantiation():
    event = ForensicEvent(
        event_id="EVT-001",
        timestamp="2026-10-25T02:14:00+00:00",
        timestamp_desc="Last Time Executed",
        artifact_source="Prefetch",
        source_file="C:/Windows/Prefetch/WINWORD.EXE-5C48A1B2.pf",
        target_path="C:/Program Files/Office/WINWORD.EXE",
        message="Executed WINWORD.EXE",
        user_sid="S-1-5-21-3928172839-1002",
        username="Alice",
        confidence_level="HIGH"
    )

    assert event.event_id == "EVT-001"
    assert event.target_path == "C:\\Program Files\\Office\\WINWORD.EXE"
    assert event.confidence_level == "HIGH"
    assert isinstance(event.dt, datetime)


def test_forensic_event_serialization():
    event = ForensicEvent(
        event_id="EVT-002",
        timestamp="2026-10-25T02:10:00+00:00",
        timestamp_desc="BagMRU Last Interacted",
        artifact_source="ShellBags",
        source_file="C:\\Users\\Alice\\UsrClass.dat",
        target_path="C:\\Users\\Alice\\Documents\\Project",
        message="Navigated to Project"
    )

    data = event.to_dict()
    assert data["event_id"] == "EVT-002"
    assert data["artifact_source"] == "ShellBags"

    restored = ForensicEvent.from_dict(data)
    assert restored.event_id == event.event_id
    assert restored.target_path == event.target_path


def test_invalid_event_timestamp():
    with pytest.raises(ValueError):
        ForensicEvent(
            event_id="EVT-ERR",
            timestamp="not-a-timestamp",
            timestamp_desc="Desc",
            artifact_source="Prefetch",
            source_file="file.pf",
            target_path="cmd.exe",
            message="Error event"
        )
