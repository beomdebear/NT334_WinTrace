"""
Unit tests for WinTrace Correlation Rules Engine (R01 - R05).
"""

import pytest
from src.schema import ForensicEvent
from src.correlation import (
    path_relation,
    is_program_file_pair,
    CorrelationEngine
)


def test_path_relation():
    # Same path
    assert path_relation("C:\\Users\\Alice\\doc.docx", "c:/users/alice/doc.docx") == "Same path"

    # Parent-child path
    assert path_relation("C:\\Users\\Alice\\Documents", "C:\\Users\\Alice\\Documents\\Project\\file.txt") == "Parent-child path"
    assert path_relation("C:\\Users\\Alice\\Documents\\Project\\file.txt", "C:\\Users\\Alice\\Documents") == "Parent-child path"

    # Unrelated paths
    assert path_relation("C:\\Windows\\System32", "C:\\Users\\Alice\\Documents") is None


def test_is_program_file_pair():
    prog_event = ForensicEvent(
        event_id="E01",
        timestamp="2026-10-25T02:14:00+00:00",
        timestamp_desc="Last Time Executed",
        artifact_source="Prefetch",
        source_file="WINWORD.EXE-5C48A1B2.pf",
        target_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        message="Executed WINWORD.EXE"
    )

    doc_event = ForensicEvent(
        event_id="E02",
        timestamp="2026-10-25T02:12:00+00:00",
        timestamp_desc="LNK Target Accessed",
        artifact_source="LNK",
        source_file="report.docx.lnk",
        target_path="C:\\Users\\Alice\\Documents\\report.docx",
        message="Shortcut accessed"
    )

    assert is_program_file_pair(prog_event, doc_event) is True


def test_correlation_engine_rules():
    engine = CorrelationEngine(window_minutes=5.0)

    events = [
        ForensicEvent(
            event_id="E01",
            timestamp="2026-10-25T02:10:00+00:00",
            timestamp_desc="BagMRU Last Interacted",
            artifact_source="ShellBags",
            source_file="UsrClass.dat",
            target_path="C:\\Users\\Alice\\Documents\\Project",
            message="Navigated to Project folder",
            username="Alice"
        ),
        ForensicEvent(
            event_id="E02",
            timestamp="2026-10-25T02:12:00+00:00",
            timestamp_desc="LNK Target File Accessed",
            artifact_source="LNK",
            source_file="confidential.docx.lnk",
            target_path="C:\\Users\\Alice\\Documents\\Project\\confidential.docx",
            message="Shortcut accessed",
            username="Alice"
        ),
        ForensicEvent(
            event_id="E03",
            timestamp="2026-10-25T02:18:00+00:00",
            timestamp_desc="Deletion Timestamp",
            artifact_source="RecycleBin",
            source_file="$I39F1AA.docx",
            target_path="C:\\Users\\Alice\\Documents\\Project\\confidential.docx",
            message="Moved to Recycle Bin",
            username="Alice"
        )
    ]

    findings = engine.correlate(events)
    assert len(findings) >= 2

    # Verify E01 and E02 correlation
    f_folder_file = next((f for f in findings if f.event_a_id == "E01" and f.event_b_id == "E02"), None)
    assert f_folder_file is not None
    assert "R01" in f_folder_file.matched_rules
    assert "R02" in f_folder_file.matched_rules
    assert "R03" in f_folder_file.matched_rules
    assert f_folder_file.confidence_level == "HIGH"

    # Verify E02 and E03 deletion context correlation
    f_deletion = next((f for f in findings if f.event_a_id == "E02" and f.event_b_id == "E03"), None)
    assert f_deletion is not None
    assert "R02" in f_deletion.matched_rules
    assert "R03" in f_deletion.matched_rules
    assert "R05" in f_deletion.matched_rules
    assert f_deletion.confidence_level == "HIGH"
