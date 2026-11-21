"""WinTrace Week 3: focused forensic negative tests for correlation rules.

Run on PR #10 (week2) worktree from repository root:
    python -m pytest tests/test_correlation_false_positives.py -v

The first three tests are intentionally *regression specifications*: they may
FAIL on the current engine. Do not weaken the assertions just to get green.
They express desired forensic-safe behavior, which needs team agreement.
"""

from src.correlation import CorrelationEngine, path_relation
from src.schema import ForensicEvent


def event(event_id: str, timestamp: str, artifact: str, path: str,
          message: str, timestamp_desc: str = "Test Event") -> ForensicEvent:
    """Generate a synthetic fixture, never claim it is real CASE01 evidence."""
    return ForensicEvent(
        event_id=event_id,
        timestamp=timestamp,
        timestamp_desc=timestamp_desc,
        artifact_source=artifact,
        source_file=f"fixture_{event_id}.csv",
        target_path=path,
        message=message,
        parser="synthetic-test",
        case_id="SYNTHETIC-NEGATIVE-TEST",
        validation_status="synthetic",
    )


def finding_for(events, id_a: str, id_b: str):
    """Find a pair regardless of chronological ordering."""
    expected = {id_a, id_b}
    return next(
        (
            f for f in CorrelationEngine(window_minutes=5).correlate(events)
            if {f.event_a_id, f.event_b_id} == expected
        ),
        None,
    )


def test_r02_same_filename_on_different_volumes_is_not_same_object():
    """One basename at two unrelated paths is NOT evidence of same object."""
    a = r"C:\Finance\report.docx"
    b = r"E:\Unrelated\report.docx"
    # Existing engine returns 'Same filename'; that is a weak search hint,
    # not a forensic object association for R02.
    assert path_relation(a, b) is None


def test_r03_unrelated_artifacts_close_in_time_do_not_corroborate_each_other():
    """Temporal coincidence + different artifact types cannot prove support."""
    events = [
        event(
            "SYN-R03-A", "2026-10-25T02:00:00+00:00", "Prefetch",
            r"C:\Windows\System32\notepad.exe", "Program execution evidence",
            "Last Time Executed",
        ),
        event(
            "SYN-R03-B", "2026-10-25T02:01:00+00:00", "LNK",
            r"E:\Unrelated\invoice.xlsx", "Shortcut target metadata",
            "LNK Target Modified",
        ),
    ]
    f = finding_for(events, "SYN-R03-A", "SYN-R03-B")
    # If the engine generates any pair, the cross-artifact rule must NOT claim
    # corroboration without a shared object/path or other independent link.
    assert f is None or "R03" not in f.matched_rules


def test_r05_deletion_before_later_interaction_must_not_claim_pre_deletion_activity():
    """An event timestamp *after* deletion is not 'prior interaction'."""
    target = r"C:\Users\Alice\Documents\contract.docx"
    events = [
        event(
            "SYN-R05-DEL", "2026-10-25T02:00:00+00:00", "RecycleBin",
            target, "Moved to Recycle Bin", "Deletion Timestamp",
        ),
        event(
            "SYN-R05-LNK", "2026-10-25T02:03:00+00:00", "LNK",
            target, "Shortcut was updated after deletion", "LNK File Modified",
        ),
    ]
    f = finding_for(events, "SYN-R05-DEL", "SYN-R05-LNK")
    assert f is not None, "Expected pair to test R05 in an otherwise-correlated path"
    assert "R05" not in f.matched_rules


def test_positive_control_actual_parent_child_path_is_related():
    """Protect intended R02 behavior while removing unrelated same-name links."""
    assert path_relation(
        r"C:\Users\Alice\Documents",
        r"C:\Users\Alice\Documents\report.docx",
    ) == "Parent-child path"


def test_r02_requires_a_fully_qualified_path_and_preserves_unc_share():
    assert path_relation("report.docx", "report.docx") is None
    a = event("A", "2026-10-25T02:00:00Z", "LNK",
              r"\\server\finance\report.docx", "Shortcut metadata")
    assert path_relation(a.target_path, r"//server/finance/REPORT.docx") == "Same path"
    assert path_relation(a.target_path, r"\\server\legal\report.docx") is None
    assert path_relation(a.target_path, r"\server\finance\report.docx") is None


def test_r03_and_r04_need_a_link_beyond_application_file_type_compatibility():
    doc_path = r"C:\Finance\report.docx"
    program = event("A", "2026-10-25T02:00:00Z", "Prefetch",
                    r"C:\Office\WINWORD.EXE", "Execution", "Last Time Executed")
    document = event("B", "2026-10-25T02:01:00Z", "LNK",
                     doc_path, "Shortcut metadata", "LNK Target File Accessed")

    program.extra_attributes["referenced_files"] = [r"E:\Unrelated\report.docx"]
    assert finding_for([program, document], "A", "B") is None

    program.extra_attributes["referenced_files"] = [doc_path]
    finding = finding_for([program, document], "A", "B")
    assert finding is not None
    assert finding.matched_rules == ["R01", "R03", "R04"]


def test_r05_requires_interaction_semantics_and_strict_temporal_order():
    path = r"C:\Finance\report.docx"
    accessed = event("A", "2026-10-25T02:00:00Z", "LNK", path, "Shortcut metadata")
    accessed.timestamp_type = "LNK_TargetAccessed"
    deletion = event("B", "2026-10-25T02:01:00Z", "RecycleBin", path, "Index entry")
    deletion.timestamp_type = "RecycleBin_DeletionTime"

    finding = finding_for([deletion, accessed], "A", "B")
    assert "R05" in finding.matched_rules

    wrong_type = event("C", "2026-10-25T01:59:00Z", "LNK",
                       path, "Shortcut file updated", "LNK Target File Accessed")
    wrong_type.timestamp_type = "LNK_FileModified"
    assert "R05" not in finding_for([wrong_type, deletion], "C", "B").matched_rules

    for timestamp in ("2026-10-25T02:00:00Z", "2026-10-25T01:59:00Z"):
        early_deletion = event("B", timestamp, "RecycleBin", path, "Index entry",
                               "Deletion Timestamp")
        assert "R05" not in finding_for([accessed, early_deletion], "A", "B").matched_rules

    delete_request = event("D", "2026-10-25T02:01:00Z", "EVTX", path,
                           "Delete access requested", "Object Access (Delete Mask)")
    assert "R05" not in finding_for([accessed, delete_request], "A", "D").matched_rules
