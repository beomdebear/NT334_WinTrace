"""
Unit tests for WinTrace Forensic Event Schema and Path Normalization (v2).
Compatible with both unittest and pytest.
"""

import unittest
from datetime import datetime, timezone
from src.schema import (
    ForensicEvent,
    CorrelationFinding,
    normalize_windows_path,
    parse_iso_utc,
    extract_drive_path_from_bagmru,
    VALID_ARTIFACTS,
    VALID_VALIDATION_STATUSES,
    VALID_TIMESTAMP_TYPES
)


class TestSchema(unittest.TestCase):

    def test_normalize_windows_path(self):
        self.assertEqual(normalize_windows_path("C:/Users/Alice/Documents/file.txt"), "C:\\Users\\Alice\\Documents\\file.txt")
        self.assertEqual(normalize_windows_path("C:\\\\Windows\\\\System32\\\\cmd.exe"), "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(normalize_windows_path(' "C:\\Folder\\Data" '), "C:\\Folder\\Data")
        self.assertEqual(normalize_windows_path(None), "")

    def test_parse_iso_utc(self):
        dt = parse_iso_utc("2026-10-25T02:14:00+00:00")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 10)
        self.assertEqual(dt.day, 25)
        self.assertEqual(dt.hour, 2)
        self.assertEqual(dt.minute, 14)
        self.assertEqual(dt.tzinfo, timezone.utc)

        with self.assertRaises(ValueError):
            parse_iso_utc("invalid-timestamp")

    def test_forensic_event_valid_instantiation(self):
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
        self.assertEqual(event.event_id, "EVT-001")
        self.assertEqual(event.target_path, "C:\\Program Files\\Office\\WINWORD.EXE")
        self.assertEqual(event.confidence_level, "HIGH")
        self.assertIsInstance(event.dt, datetime)

    def test_forensic_event_v2_fields(self):
        event = ForensicEvent(
            event_id="CASE01-SB0001",
            timestamp="2014-12-16T16:10:26+00:00",
            timestamp_desc="ShellItem Target Modified",
            artifact_source="ShellBags",
            source_file="UsrClass.dat",
            target_path="Desktop\\This PC\\E:\\Secret Project Data",
            message="Modified folder in shell item",
            timestamp_type="ShellItem_FolderModified",
            evidence_reference="Deduplicated.csv:L59 | hive=UsrClass.dat",
            validation_status="verified",
            case_id="CASE01",
            confidence_level="LOW"
        )
        self.assertEqual(event.timestamp_type, "ShellItem_FolderModified")
        self.assertEqual(event.evidence_reference, "Deduplicated.csv:L59 | hive=UsrClass.dat")
        self.assertEqual(event.validation_status, "verified")
        self.assertEqual(event.case_id, "CASE01")

        data = event.to_dict()
        self.assertEqual(data["timestamp_type"], "ShellItem_FolderModified")
        self.assertEqual(data["evidence_reference"], "Deduplicated.csv:L59 | hive=UsrClass.dat")
        self.assertEqual(data["case_id"], "CASE01")

    def test_forensic_event_serialization(self):
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
        self.assertEqual(data["event_id"], "EVT-002")
        self.assertEqual(data["artifact_source"], "ShellBags")

        restored = ForensicEvent.from_dict(data)
        self.assertEqual(restored.event_id, event.event_id)
        self.assertEqual(restored.target_path, event.target_path)

    def test_invalid_event_timestamp(self):
        with self.assertRaises(ValueError):
            ForensicEvent(
                event_id="EVT-ERR",
                timestamp="not-a-timestamp",
                timestamp_desc="Desc",
                artifact_source="Prefetch",
                source_file="file.pf",
                target_path="cmd.exe",
                message="Error event"
            )

    def test_extract_drive_path_from_bagmru(self):
        # Case 1: Drive letter
        drive, rel = extract_drive_path_from_bagmru("Desktop\\This PC\\E:\\Secret Project Data\\design")
        self.assertEqual(drive, "E:")
        self.assertEqual(rel, "Secret Project Data\\design")

        # Case 2: Network UNC path
        root, rel = extract_drive_path_from_bagmru(
            "Desktop\\Computers and Devices\\10.11.11.128\\10.11.11.128\\secured_drive\\Past Projects"
        )
        self.assertEqual(root, "\\\\10.11.11.128")
        self.assertEqual(rel, "secured_drive\\Past Projects")

        # Case 3: Arbitrary folder
        root, rel = extract_drive_path_from_bagmru("Desktop\\S data\\Secret Project Data\\Past Projects")
        self.assertEqual(root, "")
        self.assertEqual(rel, "S data\\Secret Project Data\\Past Projects")

        # Empty
        self.assertEqual(extract_drive_path_from_bagmru(""), ("", ""))

    def test_correlation_finding_v2_fields(self):
        finding = CorrelationFinding(
            finding_id="FIND-001",
            event_a_id="E01",
            event_b_id="E02",
            event_a_desc="Desc A",
            event_b_desc="Desc B",
            time_delta_seconds=120.0,
            time_delta_minutes=2.0,
            matched_rules=["R01", "R02"],
            confidence_score=80,
            confidence_level="HIGH",
            explanation="Explanation",
            investigation_note="FAT timestamp",
            evidence_references=["ref1", "ref2"]
        )
        self.assertEqual(finding.event_ids, ["E01", "E02"])
        self.assertEqual(finding.investigation_note, "FAT timestamp")
        self.assertEqual(finding.evidence_references, ["ref1", "ref2"])

    def test_vocabularies(self):
        self.assertIn("JumpLists", VALID_ARTIFACTS)
        self.assertIn("Registry", VALID_ARTIFACTS)
        self.assertIn("verified", VALID_VALIDATION_STATUSES)
        self.assertIn("ShellBag_LastInteracted", VALID_TIMESTAMP_TYPES)


if __name__ == "__main__":
    unittest.main()
