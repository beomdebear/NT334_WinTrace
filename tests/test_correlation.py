"""
Unit tests for WinTrace Correlation Rules Engine (R01 - R05) (v2).
Compatible with both unittest and pytest.
"""

import unittest
from src.schema import ForensicEvent
from src.correlation import (
    path_relation,
    is_program_file_pair,
    CorrelationEngine
)


class TestCorrelation(unittest.TestCase):

    def test_path_relation(self):
        # Same path
        self.assertEqual(path_relation("C:\\Users\\Alice\\doc.docx", "c:/users/alice/doc.docx"), "Same path")

        # Parent-child path
        self.assertEqual(path_relation("C:\\Users\\Alice\\Documents", "C:\\Users\\Alice\\Documents\\Project\\file.txt"), "Parent-child path")
        self.assertEqual(path_relation("C:\\Users\\Alice\\Documents\\Project\\file.txt", "C:\\Users\\Alice\\Documents"), "Parent-child path")

        # Unrelated paths
        self.assertIsNone(path_relation("C:\\Windows\\System32", "C:\\Users\\Alice\\Documents"))

    def test_path_relation_bagmru_paths(self):
        # BagMRU path to standard path: 'Desktop\This PC\E:\Secret Project Data\design' <-> 'E:\Secret Project Data\design'
        sb_path = "Desktop\\This PC\\E:\\Secret Project Data\\design"
        std_path = "E:\\Secret Project Data\\design"
        self.assertEqual(path_relation(sb_path, std_path), "Same path")

        # BagMRU folder to standard child file
        file_path = "E:\\Secret Project Data\\design\\report.docx"
        self.assertEqual(path_relation(sb_path, file_path), "Parent-child path")

        # BagMRU UNC path to standard UNC path
        unc_sb = "Desktop\\Computers and Devices\\10.11.11.128\\10.11.11.128\\secured_drive\\Past Projects"
        unc_std = "\\\\10.11.11.128\\secured_drive\\Past Projects\\file.xlsx"
        self.assertEqual(path_relation(unc_sb, unc_std), "Parent-child path")

    def test_is_program_file_pair(self):
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

        self.assertTrue(is_program_file_pair(prog_event, doc_event))

    def test_correlation_engine_rules(self):
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
                username="Alice",
                evidence_reference="Deduplicated.csv:L10"
            ),
            ForensicEvent(
                event_id="E02",
                timestamp="2026-10-25T02:12:00+00:00",
                timestamp_desc="LNK Target File Accessed",
                artifact_source="LNK",
                source_file="confidential.docx.lnk",
                target_path="C:\\Users\\Alice\\Documents\\Project\\confidential.docx",
                message="Shortcut accessed",
                username="Alice",
                evidence_reference="Recent:L5"
            ),
            ForensicEvent(
                event_id="E03",
                timestamp="2026-10-25T02:18:00+00:00",
                timestamp_desc="Deletion Timestamp",
                artifact_source="RecycleBin",
                source_file="$I39F1AA.docx",
                target_path="C:\\Users\\Alice\\Documents\\Project\\confidential.docx",
                message="Moved to Recycle Bin",
                username="Alice",
                evidence_reference="$I39F1AA"
            )
        ]

        findings = engine.correlate(events)
        self.assertGreaterEqual(len(findings), 2)

        # Verify E01 and E02 correlation
        f_folder_file = next((f for f in findings if f.event_a_id == "E01" and f.event_b_id == "E02"), None)
        self.assertIsNotNone(f_folder_file)
        self.assertIn("R01", f_folder_file.matched_rules)
        self.assertIn("R02", f_folder_file.matched_rules)
        self.assertIn("R03", f_folder_file.matched_rules)
        self.assertEqual(f_folder_file.confidence_level, "HIGH")
        # Check v2 fields
        self.assertEqual(f_folder_file.event_ids, ["E01", "E02"])
        self.assertIn("Deduplicated.csv:L10", f_folder_file.evidence_references)
        self.assertIn("Recent:L5", f_folder_file.evidence_references)

        # Verify E02 and E03 deletion context correlation
        f_deletion = next((f for f in findings if f.event_a_id == "E02" and f.event_b_id == "E03"), None)
        self.assertIsNotNone(f_deletion)
        self.assertIn("R02", f_deletion.matched_rules)
        self.assertIn("R03", f_deletion.matched_rules)
        self.assertIn("R05", f_deletion.matched_rules)
        self.assertEqual(f_deletion.confidence_level, "HIGH")


if __name__ == "__main__":
    unittest.main()
