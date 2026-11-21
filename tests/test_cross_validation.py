"""
Unit tests for WinTrace Cross-Validation Module and Contradiction Detection.
Compatible with both unittest and pytest.
"""

import unittest
from src.schema import ForensicEvent
from src.cross_validation import CrossValidator


class TestCrossValidation(unittest.TestCase):

    def test_cross_validation_pass_scenario(self):
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
                source_file="report.docx.lnk",
                target_path="C:\\Users\\Alice\\Documents\\Project\\report.docx",
                message="Shortcut accessed",
                username="Alice"
            ),
            ForensicEvent(
                event_id="E03",
                timestamp="2026-10-25T02:14:00+00:00",
                timestamp_desc="Last Time Executed",
                artifact_source="Prefetch",
                source_file="WINWORD.EXE-5C48A1B2.pf",
                target_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                message="Executed WINWORD.EXE",
                username="Alice"
            ),
            ForensicEvent(
                event_id="E04",
                timestamp="2026-10-25T02:18:30+00:00",
                timestamp_desc="Deletion Timestamp",
                artifact_source="RecycleBin",
                source_file="$I39F1AA.docx",
                target_path="C:\\Users\\Alice\\Documents\\Project\\report.docx",
                message="Deleted file",
                user_sid="S-1-5-21-3928172839-1002",
                username="Alice"
            )
        ]

        validator = CrossValidator(events)
        report = validator.run_all_checks()

        self.assertEqual(report["summary_status"], "VERIFIED")
        self.assertEqual(report["checks"]["navigation"]["status"], "PASS")
        self.assertEqual(report["checks"]["document_execution"]["status"], "PASS")
        self.assertEqual(report["checks"]["deletion_lifecycle"]["status"], "PASS")
        self.assertEqual(len(report["checks"]["deletion_lifecycle"]["contradictions"]), 0)

    def test_cross_validation_temporal_contradiction(self):
        # File deleted BEFORE it was created/accessed
        events = [
            ForensicEvent(
                event_id="E_DEL",
                timestamp="2026-10-25T02:00:00+00:00",
                timestamp_desc="Deletion Timestamp",
                artifact_source="RecycleBin",
                source_file="$I39F1AA.docx",
                target_path="C:\\Users\\Alice\\Documents\\tampered.docx",
                message="Deleted file"
            ),
            ForensicEvent(
                event_id="E_ACCESS",
                timestamp="2026-10-25T02:30:00+00:00",
                timestamp_desc="LNK Target File Accessed",
                artifact_source="LNK",
                source_file="tampered.docx.lnk",
                target_path="C:\\Users\\Alice\\Documents\\tampered.docx",
                message="Shortcut accessed"
            )
        ]

        validator = CrossValidator(events)
        h3 = validator.validate_file_deletion_lifecycle()

        self.assertEqual(h3["status"], "CONTRADICTION_FOUND")
        self.assertGreater(len(h3["contradictions"]), 0)
        self.assertEqual(h3["contradictions"][0]["type"], "TEMPORAL_ANOMALY")


if __name__ == "__main__":
    unittest.main()
