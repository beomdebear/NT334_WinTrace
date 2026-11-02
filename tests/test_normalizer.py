"""
Unit tests for PlasoNormalizer and ShellBagsNormalizer modules (v2).
Compatible with both unittest and pytest.
"""

import unittest
from pathlib import Path
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer


class TestNormalizer(unittest.TestCase):

    def test_detect_artifact_source(self):
        self.assertEqual(PlasoNormalizer.detect_artifact_source("winreg/shellbags", "REG", "ShellBags", ""), "ShellBags")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("prefetch", "FILE", "Prefetch", ""), "Prefetch")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("lnk", "LNK", "Shortcut", ""), "LNK")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("recycle_bin", "FILE", "Recycle Bin", ""), "RecycleBin")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("winevtx", "LOG", "Event Log", ""), "EVTX")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("jump_list", "FILE", "Jump List", ""), "JumpLists")

    def test_extract_windows_path(self):
        msg = "[4688] Process Creation: New Process Name: C:\\Windows\\System32\\cmd.exe PID: 1234"
        path = PlasoNormalizer.extract_windows_path(msg, "")
        self.assertEqual(path, "C:\\Windows\\System32\\cmd.exe")

        msg2 = "Deleted file: C:\\Users\\Alice\\Documents\\test.docx"
        path2 = PlasoNormalizer.extract_windows_path(msg2, "")
        self.assertEqual(path2, "C:\\Users\\Alice\\Documents\\test.docx")

    def test_extract_user_info(self):
        msg = "[4624] Strings: [User: Alice, LogonType: 2, UserSid: S-1-5-21-3928172839-1002]"
        username, sid = PlasoNormalizer.extract_user_info(msg, "")
        self.assertEqual(username, "Alice")
        self.assertEqual(sid, "S-1-5-21-3928172839-1002")

    def test_normalize_record(self):
        raw_row = {
            "datetime": "2026-10-25T02:14:00.000000+00:00",
            "timestamp_desc": "Last Time Executed",
            "source": "FILE",
            "source_long": "Windows Prefetch",
            "message": "[WINWORD.EXE-5C48A1B2.pf] Executed 14 times Path: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE Hash: 0x5C48A1B2",
            "parser": "prefetch",
            "display_name": "C:\\Windows\\Prefetch\\WINWORD.EXE-5C48A1B2.pf"
        }

        event = PlasoNormalizer.normalize_record(raw_row, 1, case_id="CASE01")
        self.assertEqual(event.event_id, "EVT-0001")
        self.assertEqual(event.artifact_source, "Prefetch")
        self.assertEqual(event.target_path, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
        self.assertEqual(event.extra_attributes.get("run_count"), 14)
        self.assertEqual(event.extra_attributes.get("prefetch_hash"), "0x5C48A1B2")
        self.assertEqual(event.timestamp_type, "Prefetch_LastRun")
        self.assertEqual(event.case_id, "CASE01")
        self.assertIn("plaso:prefetch", event.evidence_reference)

    def test_shellbags_normalizer(self):
        csv_path = Path("results/case01_shellbags_events.csv")
        if csv_path.exists():
            events = ShellBagsNormalizer.normalize_file(str(csv_path))
            self.assertEqual(len(events), 383)
            # Check first event
            ev0 = events[0]
            self.assertEqual(ev0.event_id, "CASE01-SB0001")
            self.assertEqual(ev0.artifact_source, "ShellBags")
            self.assertEqual(ev0.case_id, "CASE01")
            self.assertEqual(ev0.timestamp_type, "ShellItem_FolderModified")
            self.assertEqual(ev0.validation_status, "verified")
            self.assertIn("Deduplicated.csv", ev0.evidence_reference)


if __name__ == "__main__":
    unittest.main()
