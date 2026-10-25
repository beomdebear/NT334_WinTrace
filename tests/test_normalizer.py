"""
Unit tests for PlasoNormalizer module.
"""

import pytest
from src.normalizer import PlasoNormalizer


def test_detect_artifact_source():
    assert PlasoNormalizer.detect_artifact_source("winreg/shellbags", "REG", "ShellBags", "") == "ShellBags"
    assert PlasoNormalizer.detect_artifact_source("prefetch", "FILE", "Prefetch", "") == "Prefetch"
    assert PlasoNormalizer.detect_artifact_source("lnk", "LNK", "Shortcut", "") == "LNK"
    assert PlasoNormalizer.detect_artifact_source("recycle_bin", "FILE", "Recycle Bin", "") == "RecycleBin"
    assert PlasoNormalizer.detect_artifact_source("winevtx", "LOG", "Event Log", "") == "EVTX"


def test_extract_windows_path():
    msg = "[4688] Process Creation: New Process Name: C:\\Windows\\System32\\cmd.exe PID: 1234"
    path = PlasoNormalizer.extract_windows_path(msg, "")
    assert path == "C:\\Windows\\System32\\cmd.exe"

    msg2 = "Deleted file: C:\\Users\\Alice\\Documents\\test.docx"
    path2 = PlasoNormalizer.extract_windows_path(msg2, "")
    assert path2 == "C:\\Users\\Alice\\Documents\\test.docx"


def test_extract_user_info():
    msg = "[4624] Strings: [User: Alice, LogonType: 2, UserSid: S-1-5-21-3928172839-1002]"
    username, sid = PlasoNormalizer.extract_user_info(msg, "")
    assert username == "Alice"
    assert sid == "S-1-5-21-3928172839-1002"


def test_normalize_record():
    raw_row = {
        "datetime": "2026-10-25T02:14:00.000000+00:00",
        "timestamp_desc": "Last Time Executed",
        "source": "FILE",
        "source_long": "Windows Prefetch",
        "message": "[WINWORD.EXE-5C48A1B2.pf] Executed 14 times Path: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE Hash: 0x5C48A1B2",
        "parser": "prefetch",
        "display_name": "C:\\Windows\\Prefetch\\WINWORD.EXE-5C48A1B2.pf"
    }

    event = PlasoNormalizer.normalize_record(raw_row, 1)
    assert event.event_id == "EVT-0001"
    assert event.artifact_source == "Prefetch"
    assert event.target_path == "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    assert event.extra_attributes.get("run_count") == 14
    assert event.extra_attributes.get("prefetch_hash") == "0x5C48A1B2"
