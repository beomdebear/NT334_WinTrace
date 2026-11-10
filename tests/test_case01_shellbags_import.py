"""Kiểm thử tích hợp: ShellBags CASE01 thật -> normalizer -> SQLite (Phúc, tuần 2).

Chạy trên chính các file bàn giao trong repo, không dùng dữ liệu giả lập.
"""
import csv
import json
from pathlib import Path

import pytest

from src.normalizer import PlasoNormalizer
from src.storage import TimelineStore

ROOT = Path(__file__).resolve().parent.parent
UNIFIED = ROOT / "results" / "case01_shellbags_events.csv"
V2 = ROOT / "analysis" / "phuc-artifacts" / "shellbags_findings.csv"
SBECMD = ROOT / "analysis" / "phuc-artifacts" / "tool_output" / "sbecmd" / "Deduplicated.csv"

EXPECTED_EVENTS = 383
EXPECTED_VERIFIED = 30
SBECMD_ROWS = 109


@pytest.fixture(scope="module")
def events():
    evs, errors = PlasoNormalizer.normalize_file_with_report(str(UNIFIED), "case01_shellbags")
    assert errors == []
    return evs


def test_all_events_normalize(events):
    assert len(events) == EXPECTED_EVENTS
    assert len({e.event_id for e in events}) == EXPECTED_EVENTS
    assert all(e.artifact_source == "ShellBags" for e in events)


def test_sqlite_import_keeps_provenance_and_is_idempotent(events, tmp_path):
    db = tmp_path / "case01.db"
    with TimelineStore(str(db)) as store:
        assert store.insert_events(events) == EXPECTED_EVENTS
        assert store.insert_events(events) == 0  # chạy lại không nhân đôi
        row = store.connection.execute(
            "SELECT COUNT(*), COUNT(evidence_reference), COUNT(timestamp_type), "
            "SUM(validation_status = 'verified') FROM events").fetchone()
    assert tuple(row) == (EXPECTED_EVENTS, EXPECTED_EVENTS, EXPECTED_EVENTS, EXPECTED_VERIFIED)


def test_every_sbecmd_row_is_traceable(events):
    """Không ShellBag nào của SBECmd bị mất tham chiếu sau khi chuyển đổi/khử trùng."""
    referenced = set()
    for e in events:
        x = e.extra_attributes
        referenced.add(x["source_line"])
        referenced.update(x["also_source_lines"])
    assert referenced == {f"Deduplicated.csv:L{i}" for i in range(2, SBECMD_ROWS + 2)}


def test_timestamps_are_utc_and_inside_case_window(events):
    # ShellItem target metadata có thể cũ hơn kịch bản (2014-12), nhưng không được có
    # mốc của máy phân tích (2026) – dấu hiệu dùng output từ bản copy.
    assert all(e.timestamp.endswith("+00:00") for e in events)
    assert min(e.timestamp for e in events) >= "2014-12-01"
    assert max(e.timestamp for e in events) <= "2015-03-26"


def test_timestamp_semantics_are_not_merged(events):
    """Metadata của thư mục đích không được xếp vào hoạt động của người dùng."""
    by_type = {}
    for e in events:
        x = e.extra_attributes
        by_type.setdefault(x["timestamp_type"], set()).add(x["semantic_class"])
    for t in ("ShellItem_FolderCreated", "ShellItem_FolderModified", "ShellItem_FolderAccessed"):
        assert by_type[t] == {"target_metadata"}
    assert by_type["ShellBag_KeyLastWrite"] == {"user_interaction", "registry_write_unattributed"}
    for e in events:
        x = e.extra_attributes
        if x["timestamp_type"] == "ShellBag_KeyLastWrite":
            assert x["is_user_activity"] == (x["mru_position"] == 0)


def test_v2_and_unified_describe_same_events():
    with V2.open(encoding="utf-8") as f:
        v2 = {r["event_id"]: r for r in csv.DictReader(f)}
    with UNIFIED.open(encoding="utf-8") as f:
        uni = {r["event_id"]: r for r in csv.DictReader(f)}
    assert v2.keys() == uni.keys()
    for eid, r in v2.items():
        u = uni[eid]
        x = json.loads(u["extra_attributes"])
        assert u["timestamp"] == r["timestamp_utc"].replace("Z", "+00:00")
        assert x["timestamp_type"] == r["timestamp_type"]
        assert x["evidence_reference"] == r["evidence_reference"]
        assert x["validation_status"] == r["validation_status"]


@pytest.mark.parametrize("event_id, fs_path, volume", [
    # F001 – network share (verified)
    ("CASE01-SB0033", r"\\10.11.11.128\secured_drive\Secret Project Data\design", r"\\10.11.11.128\secured_drive"),
    # F004 – USB RM#2 (verified)
    ("CASE01-SB0254", r"E:\Secret Project Data\design\winter_whether_advisory.zip", "E:"),
])
def test_fs_path_mapping_for_verified_findings(events, event_id, fs_path, volume):
    e = next(e for e in events if e.event_id == event_id)
    assert e.extra_attributes["fs_path"] == fs_path
    assert e.extra_attributes["volume"] == volume


def test_cdburn_staging_flag(events):
    de = [e for e in events if e.extra_attributes["shellbag_path"] == r"Desktop\This PC\D:\de"
          and e.extra_attributes["shell_type"] == "CDBurn"]
    assert de and all(e.extra_attributes["cdburn_staging"] for e in de)


def test_cross_hive_twins_are_linked(events):
    """Cùng một lần duyệt được ghi ở cả NTUSER.DAT và UsrClass.dat: không phải 2 bằng chứng độc lập."""
    twins = [e for e in events if e.extra_attributes.get("cross_hive_twin_ids")]
    assert twins
    ids = {e.event_id: e for e in events}
    for e in twins:
        for t in e.extra_attributes["cross_hive_twin_ids"]:
            assert e.event_id in ids[t].extra_attributes["cross_hive_twin_ids"]
            assert ids[t].source_file != e.source_file


@pytest.mark.xfail(strict=True, reason=(
    "src/schema.py::normalize_windows_path gộp '\\\\' đầu UNC thành '\\' -> mất dạng "
    "\\\\host\\share. Khi đã sửa, test sẽ XPASS: xóa marker xfail."))
def test_unc_target_path_survives_normalization(events):
    e = next(e for e in events if e.event_id == "CASE01-SB0033")
    assert e.target_path.startswith("\\\\10.11.11.128\\")
