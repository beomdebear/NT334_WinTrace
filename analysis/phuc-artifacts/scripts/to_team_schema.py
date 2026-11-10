"""
Chuyển shellbags_findings.csv (format v2, mục 13.1 của đề) -> schema chung của nhóm
(docs/event_schema.md, src/schema.py::ForensicEvent), có bổ sung metadata ShellBags
có cấu trúc để correlation engine dùng trực tiếp.

Nguyên tắc
- Giữ nguyên event_id (CASE01-SB####) để mọi tham chiếu trong manual_evidence.md vẫn đúng.
- Không gộp hai timestamp khác ngữ nghĩa: mỗi event giữ timestamp_type riêng và được
  phân loại semantic_class (user_interaction / registry_write_unattributed / target_metadata).
- Không làm mất tham chiếu: evidence_reference giữ nguyên, các dòng nguồn phụ (also=) được
  tách ra thành danh sách also_source_lines.
- target_path dùng đường dẫn hệ thống tệp (E:\\..., \\\\host\\share\\..., C:\\Users\\...) khi
  suy ra được, để khớp với LNK/Jump List/Prefetch; đường dẫn gốc của Explorer giữ ở
  extra_attributes.shellbag_path.

Chạy:
    python to_team_schema.py shellbags_findings.csv \\
        --sbecmd-csv ../tool_output/sbecmd/Deduplicated.csv \\
        -o ../../../results/case01_shellbags_events.csv \\
        --username informant --user-sid S-1-5-21-2425377081-3129163575-2985601102-1000
"""
import argparse
import collections
import csv
import json
import re

TEAM_FIELDS = ["event_id", "timestamp", "timestamp_desc", "artifact_source", "source_file",
               "target_path", "message", "data_type", "parser", "user_sid", "username",
               "confidence_level", "extra_attributes"]

# timestamp_type -> (timestamp_desc theo docs/event_schema.md §3, semantic_class, precision)
TS_META = {
    "ShellBag_FirstInteracted": ("BagMRU First Interacted Time", "user_interaction", "registry_100ns"),
    "ShellBag_LastInteracted": ("BagMRU Last Interacted Time", "user_interaction", "registry_100ns"),
    "ShellBag_KeyLastWrite": ("BagMRU Key Last Write Time", None, "registry_100ns"),  # phụ thuộc MRU
    "ShellItem_FolderCreated": ("ShellItem Target Created Time", "target_metadata", "fat_2s"),
    "ShellItem_FolderModified": ("ShellItem Target Modified Time", "target_metadata", "fat_2s"),
    "ShellItem_FolderAccessed": ("ShellItem Target Accessed Time", "target_metadata", "fat_2s"),
}

UNC_PREFIX = "Desktop\\Computers and Devices\\"
DRIVE_PREFIX = "Desktop\\This PC\\"
USER_FILES_PREFIX = "Desktop\\Shared Documents Folder (Users Files)\\"
VIRTUAL_ROOTS = ("Desktop\\UsersLibraries", "Desktop\\ControlPanelHome", "Desktop\\Recycle Bin",
                 "Desktop\\Recent Places", "Desktop\\CLSID_SearchFolder", "Desktop\\This PC",
                 "Desktop\\Computers and Devices", "Desktop\\Shared Documents Folder (Users Files)")


def parse_ref(ref):
    """'Deduplicated.csv:L59 | hive=... | BagPath=... | ... | also=Deduplicated.csv:L60 (MRU=1, Slot=2)'"""
    parts = [p.strip() for p in ref.split(" | ")]
    out = {"source_line": parts[0], "also_source_lines": []}
    for p in parts[1:]:
        if p.startswith("also="):
            out["also_source_lines"].append(p[5:].split(" ")[0])
        elif p.startswith("verified:"):
            out["verified_by"] = p[len("verified:"):].strip()
        elif "=" in p:
            k, v = p.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def to_fs_path(shellbag_path, user_profile):
    """Suy ra đường dẫn hệ thống tệp từ đường dẫn namespace của Explorer.
    Trả (fs_path, basis). basis cho biết mức chắc chắn của phép ánh xạ."""
    p = shellbag_path
    if p.startswith(UNC_PREFIX):
        rest = p[len(UNC_PREFIX):].split("\\")
        # dạng: <host>\<host>\<share>\...   (SBECmd lặp tên host)
        if len(rest) >= 3 and rest[0] == rest[1]:
            return "\\\\" + rest[1] + "\\" + "\\".join(rest[2:]), "unc"
        return "", "virtual"
    if p.startswith(DRIVE_PREFIX):
        rest = p[len(DRIVE_PREFIX):]
        if re.match(r"^[A-Za-z]:", rest):
            return (rest if "\\" in rest else rest + "\\"), "drive_letter"
    if p.startswith(USER_FILES_PREFIX) and user_profile:
        return user_profile + "\\" + p[len(USER_FILES_PREFIX):], "user_profile_inferred"
    if p in VIRTUAL_ROOTS or any(p.startswith(r + "\\") for r in VIRTUAL_ROOTS if r != "Desktop\\This PC"):
        return "", "virtual"
    if p.startswith("Desktop\\") and user_profile:
        # thư mục con trực tiếp của namespace Desktop = thư mục Desktop của user (suy luận)
        return user_profile + "\\Desktop\\" + p[len("Desktop\\"):], "user_profile_inferred"
    return "", "virtual"


def volume_of(fs_path):
    if fs_path.startswith("\\\\"):
        parts = fs_path[2:].split("\\")
        return "\\\\" + "\\".join(parts[:2]) if len(parts) >= 2 else fs_path
    m = re.match(r"^([A-Za-z]:)", fs_path)
    return m.group(1).upper() if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="shellbags_findings.csv (v2)")
    ap.add_argument("--sbecmd-csv", required=True, help="Output gốc SBECmd (Deduplicated.csv)")
    ap.add_argument("-o", "--output", default="case01_shellbags_events.csv")
    ap.add_argument("--username", default="")
    ap.add_argument("--user-sid", default="")
    ap.add_argument("--user-profile", default="C:\\Users\\informant",
                    help="Thư mục profile của user sở hữu hive, dùng để suy ra path Desktop")
    ap.add_argument("--twin-window", type=int, default=60,
                    help="Giây: cửa sổ ghép bản ghi cùng thư mục giữa NTUSER.DAT và UsrClass.dat")
    args = ap.parse_args()

    with open(args.sbecmd_csv, newline="", encoding="utf-8-sig") as f:
        raw = {f"Deduplicated.csv:L{i}": r for i, r in enumerate(csv.DictReader(f), start=2)}

    with open(args.input, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))

    # burst: số event KeyLastWrite cùng hive cùng mốc (một lần ghi registry -> nhiều dòng)
    burst = collections.Counter((r["source_file"], r["timestamp_utc"]) for r in rows
                                if r["timestamp_type"] == "ShellBag_KeyLastWrite")

    out, problems = [], []
    for r in rows:
        ref = parse_ref(r["evidence_reference"])
        src = raw.get(ref["source_line"])
        if src is None:
            problems.append(f"{r['event_id']}: không tìm thấy {ref['source_line']} trong output SBECmd")
            src = {}
        ts_type = r["timestamp_type"]
        desc, sem, precision = TS_META.get(ts_type, (ts_type, "unknown", "unknown"))
        mru = ref.get("MRU", src.get("MRUPosition", ""))
        if ts_type == "ShellBag_KeyLastWrite":
            sem = "user_interaction" if mru == "0" else "registry_write_unattributed"
        if precision == "fat_2s" and ts_type == "ShellItem_FolderAccessed" and r["timestamp_utc"][11:19] in ("04:00:00", "05:00:00"):
            precision = "fat_date_only"  # FAT chỉ lưu ngày truy cập: 00:00 EDT/EST
        shell_type = ref.get("ShellType", src.get("ShellType", ""))
        sb_path = r["object_path"]
        fs_path, basis = to_fs_path(sb_path, args.user_profile)
        inside_archive = shell_type == "Zip file contents" or ".zip\\" in sb_path.lower()
        archive_path = ""
        if inside_archive:
            m = re.match(r"(.*?\.zip)(\\|$)", fs_path, re.I)
            archive_path = m.group(1) if m else ""

        extra = {
            "timestamp_type": ts_type,
            "semantic_class": sem,
            "is_user_activity": sem == "user_interaction",
            "timestamp_precision": precision,
            "evidence_reference": r["evidence_reference"],
            "validation_status": r["validation_status"],
            "hive": r["source_file"],
            "source_line": ref["source_line"],
            "also_source_lines": ref["also_source_lines"],
            "bag_path": ref.get("BagPath", src.get("BagPath", "")),
            "slot": ref.get("Slot", src.get("Slot", "")),
            "node_slot": src.get("NodeSlot", ""),
            "mru_position": int(mru) if str(mru).isdigit() else None,
            "shell_type": shell_type,
            "has_explored": src.get("HasExplored", ""),
            "shellbag_path": sb_path,
            "fs_path": fs_path,
            "fs_path_basis": basis,
            "volume": volume_of(fs_path),
            "inside_archive": inside_archive,
            "archive_path": archive_path,
            "cdburn_staging": shell_type == "CDBurn",
            "registry_write_burst": burst.get((r["source_file"], r["timestamp_utc"]), 1)
            if ts_type == "ShellBag_KeyLastWrite" else 1,
        }
        if ref.get("verified_by"):
            extra["verified_by"] = ref["verified_by"]
        out.append({
            "event_id": r["event_id"],
            "timestamp": r["timestamp_utc"][:-1] + "+00:00" if r["timestamp_utc"].endswith("Z") else r["timestamp_utc"],
            "timestamp_desc": desc,
            "artifact_source": "ShellBags",
            "source_file": r["source_file"],
            "target_path": fs_path or sb_path,
            "message": r["description"],
            "data_type": "windows:registry:bagmru",
            "parser": "sbecmd",
            "user_sid": args.user_sid,
            "username": args.username,
            "confidence_level": r["confidence"].upper(),
            "extra_attributes": extra,
        })

    # bản ghi "song sinh" giữa 2 hive: cùng thư mục, cùng loại timestamp, lệch <= twin_window giây
    from datetime import datetime
    def dt(e):
        return datetime.fromisoformat(e["timestamp"])
    groups = collections.defaultdict(list)
    for e in out:
        x = e["extra_attributes"]
        if x["semantic_class"] == "user_interaction":
            groups[(x["shellbag_path"], x["timestamp_type"])].append(e)
    for evs in groups.values():
        for e in evs:
            twins = [o["event_id"] for o in evs
                     if o is not e and o["source_file"] != e["source_file"]
                     and abs((dt(o) - dt(e)).total_seconds()) <= args.twin_window]
            e["extra_attributes"]["cross_hive_twin_ids"] = twins

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TEAM_FIELDS)
        w.writeheader()
        for e in out:
            row = dict(e)
            row["extra_attributes"] = json.dumps(e["extra_attributes"], ensure_ascii=False, sort_keys=True)
            w.writerow(row)

    c = collections.Counter(e["extra_attributes"]["semantic_class"] for e in out)
    print(f"{len(out)} event -> {args.output}")
    print("  semantic_class:", dict(c))
    print("  verified:", sum(e["extra_attributes"]["validation_status"] == "verified" for e in out))
    print("  có fs_path:", sum(bool(e["extra_attributes"]["fs_path"]) for e in out))
    if problems:
        print("CẢNH BÁO:")
        for p in problems:
            print("  ", p)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
