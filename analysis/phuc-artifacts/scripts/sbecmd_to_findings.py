"""
Chuyển output CSV của SBECmd -> shellbags_findings.csv theo event schema của nhóm (mục 13.1).

Mỗi mốc thời gian có giá trị trong một dòng ShellBag sẽ thành 1 event riêng,
kèm timestamp_type để không lẫn ngữ nghĩa (LastWrite của key khác Created của thư mục).

Chạy:
    python sbecmd_to_findings.py C:\\case01\\output\\sbecmd\\<stamp> -o C:\\case01\\findings\\shellbags_findings.csv --case CASE01
"""
import argparse
import csv
import glob
import os
from datetime import datetime, timezone

SCHEMA = ["event_id", "timestamp_utc", "timestamp_type", "artifact_type", "source_file",
          "description", "object_path", "evidence_reference", "confidence", "validation_status"]

# cột SBECmd -> (timestamp_type, mô tả, confidence)
TS_COLUMNS = {
    "LastInteracted": ("ShellBag_LastInteracted",
                       "Thư mục được tương tác gần nhất qua Shell (suy từ LastWrite + MRU)", "medium"),
    "FirstInteracted": ("ShellBag_FirstInteracted",
                        "Thư mục được tương tác lần đầu qua Shell (suy từ LastWrite + MRU)", "medium"),
    "LastWriteTime": ("ShellBag_KeyLastWrite",
                      "LastWrite của key BagMRU (chỉ gắn chắc với mục MRU 0)", "low"),
    "CreatedOn": ("ShellItem_FolderCreated",
                  "Created của thư mục lưu trong shell item (FAT time, 2s)", "low"),
    "ModifiedOn": ("ShellItem_FolderModified",
                   "Modified của thư mục lưu trong shell item (FAT time, 2s)", "low"),
    "AccessedOn": ("ShellItem_FolderAccessed",
                   "Accessed của thư mục lưu trong shell item (FAT time, 2s)", "low"),
}


def to_iso_utc(value):
    """SBECmd xuất UTC dạng 'yyyy-MM-dd HH:mm:ss' (có thể kèm phần lẻ giây). Trả ISO 8601 có Z."""
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value[:26], fmt).replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_dir", help="Thư mục chứa CSV của SBECmd")
    ap.add_argument("-o", "--output", default="shellbags_findings.csv")
    ap.add_argument("--case", default="CASE01")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.input_dir, "*.csv")))
    if not files:
        raise SystemExit(f"Không thấy CSV trong {args.input_dir}")

    rows, seen, merged, no_ts = [], {}, 0, []
    for path in files:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for line_no, r in enumerate(reader, start=2):  # dòng 1 là header
                obj = (r.get("AbsolutePath") or r.get("Value") or "").strip()
                # chỉ giữ tên hive, không lộ đường dẫn máy phân tích
                hive = os.path.basename((r.get("SourceFile") or path).strip().replace("\\", "/"))
                bag = (r.get("BagPath") or "").strip()
                mru = (r.get("MRUPosition") or r.get("MruPosition") or "").strip()
                src_ref = f"{os.path.basename(path)}:L{line_no}"
                produced = False
                for col, (ts_type, desc, conf) in TS_COLUMNS.items():
                    ts = to_iso_utc(r.get(col))
                    if not ts:
                        continue
                    produced = True
                    key = (ts, ts_type, obj, bag)
                    if key in seen:
                        # cùng path, cùng BagPath, cùng mốc: không tạo event mới (giữ event_id ổn định)
                        # nhưng ghi thêm dòng nguồn để không mất tham chiếu
                        seen[key]["evidence_reference"] += f" | also={src_ref} (MRU={mru}, Slot={r.get('Slot','')})"
                        merged += 1
                        continue
                    if col == "LastWriteTime" and mru == "0":
                        conf = "medium"
                    ref = f"{src_ref} | hive={hive} | BagPath={bag} | Slot={r.get('Slot','')} | MRU={mru} | ShellType={r.get('ShellType','')}"
                    ev = {
                        "timestamp_utc": ts,
                        "timestamp_type": ts_type,
                        "artifact_type": "ShellBags",
                        "source_file": hive,
                        "description": f"{desc}: {obj}",
                        "object_path": obj,
                        "evidence_reference": ref,
                        "confidence": conf,
                        "validation_status": "unverified",
                    }
                    seen[key] = ev
                    rows.append(ev)
                if not produced:
                    no_ts.append(f"{src_ref} {obj}")

    # sort ổn định (timestamp, rồi thứ tự đọc) để event_id tái lập được giữa các lần chạy
    rows.sort(key=lambda x: x["timestamp_utc"])
    for i, r in enumerate(rows, start=1):
        r["event_id"] = f"{args.case}-SB{i:04d}"

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMA)
        w.writeheader()
        w.writerows(rows)

    print(f"Đọc {len(files)} file CSV -> {len(rows)} event; {merged} mốc trùng được ghép tham chiếu (also=) -> {args.output}")
    if no_ts:
        print(f"CẢNH BÁO: {len(no_ts)} ShellBag không có timestamp nào, không tạo event:")
        for x in no_ts:
            print("   ", x)


if __name__ == "__main__":
    main()
