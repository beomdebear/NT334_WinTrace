"""
Chuyển shellbags_findings.csv (schema mục 13.1 của đề) -> schema chung của nhóm
(docs/event_schema.md, src/schema.py: ForensicEvent).

Giữ nguyên event_id (CASE01-SB####) để các tham chiếu trong manual_evidence.md vẫn đúng.
evidence_reference, validation_status, timestamp_type gốc được đưa vào extra_attributes (JSON).

Chạy:
    python to_team_schema.py shellbags_findings.csv -o case01_shellbags_events.csv --username informant
"""
import argparse
import csv
import json

TEAM_FIELDS = ["event_id", "timestamp", "timestamp_desc", "artifact_source", "source_file",
               "target_path", "message", "data_type", "parser", "user_sid", "username",
               "confidence_level", "extra_attributes"]

TS_DESC = {
    "ShellBag_LastInteracted": "BagMRU Last Interacted",
    "ShellBag_FirstInteracted": "BagMRU First Interacted",
    "ShellBag_KeyLastWrite": "BagMRU Key Last Write",
    "ShellItem_FolderCreated": "ShellItem Target Created",
    "ShellItem_FolderModified": "ShellItem Target Modified",
    "ShellItem_FolderAccessed": "ShellItem Target Accessed",
}


def to_iso_offset(ts):
    """'2015-03-23T20:28:17Z' -> '2015-03-23T20:28:17+00:00' (định dạng của src/schema.py)."""
    return ts[:-1] + "+00:00" if ts.endswith("Z") else ts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="case01_shellbags_events.csv")
    ap.add_argument("--username", default="")
    ap.add_argument("--user-sid", default="")
    args = ap.parse_args()

    out = []
    with open(args.input, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            ts_type = r["timestamp_type"]
            out.append({
                "event_id": r["event_id"],
                "timestamp": to_iso_offset(r["timestamp_utc"]),
                "timestamp_desc": TS_DESC.get(ts_type, ts_type),
                "artifact_source": "ShellBags",
                "source_file": r["source_file"].split("\\")[-1],
                "target_path": r["object_path"],
                "message": r["description"],
                "data_type": "windows:registry:bagmru",
                "parser": "sbecmd",
                "user_sid": args.user_sid,
                "username": args.username,
                "confidence_level": r["confidence"].upper(),
                "extra_attributes": json.dumps({
                    "timestamp_type": ts_type,
                    "evidence_reference": r["evidence_reference"],
                    "validation_status": r["validation_status"],
                }, ensure_ascii=False),
            })

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TEAM_FIELDS)
        w.writeheader()
        w.writerows(out)
    verified = sum(1 for x in out if '"verified"' in x["extra_attributes"])
    print(f"{len(out)} event -> {args.output} ({verified} verified)")


if __name__ == "__main__":
    main()
