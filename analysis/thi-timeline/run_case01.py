
from pathlib import Path
import sys
from collections import Counter
import csv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.normalizer import PlasoNormalizer
from src.correlation import CorrelationEngine

input_file = ROOT / "results" / "case01_shellbags_events.csv"

events, errors = PlasoNormalizer.normalize_file_with_report(
    str(input_file),
    "case01"
)

print("Events:", len(events))
print("Normalization errors:", len(errors))

for error in errors[:5]:
    print("ERROR:", error)

engine = CorrelationEngine(window_minutes=5)
findings = engine.correlate(events)

print("Candidate findings:", len(findings))

for finding in findings[:10]:
    print(
        finding.event_a_id,
        finding.event_b_id,
        finding.matched_rules,
        finding.explanation
    )

# Thống kê các tổ hợp rule
print("\n=== RULE STATISTICS ===")

rule_counts = Counter(
    "+".join(sorted(f.matched_rules))
    for f in findings
)

for rules, count in rule_counts.most_common():
    print(f"{rules}: {count}")

# Tạo index để tra cứu event theo ID
event_map = {e.event_id: e for e in events}

def normalize_path(path):
    return (path or "").replace("/", "\\").rstrip("\\").casefold()

review_pairs = []

for finding in findings:
    a = event_map.get(finding.event_a_id)
    b = event_map.get(finding.event_b_id)

    if a is None or b is None:
        continue

    # Phải khớp cả thời gian và quan hệ đối tượng
    if not {"R01", "R02"}.issubset(set(finding.matched_rules)):
        continue

    path_a = normalize_path(a.target_path)
    path_b = normalize_path(b.target_path)

    # Bước rà soát đầu tiên: chỉ lấy cùng đường dẫn đầy đủ
    if not path_a or path_a != path_b:
        continue

    if finding.time_delta_minutes > 5:
        continue

    review_pairs.append((finding, a, b))

print("\n=== FIRST-PASS REVIEW ===")
print("Original candidates:", len(findings))
print("Filtered candidates:", len(review_pairs))

# Xuất CSV để kiểm tra forensic semantics
output = ROOT / "results" / "case01_candidates_review.csv"
output.parent.mkdir(parents=True, exist_ok=True)

columns = [
    "event_a", "event_b",
    "time_a", "time_b",
    "timestamp_desc_a", "timestamp_desc_b",
    "target_path", "delta_minutes",
    "matched_rules"
]

with output.open("w", newline="", encoding="utf-8-sig") as file:
    writer = csv.DictWriter(file, fieldnames=columns)
    writer.writeheader()

    for finding, a, b in review_pairs:
        writer.writerow({
            "event_a": a.event_id,
            "event_b": b.event_id,
            "time_a": a.timestamp,
            "time_b": b.timestamp,
            "timestamp_desc_a": a.timestamp_desc,
            "timestamp_desc_b": b.timestamp_desc,
            "target_path": a.target_path,
            "delta_minutes": finding.time_delta_minutes,
            "matched_rules": ",".join(finding.matched_rules)
        })

print("Saved:", output)

for finding, a, b in review_pairs[:10]:
    print(
        a.event_id, b.event_id,
        "|", a.timestamp_desc,
        "<->", b.timestamp_desc,
        "|", a.target_path
    )

from collections import defaultdict
import csv

print("\n=== SHELLBAGS OBJECT GROUPING ===")

# Nhóm các event theo cùng đường dẫn
groups = defaultdict(list)

for event in events:
    if event.artifact_source != "ShellBags":
        continue

    path = normalize_path(event.target_path)

    if path:
        groups[path].append(event)

print("Total ShellBags events:", len(events))
print("Unique path groups:", len(groups))

summary_rows = []

for path, group_events in groups.items():
    ordered = sorted(group_events, key=lambda e: e.dt)

    timestamp_types = sorted({
        e.timestamp_desc for e in group_events
    })

    references = sorted({
        ref
        for e in group_events
        for ref in [
            getattr(e, "evidence_reference", None)
            or e.extra_attributes.get("evidence_reference")
        ]
        if ref
    })

    summary_rows.append({
        "target_path": group_events[0].target_path,
        "event_count": len(group_events),
        "timestamp_types": "; ".join(timestamp_types),
        "earliest_timestamp": ordered[0].timestamp,
        "latest_timestamp": ordered[-1].timestamp,
        "event_ids": "; ".join(
            e.event_id for e in ordered
        ),
        "evidence_references": "; ".join(references)
    })

summary_rows.sort(
    key=lambda row: row["event_count"],
    reverse=True
)

output = ROOT / "results" / "case01_shellbags_groups.csv"
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=list(summary_rows[0].keys())
    )
    writer.writeheader()
    writer.writerows(summary_rows)

print("\n=== TOP 10 GROUPS ===")

for row in summary_rows[:10]:
    print("\nPath:", row["target_path"])
    print("Events:", row["event_count"])
    print("Timestamp types:", row["timestamp_types"])
    print("Event IDs:", row["event_ids"])

print("\nSaved:", output)
