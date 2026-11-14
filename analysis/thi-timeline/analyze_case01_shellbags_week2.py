#!/usr/bin/env python3
"""Standalone WinTrace CASE01 ShellBags object-context audit (week 2).

No changes to src/schema.py, src/correlation.py, or tests/test_correlation.py.
Legacy (pre-v2) CSV columns are supported. This is NOT a user-activity validator.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ID_RE = re.compile(r"^CASE01-SB\d+$", flags=re.IGNORECASE)


def first_value(row: dict, *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def read_extra(row: dict, logical_record: int) -> dict:
    value = row.get("extra_attributes")
    if not value or not str(value).strip():
        return {}
    try:
        result = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"CSV record #{logical_record}: invalid extra_attributes JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise ValueError(f"CSV record #{logical_record}: extra_attributes must be a JSON object")
    return result


def parse_aware_timestamp(raw: str, logical_record: int) -> datetime:
    if not raw:
        raise ValueError(f"CSV record #{logical_record}: missing timestamp")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"CSV record #{logical_record}: invalid timestamp {raw!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"CSV record #{logical_record}: timestamp without timezone {raw!r}")
    return dt.astimezone(timezone.utc)


def kind_of_timestamp(label: str) -> tuple[str, str]:
    v = label.casefold()
    if "shellitem target" in v or "shellitem_" in v:
        return "TARGET_METADATA", "Thời gian đối tượng trong ShellItem, không tự chứng minh người dùng mở thư mục."
    if "bagmru key last write" in v:
        return "REGISTRY_UPDATE", "Registry key LastWrite; cần kiểm tra nguồn và MRUListEx."
    if "bagmru first interacted" in v or "bagmru last interacted" in v:
        return "INFERRED_INTERACTION", "Mốc tương tác suy luận từ BagMRU; cần kiểm tra điều kiện của công cụ."
    return "OTHER_OR_UNKNOWN", "Chưa phân loại chắc chắn."


def path_key(value: str) -> str:
    # Text grouping only. Do not resolve UNC, drive mapping, volume or object identity.
    return value.replace("/", "\\").rstrip("\\").casefold()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL,
            text=True, timeout=3
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return "not available"


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "results/case01_shellbags_events.csv")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--report", type=Path, default=ROOT / "analysis/thi-timeline/case01_shellbags_dfir_review_generated.md")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing previously generated output files")
    args = parser.parse_args(argv)

    input_file = args.input.resolve()
    if not input_file.is_file():
        print(f"ERROR: input CSV does not exist: {input_file}", file=sys.stderr)
        return 2

    with input_file.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            print("ERROR: input CSV has no header", file=sys.stderr)
            return 2
        rows = list(reader)
    if not rows:
        print("ERROR: input CSV contains no events", file=sys.stderr)
        return 2

    audited: list[dict] = []
    validation_errors: list[str] = []
    warnings: list[str] = []
    seen_ids: Counter[str] = Counter()

    for record_no, row in enumerate(rows, start=1):
        try:
            extra = read_extra(row, record_no)
            event_id = first_value(row, "event_id")
            if not ID_RE.fullmatch(event_id):
                raise ValueError(f"CSV record #{record_no}: missing/invalid CASE01 ShellBags event_id: {event_id!r}")
            seen_ids[event_id.upper()] += 1
            case = first_value(row, "case_id") or str(extra.get("case_id") or "").strip()
            if case and case.upper() != "CASE01":
                raise ValueError(f"CSV record #{record_no}: wrong case_id: {case!r}")
            artifact = first_value(row, "artifact_source", "artifact_type")
            if artifact.casefold().replace("_", "") not in ("shellbags", "shellbag"):
                raise ValueError(f"CSV record #{record_no}: expected ShellBags artifact, got {artifact!r}")
            time_raw = first_value(row, "timestamp_utc", "timestamp", "datetime")
            dt = parse_aware_timestamp(time_raw, record_no)
            label = first_value(row, "timestamp_desc", "timestamp_type") or str(extra.get("timestamp_type") or "")
            if not label:
                raise ValueError(f"CSV record #{record_no}: missing timestamp semantics (timestamp_desc/type)")
            path = first_value(row, "object_path", "target_path")
            if not path:
                raise ValueError(f"CSV record #{record_no}: missing object_path/target_path")
            source_file = first_value(row, "source_file")
            ref = first_value(row, "evidence_reference") or str(extra.get("evidence_reference") or "").strip()
            if not source_file:
                warnings.append(f"CSV record #{record_no}: source_file missing")
            if not ref:
                warnings.append(f"CSV record #{record_no}: evidence_reference unavailable in input")
            category, meaning = kind_of_timestamp(label)
            if category == "OTHER_OR_UNKNOWN":
                warnings.append(f"CSV record #{record_no}: unknown timestamp label {label!r}")
            audited.append({
                "event_id": event_id, "case_id": "CASE01", "artifact_source": artifact,
                "timestamp": dt.isoformat(), "timestamp_label": label,
                "timestamp_category": category, "forensic_interpretation": meaning,
                "object_path": path, "source_file": source_file,
                "evidence_reference": ref, "source_csv_record": record_no,
                "review_status": "NEEDS_CONTEXT", "is_direct_user_action": "NO",
                "_key": path_key(path), "_parsed": dt,
            })
        except ValueError as exc:
            validation_errors.append(str(exc))

    duplicate_ids = {event_id: n for event_id, n in seen_ids.items() if n > 1}
    validation_errors.extend(f"Duplicate event_id {eid}: {count} occurrences" for eid, count in duplicate_ids.items())
    if validation_errors:
        print(f"ERROR: {len(validation_errors)} validation error(s). No output written.", file=sys.stderr)
        for msg in validation_errors[:30]:
            print("  -", msg, file=sys.stderr)
        if len(validation_errors) > 30:
            print(f"  ... and {len(validation_errors)-30} more", file=sys.stderr)
        return 2

    groups = defaultdict(list)
    for row in audited:
        groups[row["_key"]].append(row)
    group_rows = []
    for group in groups.values():
        times = [r["_parsed"] for r in group]
        group_rows.append({
            "object_path": group[0]["object_path"],
            "event_count": len(group),
            "timestamp_categories": "; ".join(sorted({r["timestamp_category"] for r in group})),
            "timestamp_labels": "; ".join(sorted({r["timestamp_label"] for r in group})),
            "earliest_utc": min(times).isoformat(),
            "latest_utc": max(times).isoformat(),
            "event_ids": "; ".join(r["event_id"] for r in group),
            "source_csv_records": "; ".join(str(r["source_csv_record"]) for r in group),
            "evidence_references": "; ".join(sorted({r["evidence_reference"] for r in group if r["evidence_reference"]})),
            "interpretation": "Object/path context only, not a count of user folder openings",
        })
    group_rows.sort(key=lambda r: (-r["event_count"], r["object_path"].casefold()))

    output_dir = args.output_dir.resolve()
    report = args.report.resolve()
    audit_file = output_dir / "case01_shellbags_timestamp_audit.csv"
    context_file = output_dir / "case01_shellbags_path_context.csv"
    files = [audit_file, context_file, report]
    if len(set(files)) != len(files) or input_file in files:
        print("ERROR: input/output path collision", file=sys.stderr)
        return 2
    existing = [str(path) for path in files if path.exists()]
    if existing and not args.overwrite:
        print("ERROR: output already exists; use --overwrite after reviewing it:\n" + "\n".join(existing), file=sys.stderr)
        return 2

    output_dir.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    audit_cols = ["event_id", "case_id", "artifact_source", "timestamp", "timestamp_label",
                  "timestamp_category", "forensic_interpretation", "object_path", "source_file",
                  "evidence_reference", "source_csv_record", "review_status", "is_direct_user_action"]
    context_cols = ["object_path", "event_count", "timestamp_categories", "timestamp_labels",
                    "earliest_utc", "latest_utc", "event_ids", "source_csv_records",
                    "evidence_references", "interpretation"]
    write_csv(audit_file, audited, audit_cols)
    write_csv(context_file, group_rows, context_cols)

    by_type = Counter(r["timestamp_category"] for r in audited)
    generated_at = datetime.now(timezone.utc).isoformat()
    cmd = "python analysis/thi-timeline/analyze_case01_shellbags_week2.py --overwrite"
    lines = [
        "# CASE01 ShellBags – DFIR review (generated)", "",
        "> **Object-context audit only.** Not validated user-activity findings.", "",
        "## Reproducibility", "",
        f"- Input CSV: `{input_file.as_posix()}`",
        f"- Input SHA-256: `{file_sha256(input_file)}`",
        f"- Git HEAD at run: `{git_commit()}`",
        f"- Generated UTC: `{generated_at}`",
        f"- Suggested command (from repo root): `{cmd}`",
        "- Input supports pre-schema-v2 fields. `case_id=CASE01` is inferred from valid event IDs when absent.",
        "- `source_csv_record` is a *logical CSV record number*, not evidence hive offset or physical line number.",
        "", "## Timestamp categories (calculated from current input)", "",
        "| Category | Events |", "|---|---:|",
    ]
    for key in ("TARGET_METADATA", "REGISTRY_UPDATE", "INFERRED_INTERACTION", "OTHER_OR_UNKNOWN"):
        lines.append(f"| {key} | {by_type[key]} |")
    lines += ["", f"- Total events: **{len(audited)}**", f"- Distinct path-text groups: **{len(group_rows)}**",
              f"- Warnings: **{len(warnings)}** (non-fatal; examples below)", "",
              "## Prominent path groups", "", "| Path | Events |", "|---|---:|"]
    for group in group_rows[:10]:
        safe_path = group["object_path"].replace("|", "\\|")
        lines.append(f"| `{safe_path}` | {group['event_count']} |")
    lines += ["", "## Analysis limits", "",
              "- ShellItem target MAC timestamps are object metadata, not direct folder-opening times.",
              "- BagMRU inferred interactions and key LastWrite require source-hive / MRU context.",
              "- Path grouping compares strings only; does not equate mapped drives with UNC shares.",
              "- Do not merge two distinct timestamp semantics into one activity event.",
              "- Historical prototype 6,063/452 counts are NOT recomputed by this script. Use the separate candidate-review report.",
              "- Provenance missing in the source CSV remains missing; never invent an evidence reference.",
              "", "## Non-fatal warnings (first 15)", ""]
    lines += [f"- {msg}" for msg in warnings[:15]] or ["- None"]
    lines += ["", "## Next steps", "",
              "- Compare selected event IDs/CSV record numbers with Phúc's source evidence notes.",
              "- Keep object context separate from independently supported activity candidates.",
              "- Coordinate engine changes with Quyên rather than editing shared files concurrently.", ""]
    report.write_text("\n".join(lines), encoding="utf-8")

    print("=== CASE01 SHELLBAGS AUDIT ===")
    print("Input events:", len(audited))
    print("Distinct path groups:", len(group_rows))
    for k in ("TARGET_METADATA", "REGISTRY_UPDATE", "INFERRED_INTERACTION", "OTHER_OR_UNKNOWN"):
        print(k + ":", by_type[k])
    print("Warnings:", len(warnings), "(non-fatal)")
    for msg in warnings[:5]:
        print("  WARNING:", msg)
    print("Saved:", audit_file, context_file, report, sep="\n  ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
