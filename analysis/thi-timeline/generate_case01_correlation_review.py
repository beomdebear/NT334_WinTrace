#!/usr/bin/env python3
"""Generate reproducible CASE01 first-pass correlation review from CSVs.

Reads the legacy 452-pair review CSV and optional raw ShellBags events CSV.
Does not change the shared correlation engine or schema. The output is NOT
validated investigative findings; it is a reproducible review of candidates.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ID_RE = re.compile(r"^CASE01-SB\d+$", re.IGNORECASE)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                       stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
    except (OSError, subprocess.SubprocessError):
        return "not available"


def parse_utc(value: str, record_no: int, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"CSV record #{record_no}: bad {field}: {value!r}") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"CSV record #{record_no}: {field} lacks timezone: {value!r}")
    return dt.astimezone(timezone.utc)


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"CSV missing header: {path}")
        return list(reader)


def canonical_path(path: str) -> str:
    # Text equality only; does not equate UNC and mapped drives.
    return (path or "").replace("/", "\\").rstrip("\\").casefold()


def source_index(event_csv: Path) -> dict[str, tuple[int, dict]]:
    if not event_csv.is_file():
        raise FileNotFoundError(f"Missing events CSV: {event_csv}")
    index = {}
    for i, row in enumerate(read_csv(event_csv), start=1):
        eid = (row.get("event_id") or "").strip()
        if not ID_RE.fullmatch(eid):
            raise ValueError(f"Events CSV record #{i}: invalid id {eid!r}")
        if eid in index:
            raise ValueError(f"Events CSV duplicate id {eid}")
        index[eid] = (i, row)
    return index


def reference(row: dict) -> str:
    direct = (row.get("evidence_reference") or "").strip()
    if direct:
        return direct
    raw = row.get("extra_attributes") or ""
    if raw:
        import json
        try:
            extras = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError(f"Malformed extra_attributes for {row.get('event_id')}: {exc}") from exc
        if not isinstance(extras, dict):
            raise ValueError(f"Non-object extra_attributes for {row.get('event_id')}")
        return str(extras.get("evidence_reference") or "")
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-csv", type=Path, default=ROOT / "results/case01_candidates_review.csv")
    parser.add_argument("--events-csv", type=Path, default=ROOT / "results/case01_shellbags_events.csv")
    parser.add_argument("--report", type=Path, default=ROOT / "analysis/thi-timeline/case01_correlation_review_week2_generated.md")
    parser.add_argument("--enriched-csv", type=Path, default=ROOT / "results/case01_candidates_review_enriched.csv")
    parser.add_argument("--raw-findings", type=Path, default=None,
                        help="Optional original all-pairs CSV containing matched_rules; used to recompute original counts")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)

    try:
        review_path = args.review_csv.resolve()
        events_path = args.events_csv.resolve()
        rows = read_csv(review_path)
        source = source_index(events_path)
        if not rows:
            raise ValueError("Candidate-review CSV has no records")
        required = {"event_a", "event_b", "time_a", "time_b", "timestamp_desc_a", "timestamp_desc_b", "target_path", "matched_rules"}
        if not required.issubset(rows[0]):
            raise ValueError(f"Candidate CSV missing columns: {sorted(required-set(rows[0]))}")
        enriched = []
        invalid = []
        for i, row in enumerate(rows, start=1):
            try:
                a_id, b_id = row["event_a"].strip(), row["event_b"].strip()
                if not ID_RE.fullmatch(a_id) or not ID_RE.fullmatch(b_id):
                    raise ValueError(f"invalid IDs {a_id!r}/{b_id!r}")
                if a_id not in source or b_id not in source:
                    raise ValueError(f"cannot find event in source CSV: {a_id} or {b_id}")
                ta, tb = parse_utc(row["time_a"], i, "time_a"), parse_utc(row["time_b"], i, "time_b")
                if not row["target_path"].strip():
                    raise ValueError("missing target_path")
                a_rec, a_src = source[a_id]
                b_rec, b_src = source[b_id]
                enriched.append({
                    **row, "case_id": "CASE01", "timestamp_timezone": "UTC",
                    "review_csv_record": i, "event_a_source_csv_record": a_rec,
                    "event_b_source_csv_record": b_rec,
                    "event_a_evidence_reference": reference(a_src),
                    "event_b_evidence_reference": reference(b_src),
                    "_same_time": ta == tb,
                    "_path_key": canonical_path(row["target_path"]),
                })
            except (ValueError, KeyError) as exc:
                invalid.append(f"Candidate record #{i}: {exc}")
        if invalid:
            raise ValueError(f"{len(invalid)} invalid candidate(s). First errors:\n  " + "\n  ".join(invalid[:20]))

        metric = {
            "pairs": len(enriched),
            "distinct_paths": len({r["_path_key"] for r in enriched}),
            "equal_times": sum(r["_same_time"] for r in enriched),
            "metadata_pairs": sum(r["timestamp_desc_a"].casefold().startswith("shellitem target")
                                  and r["timestamp_desc_b"].casefold().startswith("shellitem target") for r in enriched),
            "bagmru_pairs": sum("bagmru" in r["timestamp_desc_a"].casefold()
                                or "bagmru" in r["timestamp_desc_b"].casefold() for r in enriched),
        }
        original = None
        if args.raw_findings is not None:
            raw_path = args.raw_findings.resolve()
            raw_rows = read_csv(raw_path)
            if raw_rows and "matched_rules" not in raw_rows[0]:
                raise ValueError("Raw findings CSV lacks matched_rules")
            original = Counter()
            for r in raw_rows:
                rules = sorted(set(re.findall(r"R\d\d", r.get("matched_rules", ""))))
                original["+".join(rules) or "NO_RULE"] += 1

        report_path = args.report.resolve()
        output_path = args.enriched_csv.resolve()
        if report_path == output_path or review_path in (report_path, output_path) or events_path in (report_path, output_path):
            raise ValueError("Input/output path collision")
        if not args.overwrite and (report_path.exists() or output_path.exists()):
            raise ValueError("Output exists; use --overwrite after reviewing older results")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        columns = list(rows[0].keys()) + ["case_id", "timestamp_timezone", "review_csv_record",
                "event_a_source_csv_record", "event_b_source_csv_record",
                "event_a_evidence_reference", "event_b_evidence_reference"]
        with output_path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(enriched)

        lines = [
            "# CASE01 – Correlation candidate first-pass review (generated)", "",
            "> This document reviews candidate *pairs*. It is not validation of user actions or correlation precision.", "",
            "## Data lineage and reproducibility", "",
            f"- Candidate input: `{review_path.as_posix()}`",
            f"- Candidate SHA-256: `{sha256(review_path)}`",
            f"- Source events: `{events_path.as_posix()}`",
            f"- Events SHA-256: `{sha256(events_path)}`",
            f"- Git HEAD: `{git_commit()}`",
            f"- Generated UTC: `{datetime.now(timezone.utc).isoformat()}`",
            "- Regenerate (repo root): `python analysis/thi-timeline/generate_case01_correlation_review.py --overwrite`",
            "- Candidate case inferred from `CASE01-SB...` identifiers; source-record numbers refer to logical CSV rows, not original forensic hive offsets.",
            "- `+00:00` timestamps are parsed as timezone-aware UTC. Timezone of original evidence must be verified separately.",
            "", "## Statistics calculated from candidate input", "",
            "| Metric | Value |", "|---|---:|",
            f"| First-pass review pairs | {metric['pairs']} |",
            f"| Distinct path strings | {metric['distinct_paths']} |",
            f"| Pairs with equal timestamps | {metric['equal_times']} |",
            f"| Both timestamps are ShellItem target metadata | {metric['metadata_pairs']} |",
            f"| At least one BagMRU timestamp | {metric['bagmru_pairs']} |", "",
        ]
        if original is not None:
            lines.extend(["## Original correlation snapshot recalculated from --raw-findings", "",
                          f"- Raw candidate pairs: **{sum(original.values())}**", ""])
            for k,v in sorted(original.items()):
                lines.append(f"- `{k}`: **{v}**")
            lines.append("")
        else:
            lines.extend(["## Prior baseline (not recalculated by this run)", "",
                          "The older 6,063-candidate prototype run is historical context only. "
                          "Provide `--raw-findings path/to/full_findings.csv` to recompute its counts; "
                          "do not present that historical count as a result of this run.", ""])
        lines.extend(["## Example pairs (source review CSV records)", "",
                      "| Pair | UTC times | Timestamp semantics | Source review record |",
                      "|---|---|---|---:|"])
        for r in enriched[:12]:
            lines.append(f"| `{r['event_a']}` / `{r['event_b']}` | {r['time_a']} / {r['time_b']} | "
                         f"{r['timestamp_desc_a']} / {r['timestamp_desc_b']} | {r['review_csv_record']} |")
        missing_refs = sum(not r["event_a_evidence_reference"] or not r["event_b_evidence_reference"] for r in enriched)
        lines += ["", "## Evidence and interpretive limits", "",
                  f"- Candidate pairs with at least one missing direct evidence reference: **{missing_refs}** (no references invented).",
                  "- `ShellItem Target Created/Modified/Accessed` are metadata of objects stored in ShellBags, not a sequence of user actions.",
                  "- R01 + R02 alone do not prove that a user opened, copied or modified a file.",
                  "- Network-share/drive-letter aliases require independent mapping/volume verification.",
                  "- Original ShellBags event IDs are preserved; do not delete source events to reduce pair counts.",
                  "- `case01_candidates_review_enriched.csv` links pairs to logical source CSV records and any evidence reference present in input.",
                  "- Confirm with Phúc's original artifact evidence before calling a correlation `verified`.", ""]
        report_path.write_text("\n".join(lines), encoding="utf-8")
        print("=== CASE01 CORRELATION REVIEW ===")
        for k,v in metric.items():
            print(k, v, sep=": ")
        print("Pairs missing at least one evidence_reference:", missing_refs)
        print("Saved:", output_path, report_path, sep="\n  ")
        return 0
    except (FileNotFoundError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
