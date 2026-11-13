"""
WinTrace - Forensic Event Correlation Engine (v2)
Implements rules R01 - R05 to discover meaningful forensic relationships between events.

Changelog (Week 2):
- CorrelationFinding now populates event_ids, evidence_references, investigation_note
- Added BagMRU path awareness via extract_drive_path_from_bagmru()
- path_relation() now handles ShellBags BagMRU paths
- Added timestamp_type-aware window adjustment
"""

from datetime import datetime, timezone
from itertools import combinations
from pathlib import PureWindowsPath
from typing import List, Optional, Tuple, Dict, Any
import csv
import json

from src.schema import (
    ForensicEvent,
    CorrelationFinding,
    parse_iso_utc,
    normalize_windows_path,
    extract_drive_path_from_bagmru,
)


# Timestamp types with lower precision (FAT = ±2 seconds)
LOW_PRECISION_TIMESTAMP_TYPES = {
    "ShellItem_FolderCreated",
    "ShellItem_FolderModified",
    "ShellItem_FolderAccessed",
}


def _is_bagmru_path(path: str) -> bool:
    """Check if a path looks like a BagMRU absolute path (starts with Desktop\\)."""
    if not path:
        return False
    normalized = normalize_windows_path(path)
    return normalized.lower().startswith("desktop\\")


def _extract_comparable_path(path: str) -> str:
    """Extract a filesystem-comparable path, handling BagMRU paths if needed."""
    if _is_bagmru_path(path):
        drive, relative = extract_drive_path_from_bagmru(path)
        if drive:
            return f"{drive}\\{relative}" if relative else drive
        return relative  # fallback to relative path without drive
    return path


def path_relation(path1: str, path2: str) -> Optional[str]:
    """
    Evaluate the relationship between two Windows paths.
    Handles both standard Windows paths and BagMRU paths.
    Returns: 'Same path', 'Parent-child path', 'Same filename', or None.
    """
    if not path1 or not path2:
        return None

    # Convert BagMRU paths to filesystem paths for comparison
    comparable1 = _extract_comparable_path(path1)
    comparable2 = _extract_comparable_path(path2)

    if not comparable1 or not comparable2:
        return None

    # Handle cases where path is just a filename
    p1 = PureWindowsPath(normalize_windows_path(comparable1))
    p2 = PureWindowsPath(normalize_windows_path(comparable2))

    a = tuple(p.casefold() for p in p1.parts)
    b = tuple(p.casefold() for p in p2.parts)

    if not a or not b:
        return None

    if a == b:
        return "Same path"

    # Parent-child check
    if len(a) < len(b) and b[:len(a)] == a:
        return "Parent-child path"
    if len(b) < len(a) and a[:len(b)] == b:
        return "Parent-child path"

    # Check if target file name matches the end of path
    if len(a) > 0 and len(b) > 0 and a[-1] == b[-1]:
        return "Same filename"

    return None


def is_program_file_pair(event_prog: ForensicEvent, event_file: ForensicEvent) -> bool:
    """Check if event_prog is an execution event and event_file is a file interaction event."""
    prog_artifacts = {"Prefetch", "Amcache", "EVTX"}
    file_artifacts = {"LNK", "ShellBags", "RecycleBin", "NTFS_MFT", "JumpLists"}

    is_prog = (
        event_prog.artifact_source in prog_artifacts or
        "execute" in event_prog.message.lower() or
        event_prog.target_path.lower().endswith(".exe")
    )
    is_file = (
        event_file.artifact_source in file_artifacts or
        any(event_file.target_path.lower().endswith(ext) for ext in [".docx", ".pdf", ".xlsx", ".txt", ".zip"])
    )

    if not (is_prog and is_file):
        return False

    # Check if prefetch references the file in extra_attributes
    referenced_files = event_prog.extra_attributes.get("referenced_files", [])
    for ref in referenced_files:
        if path_relation(ref, event_file.target_path):
            return True

    # General association if time is close and program can open that document
    exec_name = PureWindowsPath(event_prog.target_path).name.lower()
    doc_ext = PureWindowsPath(event_file.target_path).suffix.lower()

    office_exts = {".docx", ".doc", ".dotx"}
    if "winword" in exec_name and doc_ext in office_exts:
        return True
    if "excel" in exec_name and doc_ext in {".xlsx", ".xls", ".csv"}:
        return True
    if "notepad" in exec_name and doc_ext in {".txt", ".log", ".ini"}:
        return True

    return False


def _get_effective_window(event_a: ForensicEvent, event_b: ForensicEvent,
                          base_window: float) -> float:
    """Adjust correlation time window based on timestamp precision.

    FAT timestamps (ShellItem_Folder*) have ±2 second precision,
    so a slightly wider window may be appropriate.
    """
    a_type = event_a.timestamp_type or ""
    b_type = event_b.timestamp_type or ""

    if a_type in LOW_PRECISION_TIMESTAMP_TYPES or b_type in LOW_PRECISION_TIMESTAMP_TYPES:
        # Add a small buffer for FAT precision but don't exceed 2x the base window
        return min(base_window + 0.1, base_window * 2)

    return base_window


class CorrelationEngine:
    """Core correlation engine implementing forensic rules R01 - R05."""

    def __init__(self, window_minutes: float = 5.0):
        self.window_minutes = window_minutes

    def correlate(self, events: List[ForensicEvent]) -> List[CorrelationFinding]:
        findings: List[CorrelationFinding] = []
        finding_count = 1

        # Sort events chronologically
        sorted_events = sorted(events, key=lambda e: e.dt)

        for event_a, event_b in combinations(sorted_events, 2):
            delta_seconds = abs((event_a.dt - event_b.dt).total_seconds())
            delta_minutes = round(delta_seconds / 60.0, 2)

            # Adjust window based on timestamp precision
            effective_window = _get_effective_window(event_a, event_b, self.window_minutes)

            matched_rules: List[str] = []
            score = 0
            explanations: List[str] = []
            investigation_notes: List[str] = []

            # Rule R01: Temporal Proximity
            if delta_minutes <= effective_window:
                matched_rules.append("R01")
                score += 20
                explanations.append(f"Events occurred within {delta_minutes:.1f}m (threshold {effective_window}m)")

            # Rule R02: Object Association
            relation = path_relation(event_a.target_path, event_b.target_path)
            if relation:
                matched_rules.append("R02")
                score += 30
                explanations.append(f"Target object relationship: {relation}")

            # Rule R03: Cross-Artifact Support
            if event_a.artifact_source != event_b.artifact_source and (delta_minutes <= effective_window or relation):
                matched_rules.append("R03")
                score += 30
                explanations.append(f"Corroborated across distinct sources: {event_a.artifact_source} <-> {event_b.artifact_source}")

            # Rule R04: Program-File Association
            if is_program_file_pair(event_a, event_b) or is_program_file_pair(event_b, event_a):
                if delta_minutes <= effective_window or relation:
                    matched_rules.append("R04")
                    score += 20
                    explanations.append("Execution artifact directly correlates with document interaction")

            # Rule R05: Deletion Context
            is_deletion = (
                event_a.artifact_source == "RecycleBin" or "delete" in event_a.message.lower() or
                event_b.artifact_source == "RecycleBin" or "delete" in event_b.message.lower()
            )
            if is_deletion and (relation or delta_minutes <= (effective_window * 2)):
                matched_rules.append("R05")
                score += 20
                explanations.append("Prior user/application interaction precedes file deletion activity")

            # Bonus: User attribution match
            if event_a.username and event_b.username and event_a.username.lower() == event_b.username.lower():
                score += 10
                explanations.append(f"Consistent user attribution: {event_a.username}")

            # Week 2: Note if either event uses low-precision timestamp
            a_type = event_a.timestamp_type or ""
            b_type = event_b.timestamp_type or ""
            if a_type in LOW_PRECISION_TIMESTAMP_TYPES or b_type in LOW_PRECISION_TIMESTAMP_TYPES:
                investigation_notes.append("One or more events use FAT timestamps (±2s precision)")

            # Week 2: Note if either event is unverified
            a_status = event_a.validation_status or "unverified"
            b_status = event_b.validation_status or "unverified"
            if a_status != "verified" or b_status != "verified":
                investigation_notes.append(f"Validation status: {event_a.event_id}={a_status}, {event_b.event_id}={b_status}")

            # Filter candidates that matched at least 2 rules or high confidence
            if len(matched_rules) >= 2 or score >= 40:
                # Clamp score to 100
                score = min(score, 100)
                if score >= 80:
                    conf_level = "HIGH"
                elif score >= 50:
                    conf_level = "MEDIUM"
                else:
                    conf_level = "LOW"

                # Collect evidence references
                evidence_refs = []
                if event_a.evidence_reference:
                    evidence_refs.append(event_a.evidence_reference)
                if event_b.evidence_reference:
                    evidence_refs.append(event_b.evidence_reference)

                findings.append(CorrelationFinding(
                    finding_id=f"FIND-{finding_count:03d}",
                    event_a_id=event_a.event_id,
                    event_b_id=event_b.event_id,
                    event_a_desc=f"[{event_a.artifact_source}] {event_a.message}",
                    event_b_desc=f"[{event_b.artifact_source}] {event_b.message}",
                    time_delta_seconds=round(delta_seconds, 2),
                    time_delta_minutes=delta_minutes,
                    matched_rules=matched_rules,
                    confidence_score=score,
                    confidence_level=conf_level,
                    explanation=" | ".join(explanations),
                    event_ids=[event_a.event_id, event_b.event_id],
                    investigation_note=" | ".join(investigation_notes) if investigation_notes else None,
                    evidence_references=evidence_refs,
                ))
                finding_count += 1

        return findings

    @staticmethod
    def export_findings_json(findings: List[CorrelationFinding], output_path: str) -> None:
        """Export findings to a JSON file."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([f.to_dict() for f in findings], f, ensure_ascii=False, indent=2)

    @staticmethod
    def export_findings_csv(findings: List[CorrelationFinding], output_path: str) -> None:
        """Export findings to a CSV file."""
        if not findings:
            return
        fieldnames = [
            "finding_id", "event_a_id", "event_b_id", "event_ids",
            "time_delta_minutes", "matched_rules", "confidence_score",
            "confidence_level", "event_a_desc", "event_b_desc",
            "explanation", "investigation_note", "evidence_references",
        ]
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings:
                row = finding.to_dict()
                row["matched_rules"] = ";".join(row["matched_rules"])
                row["event_ids"] = ";".join(row["event_ids"])
                row["evidence_references"] = ";".join(row.get("evidence_references", []))
                # Remove fields not in fieldnames
                row = {k: v for k, v in row.items() if k in fieldnames}
                writer.writerow(row)
