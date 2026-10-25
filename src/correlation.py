"""
WinTrace - Forensic Event Correlation Engine
Implements rules R01 - R05 to discover meaningful forensic relationships between events.
"""

from datetime import datetime, timezone
from itertools import combinations
from pathlib import PureWindowsPath
from typing import List, Optional, Tuple, Dict, Any
import csv
import json

from src.schema import ForensicEvent, CorrelationFinding, parse_iso_utc, normalize_windows_path


def path_relation(path1: str, path2: str) -> Optional[str]:
    """
    Evaluate the relationship between two Windows paths.
    Returns: 'Same path', 'Parent-child path', or None.
    """
    if not path1 or not path2:
        return None

    # Handle cases where path is just a filename
    p1 = PureWindowsPath(normalize_windows_path(path1))
    p2 = PureWindowsPath(normalize_windows_path(path2))

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
    file_artifacts = {"LNK", "ShellBags", "RecycleBin", "NTFS_MFT"}

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

            matched_rules: List[str] = []
            score = 0
            explanations: List[str] = []

            # Rule R01: Temporal Proximity
            if delta_minutes <= self.window_minutes:
                matched_rules.append("R01")
                score += 20
                explanations.append(f"Events occurred within {delta_minutes:.1f}m (threshold {self.window_minutes}m)")

            # Rule R02: Object Association
            relation = path_relation(event_a.target_path, event_b.target_path)
            if relation:
                matched_rules.append("R02")
                score += 30
                explanations.append(f"Target object relationship: {relation}")

            # Rule R03: Cross-Artifact Support
            if event_a.artifact_source != event_b.artifact_source and (delta_minutes <= self.window_minutes or relation):
                matched_rules.append("R03")
                score += 30
                explanations.append(f"Corroborated across distinct sources: {event_a.artifact_source} <-> {event_b.artifact_source}")

            # Rule R04: Program-File Association
            if is_program_file_pair(event_a, event_b) or is_program_file_pair(event_b, event_a):
                if delta_minutes <= self.window_minutes or relation:
                    matched_rules.append("R04")
                    score += 20
                    explanations.append("Execution artifact directly correlates with document interaction")

            # Rule R05: Deletion Context
            is_deletion = (
                event_a.artifact_source == "RecycleBin" or "delete" in event_a.message.lower() or
                event_b.artifact_source == "RecycleBin" or "delete" in event_b.message.lower()
            )
            if is_deletion and (relation or delta_minutes <= (self.window_minutes * 2)):
                matched_rules.append("R05")
                score += 20
                explanations.append("Prior user/application interaction precedes file deletion activity")

            # Bonus: User attribution match
            if event_a.username and event_b.username and event_a.username.lower() == event_b.username.lower():
                score += 10
                explanations.append(f"Consistent user attribution: {event_a.username}")

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
                    explanation=" | ".join(explanations)
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
            "finding_id", "event_a_id", "event_b_id", "time_delta_minutes",
            "matched_rules", "confidence_score", "confidence_level",
            "event_a_desc", "event_b_desc", "explanation"
        ]
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for f in findings:
                row = f.to_dict()
                row["matched_rules"] = ";".join(row["matched_rules"])
                writer.writerow(row)
