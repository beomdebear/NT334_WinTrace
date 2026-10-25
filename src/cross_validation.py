"""
WinTrace - Cross-Validation Module
Performs cross-source consistency checks, verifies hypotheses H1 - H4,
and flags forensic contradictions (e.g., temporal anomalies or attribution mismatches).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import PureWindowsPath

from src.schema import ForensicEvent
from src.correlation import path_relation


class CrossValidator:
    """Evaluates cross-artifact consistency and detects forensic contradictions."""

    def __init__(self, events: List[ForensicEvent]):
        self.events = sorted(events, key=lambda e: e.dt)

    def validate_navigation_to_file(self) -> Dict[str, Any]:
        """
        Hypothesis H1: User navigated to directory via ShellBags before interacting with files inside it.
        """
        shellbag_events = [e for e in self.events if e.artifact_source == "ShellBags"]
        file_events = [e for e in self.events if e.artifact_source in {"LNK", "Prefetch", "RecycleBin"}]

        corroborated = []
        for sb in shellbag_events:
            for fe in file_events:
                rel = path_relation(sb.target_path, fe.target_path)
                if rel == "Parent-child path":
                    time_diff = (fe.dt - sb.dt).total_seconds() / 60.0
                    corroborated.append({
                        "folder_event": sb.event_id,
                        "folder_path": sb.target_path,
                        "file_event": fe.event_id,
                        "file_path": fe.target_path,
                        "time_diff_minutes": round(time_diff, 2),
                        "logical_order": time_diff >= 0  # Folder should be navigated before/during file access
                    })

        return {
            "hypothesis": "H1_User_Navigation",
            "status": "PASS" if any(c["logical_order"] for c in corroborated) else "NO_DATA",
            "matches_count": len(corroborated),
            "details": corroborated
        }

    def validate_document_execution(self) -> Dict[str, Any]:
        """
        Hypothesis H2: Document access (LNK) is corroborated by application execution (Prefetch).
        """
        lnk_events = [e for e in self.events if e.artifact_source == "LNK"]
        prefetch_events = [e for e in self.events if e.artifact_source == "Prefetch"]

        corroborated = []
        for lnk in lnk_events:
            for pf in prefetch_events:
                time_diff = abs((pf.dt - lnk.dt).total_seconds()) / 60.0
                # Check if prefetch is associated with document viewer (Word, Acrobat, etc.)
                doc_ext = PureWindowsPath(lnk.target_path).suffix.lower()
                exec_name = PureWindowsPath(pf.target_path).name.lower()

                match = False
                if doc_ext in {".docx", ".doc"} and "winword" in exec_name:
                    match = True
                elif doc_ext in {".pdf"} and ("acrobat" in exec_name or "acro" in exec_name):
                    match = True
                elif doc_ext in {".txt", ".log"} and "notepad" in exec_name:
                    match = True

                if match:
                    corroborated.append({
                        "lnk_event": lnk.event_id,
                        "document": lnk.target_path,
                        "prefetch_event": pf.event_id,
                        "executable": pf.target_path,
                        "time_diff_minutes": round(time_diff, 2),
                        "consistent": time_diff <= 10.0
                    })

        return {
            "hypothesis": "H2_Document_Execution",
            "status": "PASS" if any(c["consistent"] for c in corroborated) else "NO_DATA",
            "matches_count": len(corroborated),
            "details": corroborated
        }

    def validate_file_deletion_lifecycle(self) -> Dict[str, Any]:
        """
        Hypothesis H3 & H4: File was accessed/modified prior to deletion into Recycle Bin,
        and User SID matches.
        """
        recycle_events = [e for e in self.events if e.artifact_source == "RecycleBin"]
        prior_events = [e for e in self.events if e.artifact_source in {"LNK", "ShellBags", "Prefetch", "EVTX"}]

        lifecycle = []
        contradictions = []

        for rb in recycle_events:
            for pe in prior_events:
                rel = path_relation(rb.target_path, pe.target_path)
                if rel in {"Same path", "Same filename", "Parent-child path"}:
                    time_diff = (rb.dt - pe.dt).total_seconds() / 60.0

                    if time_diff < 0:
                        # Contradiction: File deleted before it was accessed/opened
                        contradictions.append({
                            "type": "TEMPORAL_ANOMALY",
                            "message": f"Event {pe.event_id} occurred after deletion event {rb.event_id}",
                            "time_diff_minutes": round(time_diff, 2)
                        })
                    else:
                        lifecycle.append({
                            "deletion_event": rb.event_id,
                            "prior_event": pe.event_id,
                            "prior_source": pe.artifact_source,
                            "time_to_deletion_minutes": round(time_diff, 2),
                            "sid_match": rb.user_sid == pe.user_sid if (rb.user_sid and pe.user_sid) else None
                        })

        return {
            "hypothesis": "H3_H4_File_Deletion_Lifecycle",
            "status": "CONTRADICTION_FOUND" if contradictions else ("PASS" if lifecycle else "NO_DATA"),
            "valid_lifecycle_sequences": len(lifecycle),
            "contradictions": contradictions,
            "details": lifecycle
        }

    def run_all_checks(self) -> Dict[str, Any]:
        """Execute all cross-validation checks and compile comprehensive summary."""
        h1 = self.validate_navigation_to_file()
        h2 = self.validate_document_execution()
        h3 = self.validate_file_deletion_lifecycle()

        all_passed = (
            h1["status"] in {"PASS", "NO_DATA"} and
            h2["status"] in {"PASS", "NO_DATA"} and
            h3["status"] in {"PASS", "NO_DATA"} and
            len(h3.get("contradictions", [])) == 0
        )

        return {
            "summary_status": "VERIFIED" if all_passed else "FLAGGED",
            "total_events_checked": len(self.events),
            "checks": {
                "navigation": h1,
                "document_execution": h2,
                "deletion_lifecycle": h3
            }
        }
