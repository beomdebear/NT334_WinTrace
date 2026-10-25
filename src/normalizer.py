"""
WinTrace - Plaso Data Normalization Module
Transforms raw Plaso output (CSV / JSON Lines) into standardized ForensicEvent records
matching docs/event_schema.md.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import csv
import json
import re

from src.schema import ForensicEvent, normalize_windows_path, parse_iso_utc


class PlasoNormalizer:
    """Normalizes raw Plaso records into unified forensic events."""

    @staticmethod
    def detect_artifact_source(parser: str, source: str, source_long: str, message: str) -> str:
        """Map heterogeneous Plaso indicators to standardized artifact categories."""
        combined = f"{parser} {source} {source_long} {message}".lower()
        if "shellbag" in combined or "bagmru" in combined:
            return "ShellBags"
        if "prefetch" in combined:
            return "Prefetch"
        if "lnk" in combined or "shortcut" in combined:
            return "LNK"
        if "recycle" in combined or "$i" in combined:
            return "RecycleBin"
        if "winevt" in combined or "eventlog" in combined:
            return "EVTX"
        if "mft" in combined or "ntfs" in combined:
            return "NTFS_MFT"
        return "Generic"

    @staticmethod
    def extract_windows_path(message: str, display_name: str) -> str:
        """Extract referenced target object path from raw Plaso message or display name."""
        # Check for explicit "Path: ..." or "[C:\...]" patterns
        path_patterns = [
            r"Path:\s*([a-zA-Z]:\\[^\s,\]]+)",
            r"\[([a-zA-Z]:\\[^\]]+)\]",
            r"Object Name:\s*([a-zA-Z]:\\[^\s,]+)",
            r"Deleted file:\s*([a-zA-Z]:\\[^\s,]+)",
            r"New Process Name:\s*([a-zA-Z]:\\[^\s,]+)",
            r"([a-zA-Z]:\\[A-Za-z0-9_\-\.\\]+)"
        ]
        for pattern in path_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return normalize_windows_path(match.group(1))

        # Fallback to display_name if valid path
        if re.match(r"^[a-zA-Z]:\\", display_name):
            return normalize_windows_path(display_name)

        return ""

    @staticmethod
    def extract_user_info(message: str, display_name: str) -> tuple[Optional[str], Optional[str]]:
        """Extract username and User SID from event messages and path hints."""
        username = None
        user_sid = None

        user_match = re.search(r"User:\s*([A-Za-z0-9_\-]+)", message, re.IGNORECASE)
        if user_match:
            username = user_match.group(1)

        sid_match = re.search(r"(S-1-5-21-[0-9\-]+)", message + " " + display_name)
        if sid_match:
            user_sid = sid_match.group(1)

        # Infer user from path if present (e.g. C:\Users\<Username>\...)
        if not username:
            path_user_match = re.search(r"C:\\Users\\([^\\]+)\\", display_name + " " + message, re.IGNORECASE)
            if path_user_match and path_user_match.group(1).lower() not in {"public", "all users", "default"}:
                username = path_user_match.group(1)

        return username, user_sid

    @staticmethod
    def extract_extra_attributes(message: str, artifact_source: str) -> Dict[str, Any]:
        """Extract artifact-specific metadata into a clean dictionary."""
        extra: Dict[str, Any] = {}

        # Run count for Prefetch
        if artifact_source == "Prefetch":
            run_match = re.search(r"Executed (\d+) times", message, re.IGNORECASE)
            if run_match:
                extra["run_count"] = int(run_match.group(1))
            hash_match = re.search(r"Hash:\s*(0x[A-Fa-f0-9]+|[A-Fa-f0-9]{8})", message)
            if hash_match:
                extra["prefetch_hash"] = hash_match.group(1)

        # Volume serial and size
        if artifact_source == "LNK":
            vol_match = re.search(r"Volume serial:\s*(0x[A-Fa-f0-9]+)", message, re.IGNORECASE)
            if vol_match:
                extra["volume_serial"] = vol_match.group(1)

        # Recycle bin size
        if artifact_source == "RecycleBin":
            size_match = re.search(r"Original size:\s*(\d+)", message, re.IGNORECASE)
            if size_match:
                extra["original_size"] = int(size_match.group(1))

        # Event ID & Logon Type
        if artifact_source == "EVTX":
            evt_id_match = re.search(r"\[(\d+)\s*/", message)
            if evt_id_match:
                extra["event_id"] = int(evt_id_match.group(1))
            logon_match = re.search(r"LogonType:\s*(\d+)", message)
            if logon_match:
                extra["logon_type"] = int(logon_match.group(1))
            mask_match = re.search(r"Access Mask:\s*(0x[0-9a-fA-F]+)", message)
            if mask_match:
                extra["access_mask"] = mask_match.group(1)

        return extra

    @classmethod
    def normalize_record(cls, raw_row: Dict[str, str], index: int) -> ForensicEvent:
        """Convert a single raw Plaso row into a standardized ForensicEvent."""
        event_id = f"EVT-{index:04d}"

        # Parse timestamp
        raw_time = raw_row.get("datetime") or raw_row.get("timestamp") or ""
        dt = parse_iso_utc(raw_time)
        iso_timestamp = dt.isoformat()

        timestamp_desc = raw_row.get("timestamp_desc", "Unknown")
        parser = raw_row.get("parser", "generic")
        source = raw_row.get("source", "")
        source_long = raw_row.get("source_long", "")
        message = raw_row.get("message", "").strip()
        display_name = raw_row.get("display_name", "")

        artifact_source = cls.detect_artifact_source(parser, source, source_long, message)
        target_path = cls.extract_windows_path(message, display_name)
        username, user_sid = cls.extract_user_info(message, display_name)
        extra_attrs = cls.extract_extra_attributes(message, artifact_source)

        return ForensicEvent(
            event_id=event_id,
            timestamp=iso_timestamp,
            timestamp_desc=timestamp_desc,
            artifact_source=artifact_source,
            source_file=normalize_windows_path(display_name),
            target_path=target_path,
            message=message,
            data_type=f"plaso:{parser}",
            parser=parser,
            user_sid=user_sid,
            username=username,
            confidence_level="HIGH" if artifact_source != "Generic" else "MEDIUM",
            extra_attributes=extra_attrs
        )

    @classmethod
    def normalize_file(cls, input_path: str) -> List[ForensicEvent]:
        """Read a raw Plaso CSV file and normalize all records."""
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        events: List[ForensicEvent] = []
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            idx = 1
            for row in reader:
                try:
                    event = cls.normalize_record(row, idx)
                    events.append(event)
                    idx += 1
                except Exception as e:
                    # Skip malformed lines while reporting
                    print(f"Warning: Skipping line {idx} due to error: {e}")
        return events
