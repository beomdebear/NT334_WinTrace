"""
WinTrace - Timeline Parser & Targeted Filtering Module
Parses Plaso psort output (CSV / JSON) into standardized ForensicEvent objects
and provides forensic targeted filtering.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
import csv
import json

from src.schema import ForensicEvent, normalize_windows_path, parse_iso_utc


def map_plaso_source_to_artifact(source: str, source_long: str, data_type: str) -> str:
    """Map Plaso's source/data_type to WinTrace standard artifact name."""
    s = (source + " " + source_long + " " + data_type).lower()
    if "shellbag" in s or "bagmru" in s:
        return "ShellBags"
    if "prefetch" in s:
        return "Prefetch"
    if "lnk" in s or "shortcut" in s:
        return "LNK"
    if "recycle" in s or "$i" in s:
        return "RecycleBin"
    if "winevt" in s or "evtx" in s or "eventlog" in s:
        return "EVTX"
    if "mft" in s or "ntfs" in s:
        return "NTFS_MFT"
    return "Generic"


class TimelineParser:
    """Parses timeline files into normalized ForensicEvent collections."""

    @staticmethod
    def load_from_json(json_path: str) -> List[ForensicEvent]:
        """Load standardized events from a JSON file."""
        events: List[ForensicEvent] = []
        path = Path(json_path)
        if not path.exists():
            raise FileNotFoundError(f"Timeline file not found: {json_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data:
                events.append(ForensicEvent.from_dict(item))
        return events

    @staticmethod
    def load_from_csv(csv_path: str) -> List[ForensicEvent]:
        """Load events from a Plaso / WinTrace CSV file."""
        events: List[ForensicEvent] = []
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(f"Timeline CSV not found: {csv_path}")

        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            idx = 1
            for row in reader:
                # Handle standard WinTrace CSV format or Plaso psort format
                event_id = row.get("event_id", f"EVT-{idx:04d}")
                raw_time = row.get("timestamp") or row.get("datetime")
                if not raw_time:
                    continue

                # Parse timestamp to ISO UTC string
                dt = parse_iso_utc(raw_time)
                iso_time = dt.isoformat()

                timestamp_desc = row.get("timestamp_desc", "Unknown")
                artifact = row.get("artifact_source") or map_plaso_source_to_artifact(
                    row.get("source", ""),
                    row.get("source_long", ""),
                    row.get("data_type", "")
                )
                source_file = row.get("source_file", row.get("display_name", ""))
                target_path = row.get("target_path", row.get("filename", ""))
                message = row.get("message", row.get("desc", ""))
                data_type = row.get("data_type", "windows:timeline:event")
                parser = row.get("parser", "plaso")
                user_sid = row.get("user_sid")
                username = row.get("username")
                confidence = row.get("confidence_level", "MEDIUM")

                events.append(ForensicEvent(
                    event_id=event_id,
                    timestamp=iso_time,
                    timestamp_desc=timestamp_desc,
                    artifact_source=artifact,
                    source_file=source_file,
                    target_path=target_path,
                    message=message,
                    data_type=data_type,
                    parser=parser,
                    user_sid=user_sid,
                    username=username,
                    confidence_level=confidence
                ))
                idx += 1
        return events

    @staticmethod
    def export_to_json(events: List[ForensicEvent], output_path: str) -> None:
        """Export standardized events to JSON."""
        data = [e.to_dict() for e in events]
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def export_to_csv(events: List[ForensicEvent], output_path: str) -> None:
        """Export standardized events to CSV."""
        if not events:
            return
        fieldnames = [
            "event_id", "timestamp", "timestamp_desc", "artifact_source",
            "source_file", "target_path", "message", "data_type",
            "parser", "user_sid", "username", "confidence_level"
        ]
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for e in events:
                row = {k: getattr(e, k) for k in fieldnames}
                writer.writerow(row)


class TargetedFilter:
    """Targeted timeline filtering for focused forensic analysis."""

    @staticmethod
    def filter_by_time_range(
        events: List[ForensicEvent],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[ForensicEvent]:
        filtered = []
        for e in events:
            if start_time and e.dt < start_time:
                continue
            if end_time and e.dt > end_time:
                continue
            filtered.append(e)
        return filtered

    @staticmethod
    def filter_by_artifacts(
        events: List[ForensicEvent],
        artifacts: List[str]
    ) -> List[ForensicEvent]:
        art_set = {a.lower() for a in artifacts}
        return [e for e in events if e.artifact_source.lower() in art_set]

    @staticmethod
    def filter_by_path_keyword(
        events: List[ForensicEvent],
        keyword: str
    ) -> List[ForensicEvent]:
        kw = keyword.lower()
        return [
            e for e in events
            if kw in e.target_path.lower() or kw in e.source_file.lower() or kw in e.message.lower()
        ]

    @staticmethod
    def filter_by_user(
        events: List[ForensicEvent],
        username: Optional[str] = None,
        user_sid: Optional[str] = None
    ) -> List[ForensicEvent]:
        result = []
        for e in events:
            if username and e.username and username.lower() in e.username.lower():
                result.append(e)
            elif user_sid and e.user_sid and user_sid.lower() == e.user_sid.lower():
                result.append(e)
        return result
