"""
WinTrace - Plaso Data Normalization Module (v2)
Transforms raw Plaso output (CSV / JSON Lines) into standardized ForensicEvent records
matching docs/event_schema.md.

Changelog (Week 2):
- PlasoNormalizer now populates timestamp_type, evidence_reference, validation_status, case_id
- Added ShellBagsNormalizer to import ShellBags CSV (from Phúc's to_team_schema.py output)
- Added map_plaso_timestamp_type() for Plaso timestamp_desc → timestamp_type mapping
- Malformed records are counted and logged, not silently dropped
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import csv
import json
import re

from src.schema import ForensicEvent, normalize_windows_path, parse_iso_utc


# Mapping from Plaso timestamp_desc values to WinTrace timestamp_type codes
PLASO_TIMESTAMP_TYPE_MAP = {
    # Prefetch
    "Last Time Executed": "Prefetch_LastRun",
    "Previous Last Time Executed": "Prefetch_PreviousRun",
    # LNK
    "File Last Modification Time": "LNK_TargetModified",
    "File Creation Time": "LNK_TargetCreated",
    "File Last Access Time": "LNK_TargetAccessed",
    # EVTX
    "Event Generated Time": "EVTX_EventGenerated",
    "Creation Time": "EVTX_EventGenerated",
    # RecycleBin
    "File Deletion Time": "RecycleBin_DeletionTime",
    # ShellBags (via Plaso winreg parser)
    "Last Time Visited": "ShellBag_LastInteracted",
    # NTFS / MFT
    "Content Modification Time": "NTFS_SI_Modified",
    "File Created Time": "NTFS_SI_Created",
    "Last Access Time": "NTFS_SI_Accessed",
    "Entry Modification Time": "NTFS_SI_EntryModified",
}

# Mapping from ShellBags timestamp_type (from Phúc's sbecmd_to_findings.py)
SHELLBAGS_TIMESTAMP_DESC_MAP = {
    "ShellBag_LastInteracted": "BagMRU Last Interacted",
    "ShellBag_FirstInteracted": "BagMRU First Interacted",
    "ShellBag_KeyLastWrite": "BagMRU Key Last Write",
    "ShellItem_FolderCreated": "ShellItem Target Created",
    "ShellItem_FolderModified": "ShellItem Target Modified",
    "ShellItem_FolderAccessed": "ShellItem Target Accessed",
}


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
        if "jump_list" in combined or "automaticdestinations" in combined:
            return "JumpLists"
        return "Generic"

    @staticmethod
    def map_timestamp_type(timestamp_desc: str, artifact_source: str) -> str:
        """Map Plaso timestamp_desc to WinTrace timestamp_type code."""
        mapped = PLASO_TIMESTAMP_TYPE_MAP.get(timestamp_desc)
        if mapped:
            return mapped
        return "Generic"

    @staticmethod
    def extract_windows_path(message: str, display_name: str) -> str:
        """Extract referenced target object path from raw Plaso message or display name."""
        # Check for explicit "Path: ..." or "[C:\...]" patterns
        path_patterns = [
<<<<<<< HEAD
            r"Path:\s*([a-zA-Z]:\\[^,\]\r\n]+?)(?=\s+[A-Za-z]+(?:\s+[A-Za-z]+)?:|\s*$|\]|\r|\n)",
            r"\[([a-zA-Z]:\\[^\]]+)\]",
            r"Object Name:\s*([a-zA-Z]:\\[^,\]\r\n]+?)(?=\s+[A-Za-z]+(?:\s+[A-Za-z]+)?:|\s*$|\]|\r|\n)",
            r"Deleted file:\s*([a-zA-Z]:\\[^,\]\r\n]+?)(?=\s+[A-Za-z]+(?:\s+[A-Za-z]+)?:|\s*$|\]|\r|\n)",
            r"New Process Name:\s*([a-zA-Z]:\\[^,\]\r\n]+?)(?=\s+[A-Za-z]+(?:\s+[A-Za-z]+)?:|\s*$|\]|\r|\n)",
            r"([a-zA-Z]:\\[A-Za-z0-9_\-\.\\ ]+)"
=======
            r"Path:\s*(.*?)(?=\s+(?:Hash:|PID:|Volume serial:|Parent Process Name:)|$)",
            r"\[([a-zA-Z]:\\[^\]]+)\]",
            r"Object Name:\s*(.*?)(?=\s+(?:Access Mask:|Process:)|$)",
            r"Deleted file:\s*(.*?)(?=\s+(?:Original size:|$)|$)",
            r"New Process Name:\s*(.*?)(?=\s+(?:Parent Process Name:|PID:|User:)|$)",
            r"([a-zA-Z]:\\[A-Za-z0-9_\-\.\\]+)"
>>>>>>> a184b21b5b0bb50266b8d9b26d6dcd664706e970
        ]
        for pattern in path_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                candidate = match.group(1).strip().rstrip(",")
                if re.match(r"^[a-zA-Z]:\\", candidate):
                    return normalize_windows_path(candidate)

        # Fallback to display_name if valid path
        if re.match(r"^[a-zA-Z]:\\", display_name):
            return normalize_windows_path(display_name)

        return ""

    @staticmethod
    def extract_user_info(message: str, display_name: str) -> tuple:
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
    def normalize_record(cls, raw_row: Dict[str, str], index: int,
                         case_id: Optional[str] = None) -> ForensicEvent:
        """Convert a single raw Plaso row into a standardized ForensicEvent."""
        event_id = raw_row.get("event_id") or f"EVT-{index:04d}"

        # Parse timestamp
        raw_time = (
            raw_row.get("datetime")
            or raw_row.get("timestamp")
            or raw_row.get("timestamp_utc")
            or ""
        )
        dt = parse_iso_utc(raw_time)
        iso_timestamp = dt.isoformat()

        timestamp_desc = (
            raw_row.get("timestamp_desc")
            or raw_row.get("timestamp_type")
            or "Unknown"
        )
        parser = raw_row.get("parser", "generic")
        source = raw_row.get("source", "")
        source_long = raw_row.get("source_long", "")
        message = (raw_row.get("message") or raw_row.get("description") or "").strip()
        display_name = raw_row.get("display_name") or raw_row.get("source_file", "")
        artifact_hint = raw_row.get("artifact_source") or raw_row.get("artifact_type", "")
        target_hint = raw_row.get("target_path") or raw_row.get("object_path", "")

        artifact_source = artifact_hint or cls.detect_artifact_source(
            parser, source, source_long, message
        )
        target_path = target_hint or cls.extract_windows_path(message, display_name)
        username, user_sid = cls.extract_user_info(message, display_name)
        username = raw_row.get("username") or username
        user_sid = raw_row.get("user_sid") or user_sid
        extra_attrs = cls.extract_extra_attributes(message, artifact_source)
        raw_extra = raw_row.get("extra_attributes")
        if raw_extra:
            try:
                parsed_extra = json.loads(raw_extra)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid extra_attributes JSON: {exc}") from exc
            if not isinstance(parsed_extra, dict):
                raise ValueError("extra_attributes must contain a JSON object")
            extra_attrs = {**parsed_extra, **extra_attrs}
        for field in ("timestamp_type", "evidence_reference", "validation_status"):
            if raw_row.get(field):
                extra_attrs.setdefault(field, raw_row[field])

        # Week 2: Map timestamp_type
        timestamp_type = cls.map_timestamp_type(timestamp_desc, artifact_source)

        # Week 2: Build evidence_reference from Plaso source info
        evidence_reference = f"plaso:{parser} | display_name={display_name}" if display_name else None

        return ForensicEvent(
            event_id=event_id,
            timestamp=iso_timestamp,
            timestamp_desc=timestamp_desc,
            artifact_source=artifact_source,
            source_file=normalize_windows_path(display_name),
            target_path=target_path,
            message=message,
            data_type=raw_row.get("data_type") or f"plaso:{parser}",
            parser=parser or "generic",
            user_sid=user_sid,
            username=username,
<<<<<<< HEAD
            confidence_level="HIGH" if artifact_source != "Generic" else "MEDIUM",
            extra_attributes=extra_attrs,
            timestamp_type=timestamp_type,
            evidence_reference=evidence_reference,
            validation_status="unverified",
            case_id=case_id,
        )

    @classmethod
    def normalize_file(cls, input_path: str, case_id: Optional[str] = None) -> List[ForensicEvent]:
        """Read a raw Plaso CSV file and normalize all records.

        Returns a list of successfully normalized ForensicEvent objects.
        Malformed records are skipped with a warning printed to stdout.
        """
=======
            confidence_level=(
                raw_row.get("confidence_level")
                or raw_row.get("confidence")
                or ("HIGH" if artifact_source != "Generic" else "MEDIUM")
            ).upper(),
            extra_attributes=extra_attrs
        )

    @classmethod
    def normalize_file_with_report(
        cls, input_path: str, source_label: Optional[str] = None
    ) -> Tuple[List[ForensicEvent], List[Dict[str, Any]]]:
        """Read a raw Plaso CSV file and normalize all records."""
>>>>>>> a184b21b5b0bb50266b8d9b26d6dcd664706e970
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        events: List[ForensicEvent] = []
<<<<<<< HEAD
        skipped = 0
=======
        errors: List[Dict[str, Any]] = []
>>>>>>> a184b21b5b0bb50266b8d9b26d6dcd664706e970
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            idx = 1
            for row in reader:
                try:
<<<<<<< HEAD
                    event = cls.normalize_record(row, idx, case_id=case_id)
                    events.append(event)
                    idx += 1
                except Exception as e:
                    # Skip malformed lines while reporting
                    skipped += 1
                    print(f"Warning: Skipping line {idx} due to error: {e}")
        if skipped > 0:
            print(f"Total skipped records: {skipped}")
=======
                    event = cls.normalize_record(row, idx)
                    if source_label:
                        event.extra_attributes.setdefault("source_label", source_label)
                    events.append(event)
                    idx += 1
                except Exception as e:
                    errors.append({"record": idx, "error": str(e), "row": dict(row)})
                    idx += 1
        return events, errors

    @classmethod
    def normalize_file(cls, input_path: str) -> List[ForensicEvent]:
        """Read a raw Plaso CSV file and normalize all valid records."""
        events, _ = cls.normalize_file_with_report(input_path)
>>>>>>> a184b21b5b0bb50266b8d9b26d6dcd664706e970
        return events


class ShellBagsNormalizer:
    """Normalizes ShellBags CSV (output of Phúc's to_team_schema.py or
    case01_shellbags_events.csv) into ForensicEvent objects.

    This adapter handles the differences between ShellBags event format
    and the main Plaso pipeline format, specifically:
    - Extracts evidence_reference and validation_status from extra_attributes JSON
    - Maps timestamp_type from extra_attributes
    - Preserves BagMRU paths in target_path while also extracting drive paths
    """

    @classmethod
    def normalize_file(cls, input_path: str) -> List[ForensicEvent]:
        """Load ShellBags events from a team-schema CSV file.

        Expects columns matching the ForensicEvent schema:
            event_id, timestamp, timestamp_desc, artifact_source, source_file,
            target_path, message, data_type, parser, user_sid, username,
            confidence_level, extra_attributes

        The extra_attributes column should contain a JSON string with keys:
            timestamp_type, evidence_reference, validation_status
        """
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"ShellBags CSV not found: {input_path}")

        events: List[ForensicEvent] = []
        skipped = 0

        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for line_no, row in enumerate(reader, start=2):
                try:
                    event = cls._normalize_row(row)
                    events.append(event)
                except Exception as e:
                    skipped += 1
                    print(f"Warning: Skipping ShellBags line {line_no}: {e}")

        if skipped > 0:
            print(f"Total skipped ShellBags records: {skipped}")
        return events

    @classmethod
    def _normalize_row(cls, row: Dict[str, str]) -> ForensicEvent:
        """Convert a single ShellBags CSV row to ForensicEvent."""
        # Parse extra_attributes JSON to extract embedded fields
        extra_raw = row.get("extra_attributes", "")
        extra_dict: Dict[str, Any] = {}
        timestamp_type = None
        evidence_reference = None
        validation_status = None

        if extra_raw and extra_raw.strip():
            try:
                extra_dict = json.loads(extra_raw)
                timestamp_type = extra_dict.pop("timestamp_type", None)
                evidence_reference = extra_dict.pop("evidence_reference", None)
                validation_status = extra_dict.pop("validation_status", None)
            except json.JSONDecodeError:
                pass  # extra_attributes stays empty

        # Determine case_id from event_id prefix
        event_id = row.get("event_id", "")
        case_id = None
        if event_id.startswith("CASE01"):
            case_id = "CASE01"

        # Parse timestamp
        raw_time = row.get("timestamp", "")
        dt = parse_iso_utc(raw_time)
        iso_timestamp = dt.isoformat()

        return ForensicEvent(
            event_id=event_id,
            timestamp=iso_timestamp,
            timestamp_desc=row.get("timestamp_desc", "Unknown"),
            artifact_source=row.get("artifact_source", "ShellBags"),
            source_file=row.get("source_file", ""),
            target_path=row.get("target_path", ""),
            message=row.get("message", ""),
            data_type=row.get("data_type", "windows:registry:bagmru"),
            parser=row.get("parser", "sbecmd"),
            user_sid=row.get("user_sid") or None,
            username=row.get("username") or None,
            confidence_level=row.get("confidence_level", "MEDIUM"),
            extra_attributes=extra_dict,
            timestamp_type=timestamp_type,
            evidence_reference=evidence_reference,
            validation_status=validation_status,
            case_id=case_id,
        )
