"""
WinTrace - Plaso Data Normalization Module (v2)
Transforms raw Plaso output (CSV / JSON Lines) into standardized ForensicEvent records
matching docs/event_schema.md.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import csv
import json
import re

from src.schema import ForensicEvent, normalize_windows_path, parse_iso_utc


PLASO_TIMESTAMP_TYPE_MAP = {
    "Last Time Executed": "Prefetch_LastRun",
    "Previous Last Time Executed": "Prefetch_PreviousRun",
    "File Last Modification Time": "LNK_TargetModified",
    "File Creation Time": "LNK_TargetCreated",
    "File Last Access Time": "LNK_TargetAccessed",
    "Event Generated Time": "EVTX_EventGenerated",
    "Creation Time": "EVTX_EventGenerated",
    "File Deletion Time": "RecycleBin_DeletionTime",
    "Last Time Visited": "ShellBag_LastInteracted",
    "Content Modification Time": "NTFS_SI_Modified",
    "File Created Time": "NTFS_SI_Created",
    "Last Access Time": "NTFS_SI_Accessed",
    "Entry Modification Time": "NTFS_SI_EntryModified",
}

SHELLBAGS_TIMESTAMP_DESC_MAP = {
    "ShellBag_LastInteracted": "BagMRU Last Interacted",
    "ShellBag_FirstInteracted": "BagMRU First Interacted",
    "ShellBag_KeyLastWrite": "BagMRU Key Last Write",
    "ShellItem_FolderCreated": "ShellItem Target Created",
    "ShellItem_FolderModified": "ShellItem Target Modified",
    "ShellItem_FolderAccessed": "ShellItem Target Accessed",
}

PROVENANCE_FIELDS = ("timestamp_type", "evidence_reference", "validation_status", "case_id")


def _read_provenance(row: Dict[str, str], extra_attributes: Dict[str, Any]) -> Dict[str, Any]:
    return {field: row.get(field) or extra_attributes.get(field) for field in PROVENANCE_FIELDS}


def _legacy_case_id(event_id: str) -> Optional[str]:
    return "CASE01" if event_id.startswith("CASE01-") else None


class PlasoNormalizer:
    """Normalizes raw Plaso records into unified forensic events."""

    @staticmethod
    def detect_artifact_source(parser: str, source: str, source_long: str, message: str) -> str:
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
        mapped = PLASO_TIMESTAMP_TYPE_MAP.get(timestamp_desc)
        if mapped:
            return mapped
        return "Generic"

    @staticmethod
    def extract_windows_path(message: str, display_name: str) -> str:
        path_patterns = [
            r"Path:\s*(.*?)(?=\s+(?:Hash:|PID:|Volume serial:|Parent Process Name:)|$)",
            r"\[([a-zA-Z]:\\[^\]]+)\]",
            r"Object Name:\s*(.*?)(?=\s+(?:Access Mask:|Process:)|$)",
            r"Deleted file:\s*(.*?)(?=\s+(?:Original size:|$)|$)",
            r"New Process Name:\s*(.*?)(?=\s+(?:Parent Process Name:|PID:|User:)|$)",
            r"([a-zA-Z]:\\[A-Za-z0-9_\-\.\\]+)"
        ]
        for pattern in path_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                candidate = match.group(1).strip().rstrip(",")
                if re.match(r"^[a-zA-Z]:\\", candidate):
                    return normalize_windows_path(candidate)

        if re.match(r"^[a-zA-Z]:\\", display_name):
            return normalize_windows_path(display_name)
        return ""

    @staticmethod
    def extract_user_info(message: str, display_name: str) -> tuple:
        username = None
        user_sid = None

        user_match = re.search(r"User:\s*([A-Za-z0-9_\-]+)", message, re.IGNORECASE)
        if user_match:
            username = user_match.group(1)

        sid_match = re.search(r"(S-1-5-21-[0-9\-]+)", message + " " + display_name)
        if sid_match:
            user_sid = sid_match.group(1)

        if not username:
            path_user_match = re.search(r"C:\\Users\\([^\\]+)\\", display_name + " " + message, re.IGNORECASE)
            if path_user_match and path_user_match.group(1).lower() not in {"public", "all users", "default"}:
                username = path_user_match.group(1)

        return username, user_sid

    @staticmethod
    def extract_extra_attributes(message: str, artifact_source: str) -> Dict[str, Any]:
        extra: Dict[str, Any] = {}
        if artifact_source == "Prefetch":
            run_match = re.search(r"Executed (\d+) times", message, re.IGNORECASE)
            if run_match:
                extra["run_count"] = int(run_match.group(1))
            hash_match = re.search(r"Hash:\s*(0x[A-Fa-f0-9]+|[A-Fa-f0-9]{8})", message)
            if hash_match:
                extra["prefetch_hash"] = hash_match.group(1)

        if artifact_source == "LNK":
            vol_match = re.search(r"Volume serial:\s*(0x[A-Fa-f0-9]+)", message, re.IGNORECASE)
            if vol_match:
                extra["volume_serial"] = vol_match.group(1)

        if artifact_source == "RecycleBin":
            size_match = re.search(r"Original size:\s*(\d+)", message, re.IGNORECASE)
            if size_match:
                extra["original_size"] = int(size_match.group(1))

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
        event_id = raw_row.get("event_id") or f"EVT-{index:04d}"

        raw_time = (
            raw_row.get("datetime")
            or raw_row.get("timestamp")
            or raw_row.get("timestamp_utc")
            or ""
        )
        dt = parse_iso_utc(raw_time)
        iso_timestamp = dt.isoformat()

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
            
        provenance = _read_provenance(raw_row, extra_attrs)
        for field in PROVENANCE_FIELDS:
            if raw_row.get(field):
                extra_attrs.setdefault(field, raw_row[field])

        timestamp_type = provenance["timestamp_type"]
        timestamp_desc = (
            raw_row.get("timestamp_desc")
            or SHELLBAGS_TIMESTAMP_DESC_MAP.get(timestamp_type)
            or timestamp_type
            or "Unknown"
        )
        provenance["timestamp_type"] = timestamp_type or cls.map_timestamp_type(timestamp_desc, artifact_source)
        if not provenance["evidence_reference"] and display_name:
            provenance["evidence_reference"] = f"plaso:{parser} | display_name={display_name}"
        provenance["validation_status"] = provenance["validation_status"] or "unverified"
        provenance["case_id"] = provenance["case_id"] or case_id or _legacy_case_id(event_id)

        confidence_level = (
            raw_row.get("confidence_level")
            or raw_row.get("confidence")
            or ("HIGH" if artifact_source != "Generic" else "MEDIUM")
        ).upper()

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
            confidence_level=confidence_level,
            extra_attributes=extra_attrs,
            **provenance,
        )

    @classmethod
    def normalize_file_with_report(
        cls, input_path: str, source_label: Optional[str] = None, *, case_id: Optional[str] = None
    ) -> Tuple[List[ForensicEvent], List[Dict[str, Any]]]:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        events: List[ForensicEvent] = []
        errors: List[Dict[str, Any]] = []
        
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            idx = 1
            for row in reader:
                try:
                    event = cls.normalize_record(row, idx, case_id=case_id)
                    if source_label:
                        event.extra_attributes.setdefault("source_label", source_label)
                    events.append(event)
                except Exception as e:
                    errors.append({"record": idx, "error": str(e), "row": dict(row)})
                idx += 1
        
        if errors:
            print(f"Total skipped records: {len(errors)}")
        return events, errors

    @classmethod
    def normalize_file(cls, input_path: str, case_id: Optional[str] = None) -> List[ForensicEvent]:
        events, _ = cls.normalize_file_with_report(input_path, case_id=case_id)
        return events


class ShellBagsNormalizer:
    """Normalizes ShellBags CSV into ForensicEvent objects."""

    @classmethod
    def normalize_file(cls, input_path: str) -> List[ForensicEvent]:
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
        extra_raw = row.get("extra_attributes", "")
        extra_dict: Dict[str, Any] = {}

        if extra_raw and extra_raw.strip():
            try:
                parsed_extra = json.loads(extra_raw)
                if isinstance(parsed_extra, dict):
                    extra_dict = parsed_extra
            except json.JSONDecodeError:
                pass

        provenance = _read_provenance(row, extra_dict)
        for field in PROVENANCE_FIELDS:
            extra_dict.pop(field, None)
        event_id = row.get("event_id", "")
        provenance["case_id"] = provenance["case_id"] or _legacy_case_id(event_id)

        raw_time = row.get("timestamp") or row.get("timestamp_utc") or ""
        dt = parse_iso_utc(raw_time)
        iso_timestamp = dt.isoformat()

        return ForensicEvent(
            event_id=event_id,
            timestamp=iso_timestamp,
            timestamp_desc=(row.get("timestamp_desc")
                            or SHELLBAGS_TIMESTAMP_DESC_MAP.get(provenance["timestamp_type"], "Unknown")),
            artifact_source=row.get("artifact_source") or row.get("artifact_type") or "ShellBags",
            source_file=row.get("source_file", ""),
            target_path=row.get("target_path") or row.get("object_path") or "",
            message=row.get("message") or row.get("description") or "",
            data_type=row.get("data_type", "windows:registry:bagmru"),
            parser=row.get("parser", "sbecmd"),
            user_sid=row.get("user_sid") or None,
            username=row.get("username") or None,
            confidence_level=(row.get("confidence_level") or row.get("confidence") or "MEDIUM").upper(),
            extra_attributes=extra_dict,
            **provenance,
        )
