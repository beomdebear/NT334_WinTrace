"""
WinTrace - Event Schema and Data Models (v2)
Defines the standardized forensic event structure and validation logic.

Changelog (Week 2):
- Added evidence_reference, timestamp_type, validation_status, case_id to ForensicEvent
- Added event_ids, investigation_note, evidence_references to CorrelationFinding
- Added JumpLists, USNJournal, Registry to VALID_ARTIFACTS
- Added VALID_VALIDATION_STATUSES, VALID_TIMESTAMP_TYPES
- Added extract_drive_path_from_bagmru() for ShellBags path compatibility
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from typing import Dict, List, Optional, Any
import json
import re


VALID_ARTIFACTS = {
    "ShellBags",
    "Prefetch",
    "LNK",
    "JumpLists",
    "RecycleBin",
    "EVTX",
    "NTFS_MFT",
    "Amcache",
    "UserAssist",
    "USNJournal",
    "Registry",
}

VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}

VALID_VALIDATION_STATUSES = {
    "verified",     # Kiểm chứng bằng tool độc lập hoặc ground truth
    "unverified",   # Chưa kiểm chứng
    "synthetic",    # Dữ liệu mô phỏng (chỉ dùng cho test)
    "disputed",     # Có mâu thuẫn hoặc nghi vấn
}

VALID_TIMESTAMP_TYPES = {
    # ShellBags
    "ShellBag_LastInteracted",
    "ShellBag_FirstInteracted",
    "ShellBag_KeyLastWrite",
    "ShellItem_FolderCreated",
    "ShellItem_FolderModified",
    "ShellItem_FolderAccessed",
    # Prefetch
    "Prefetch_LastRun",
    "Prefetch_PreviousRun",
    "Prefetch_FileCreated",
    # LNK
    "LNK_TargetCreated",
    "LNK_TargetModified",
    "LNK_TargetAccessed",
    "LNK_FileCreated",
    "LNK_FileModified",
    # JumpLists
    "JumpList_TargetCreated",
    "JumpList_TargetModified",
    "JumpList_TargetAccessed",
    # RecycleBin
    "RecycleBin_DeletionTime",
    # EVTX
    "EVTX_EventGenerated",
    # NTFS
    "NTFS_SI_Created",
    "NTFS_SI_Modified",
    "NTFS_SI_Accessed",
    "NTFS_SI_EntryModified",
    "NTFS_FN_Created",
    # Generic / Unknown
    "Generic",
}


def normalize_windows_path(path_str: Optional[str]) -> str:
    """Normalize Windows paths for consistent case-insensitive comparison."""
    if not path_str:
        return ""
    # Strip quotes and leading/trailing whitespace
    cleaned = path_str.strip().strip('"\'')
    # Replace forward slashes with backslashes
    cleaned = cleaned.replace('/', '\\')
    # Remove redundant backslashes
    cleaned = re.sub(r'\\+', r'\\', cleaned)
    return cleaned


def parse_iso_utc(timestamp_str: str) -> datetime:
    """Parse ISO 8601 string and ensure it has UTC timezone info."""
    if not timestamp_str:
        raise ValueError("Timestamp string cannot be empty")
    dt = datetime.fromisoformat(timestamp_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_drive_path_from_bagmru(bagmru_path: str) -> tuple:
    """
    Extract drive letter/network root and relative path from BagMRU absolute path.

    BagMRU paths start from 'Desktop' and encode the full navigation hierarchy.
    This function extracts the actual filesystem path component for correlation
    with paths from other artifacts (LNK, Prefetch, MFT, etc.).

    Examples:
        'Desktop\\This PC\\E:\\Secret Project Data\\design'
        → ('E:', 'Secret Project Data\\design')

        'Desktop\\This PC\\E:\\RM#1\\Secret Project Data\\design'
        → ('E:', 'RM#1\\Secret Project Data\\design')

        'Desktop\\Computers and Devices\\10.11.11.128\\10.11.11.128\\secured_drive\\Past Projects'
        → ('\\\\10.11.11.128', 'secured_drive\\Past Projects')

        'Desktop\\S data\\Secret Project Data\\Past Projects'
        → ('', 'S data\\Secret Project Data\\Past Projects')

    Returns:
        Tuple of (drive_or_root, relative_path). drive_or_root may be a drive
        letter like 'E:', a UNC root like '\\\\10.11.11.128', or '' if the
        root cannot be determined.
    """
    if not bagmru_path:
        return ("", "")

    path = normalize_windows_path(bagmru_path)
    parts = [p for p in path.split("\\") if p]

    if not parts:
        return ("", "")

    # Strip leading 'Desktop' if present
    if parts[0].lower() == "desktop":
        parts = parts[1:]

    if not parts:
        return ("", "")

    # Case 1: 'This PC\E:\...' → drive letter path
    if parts[0].lower() == "this pc" and len(parts) > 1:
        parts = parts[1:]  # remove 'This PC'
        # Check for drive letter pattern (e.g., 'E:')
        if len(parts) >= 1 and re.match(r'^[A-Za-z]:$', parts[0]):
            drive = parts[0].upper()
            relative = "\\".join(parts[1:]) if len(parts) > 1 else ""
            return (drive, relative)
        # Fallback: might be something like 'This PC\SomeFolder'
        return ("", "\\".join(parts))

    # Case 2: 'Computers and Devices\IP\IP\share\...' → network path
    if parts[0].lower() in ("computers and devices", "network"):
        parts = parts[1:]  # remove prefix
        if not parts:
            return ("", "")
        # The first part should be IP/hostname
        host = parts[0]
        # Sometimes the host is duplicated: '10.11.11.128\10.11.11.128\share'
        start_idx = 1
        if len(parts) > 1 and parts[1].lower() == host.lower():
            start_idx = 2
        relative = "\\".join(parts[start_idx:]) if len(parts) > start_idx else ""
        return (f"\\\\{host}", relative)

    # Case 3: Everything else — cannot determine drive/root
    # e.g. 'S data\Secret Project Data\Past Projects'
    return ("", "\\".join(parts))


@dataclass
class ForensicEvent:
    event_id: str
    timestamp: str  # ISO 8601 format: YYYY-MM-DDTHH:MM:SS+00:00
    timestamp_desc: str
    artifact_source: str
    source_file: str
    target_path: str
    message: str
    data_type: str = "windows:forensic:generic"
    parser: str = "generic"
    user_sid: Optional[str] = None
    username: Optional[str] = None
    confidence_level: str = "MEDIUM"
    extra_attributes: Dict[str, Any] = field(default_factory=dict)
    # --- Week 2: New fields (all Optional for backward compatibility) ---
    timestamp_type: Optional[str] = None
    evidence_reference: Optional[str] = None
    validation_status: Optional[str] = None
    case_id: Optional[str] = None

    def __post_init__(self):
        # Validate timestamp format
        try:
            self._dt = parse_iso_utc(self.timestamp)
        except Exception as e:
            raise ValueError(f"Invalid timestamp '{self.timestamp}' in event {self.event_id}: {e}")

        # Normalize target_path
        self.target_path = normalize_windows_path(self.target_path)
        self.source_file = normalize_windows_path(self.source_file)

        if self.confidence_level not in VALID_CONFIDENCE_LEVELS:
            self.confidence_level = "MEDIUM"

        # Validate validation_status if provided
        if self.validation_status and self.validation_status not in VALID_VALIDATION_STATUSES:
            self.validation_status = "unverified"

    @property
    def dt(self) -> datetime:
        return self._dt

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ForensicEvent":
        # Filter fields matching dataclass
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in field_names}
        return cls(**filtered)


@dataclass
class CorrelationFinding:
    finding_id: str
    event_a_id: str
    event_b_id: str
    event_a_desc: str
    event_b_desc: str
    time_delta_seconds: float
    time_delta_minutes: float
    matched_rules: List[str]
    confidence_score: int
    confidence_level: str
    explanation: str
    # --- Week 2: New fields (all Optional for backward compatibility) ---
    event_ids: List[str] = field(default_factory=list)
    investigation_note: Optional[str] = None
    evidence_references: List[str] = field(default_factory=list)
    validation_status: Optional[str] = None

    def __post_init__(self):
        # Auto-populate event_ids from event_a_id and event_b_id if empty
        if not self.event_ids:
            self.event_ids = [self.event_a_id, self.event_b_id]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
