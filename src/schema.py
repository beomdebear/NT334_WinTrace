"""
WinTrace - Event Schema and Data Models
Defines the standardized forensic event structure and validation logic.
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
    "RecycleBin",
    "EVTX",
    "NTFS_MFT",
    "Amcache",
    "UserAssist"
}

VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
