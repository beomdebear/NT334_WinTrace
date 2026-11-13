import csv

from src.normalizer import PlasoNormalizer
from src.storage import TimelineStore


def test_raw_shellbags_schema_v2_imports_without_losing_provenance(tmp_path):
    source = tmp_path / "shellbags_v2.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "event_id", "timestamp_utc", "timestamp_type", "artifact_type",
            "source_file", "description", "object_path", "evidence_reference",
            "confidence", "validation_status",
        ])
        writer.writeheader()
        writer.writerow({
            "event_id": "CASE01-SB0001",
            "timestamp_utc": "2015-03-22T14:52:22Z",
            "timestamp_type": "ShellItem_FolderAccessed",
            "artifact_type": "ShellBags",
            "source_file": "UsrClass.dat",
            "description": "Folder accessed",
            "object_path": r"E:\Secret Project Data",
            "evidence_reference": "Deduplicated.csv:L10",
            "confidence": "low",
            "validation_status": "verified",
        })

    events, errors = PlasoNormalizer.normalize_file_with_report(str(source), "case01")
    assert not errors
    with TimelineStore(str(tmp_path / "case01.db")) as store:
        assert store.insert_events(events) == 1
        result = store.query(artifact="ShellBags")

    assert len(result) == 1
    assert result[0].event_id == "CASE01-SB0001"
    assert result[0].extra_attributes["evidence_reference"] == "Deduplicated.csv:L10"
