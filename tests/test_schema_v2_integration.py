import csv
import json
from dataclasses import replace

from src.normalizer import PlasoNormalizer
from src.report_generator import ReportGenerator
from src.storage import TimelineStore


def test_raw_shellbags_schema_v2_imports_without_losing_provenance(tmp_path):
    source = tmp_path / "shellbags_v2.csv"
    with source.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "event_id", "timestamp_utc", "timestamp_type", "artifact_type",
            "source_file", "description", "object_path", "evidence_reference",
            "confidence", "validation_status", "case_id", "extra_attributes",
        ])
        writer.writeheader()
        writer.writerow({
            "event_id": "CASE02-SB0001",
            "timestamp_utc": "2015-03-22T14:52:22Z",
            "timestamp_type": "ShellItem_FolderAccessed",
            "artifact_type": "ShellBags",
            "source_file": "UsrClass.dat",
            "description": "Folder accessed",
            "object_path": r"E:\Secret Project Data",
            "evidence_reference": "Deduplicated.csv:L10",
            "confidence": "low",
            "validation_status": "verified",
            "case_id": "CASE02",
            "extra_attributes": json.dumps({
                "timestamp_type": "Generic",
                "evidence_reference": "old.csv:L1",
                "validation_status": "unverified",
                "case_id": "OLD",
            }),
        })
        writer.writerow({
            "event_id": "CASE01-SB0001",
            "timestamp_utc": "2015-03-22T14:52:23Z",
            "artifact_type": "ShellBags",
            "source_file": "UsrClass.dat",
            "extra_attributes": json.dumps({
                "timestamp_type": "ShellBag_LastInteracted",
                "evidence_reference": "Deduplicated.csv:L59",
                "validation_status": "verified",
            }),
        })

    events, errors = PlasoNormalizer.normalize_file_with_report(str(source), "shellbags")
    assert not errors
    database_path = str(tmp_path / "timeline.db")
    with TimelineStore(database_path) as store:
        assert store.insert_events(events) == 2
    with TimelineStore(database_path) as store:
        result = store.query(artifact="ShellBags")

    explicit, legacy = result
    assert explicit.event_id == "CASE02-SB0001"
    assert explicit.timestamp_type == "ShellItem_FolderAccessed"
    assert explicit.evidence_reference == "Deduplicated.csv:L10"
    assert explicit.validation_status == "verified"
    assert explicit.case_id == "CASE02"
    assert explicit.extra_attributes["source_label"] == "shellbags"
    assert legacy.event_id == "CASE01-SB0001"
    assert legacy.timestamp_type == "ShellBag_LastInteracted"
    assert legacy.evidence_reference == "Deduplicated.csv:L59"
    assert legacy.validation_status == "verified"
    assert legacy.case_id == "CASE01"

    report = ReportGenerator.generate_html_report(result, [])
    assert "<strong>Case ID:</strong> CASE01, CASE02" in report
    assert "ShellBag_LastInteracted" in report
    assert "<td>Deduplicated.csv:L10</td>" in report
    assert "<td>verified</td>" in report

    unknown = replace(explicit, case_id=None, message="<folder>")
    report = ReportGenerator.generate_html_report([explicit, unknown], [])
    assert "<strong>Case ID:</strong> CASE02, Unspecified" in report
    assert "&lt;folder&gt;" in report
    assert "<strong>Case ID:</strong> Unspecified" in ReportGenerator.generate_html_report([unknown], [])
