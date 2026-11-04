"""
WinTrace - Plaso Pipeline Prototype Script
End-to-end prototype for ingesting, normalizing, filtering, and exporting Plaso timelines.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

# Add project root to sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.normalizer import PlasoNormalizer
from src.storage import TimelineStore
from src.timeline_parser import TimelineParser, TargetedFilter


def print_banner():
    banner = """
============================================================
       WinTrace - Plaso Timeline Normalization Pipeline     
============================================================
"""
    print(banner)


def run_pipeline(
    input_file: str,
    output_file: str,
    output_format: str = "json",
    filter_user: str = None,
    filter_artifact: str = None,
    shellbags_file: Optional[str] = None,
    database_file: Optional[str] = None,
    error_log: Optional[str] = None,
):
    print_banner()
    print(f"[*] Loading and normalizing raw Plaso output from: {input_file}")

    # Step 1: Normalize raw Plaso input
    events, errors = PlasoNormalizer.normalize_file_with_report(input_file, "plaso")
    if shellbags_file:
        shellbag_events, shellbag_errors = PlasoNormalizer.normalize_file_with_report(
            shellbags_file, "shellbags"
        )
        events.extend(shellbag_events)
        errors.extend(shellbag_errors)
        print(f"[+] Imported {len(shellbag_events)} ShellBags events.")
    if errors:
        if error_log:
            error_path = Path(error_log)
            error_path.parent.mkdir(parents=True, exist_ok=True)
            error_path.write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[WARNING] Records rejected during normalization: {len(errors)}")
    total_ingested = len(events)
    print(f"[+] Successfully normalized {total_ingested} forensic events.")

    # Step 2: Optional Targeted Filtering
    if filter_user:
        print(f"[*] Applying filter for user: {filter_user}")
        events = TargetedFilter.filter_by_user(events, username=filter_user)
        print(f"[+] Events after user filter: {len(events)}")

    if filter_artifact:
        print(f"[*] Applying filter for artifact: {filter_artifact}")
        events = TargetedFilter.filter_by_artifacts(events, artifacts=[filter_artifact])
        print(f"[+] Events after artifact filter: {len(events)}")

    # Step 3: Export normalized events
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format.lower() == "csv":
        TimelineParser.export_to_csv(events, str(out_path))
        print(f"[+] Exported normalized timeline (CSV) to: {out_path}")
    else:
        TimelineParser.export_to_json(events, str(out_path))
        print(f"[+] Exported normalized timeline (JSON) to: {out_path}")

    if database_file:
        with TimelineStore(database_file) as store:
            inserted = store.insert_events(events)
            print(
                f"[+] SQLite timeline: {inserted} new events, "
                f"{store.count()} total events at {database_file}"
            )

    # Step 4: Summary Statistics Dashboard
    artifact_counts = Counter(e.artifact_source for e in events)
    users_found = {e.username for e in events if e.username}
    sids_found = {e.user_sid for e in events if e.user_sid}

    sorted_events = sorted(events, key=lambda e: e.dt)
    earliest = sorted_events[0].timestamp if sorted_events else "N/A"
    latest = sorted_events[-1].timestamp if sorted_events else "N/A"

    print("\n------------------ PIPELINE STATISTICS ------------------")
    print(f"Total Events Processed : {len(events)} / {total_ingested}")
    print(f"Timeline Start (UTC)   : {earliest}")
    print(f"Timeline End   (UTC)   : {latest}")
    print(f"Identified Users       : {', '.join(users_found) if users_found else 'None'}")
    print(f"Identified SIDs        : {', '.join(sids_found) if sids_found else 'None'}")
    print("\nArtifact Breakdown:")
    for art, count in sorted(artifact_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  - {art:<15}: {count:>4} events")
    print("---------------------------------------------------------\n")
    print("[SUCCESS] Pipeline completed successfully!\n")


def main():
    parser = argparse.ArgumentParser(description="WinTrace Plaso Pipeline Prototype")
    parser.add_argument(
        "--input", "-i",
        default="results/plaso_raw_output.csv",
        help="Path to raw Plaso CSV file (default: results/plaso_raw_output.csv)"
    )
    parser.add_argument(
        "--output", "-o",
        default="results/normalized_events.json",
        help="Path to save normalized output (default: results/normalized_events.json)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "csv"],
        default="json",
        help="Output format: json or csv (default: json)"
    )
    parser.add_argument(
        "--user", "-u",
        default=None,
        help="Filter events by username"
    )
    parser.add_argument(
        "--artifact", "-a",
        default=None,
        help="Filter events by artifact type (Prefetch, LNK, ShellBags, RecycleBin, EVTX)"
    )
    parser.add_argument("--shellbags", default=None, help="CASE01 ShellBags CSV to import")
    parser.add_argument("--database", default=None, help="SQLite database output path")
    parser.add_argument("--error-log", default=None, help="JSON file for rejected records")

    args = parser.parse_args()
    run_pipeline(
        input_file=args.input,
        output_file=args.output,
        output_format=args.format,
        filter_user=args.user,
        filter_artifact=args.artifact,
        shellbags_file=args.shellbags,
        database_file=args.database,
        error_log=args.error_log,
    )


if __name__ == "__main__":
    main()
