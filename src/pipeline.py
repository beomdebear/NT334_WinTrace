"""
WinTrace - Plaso Pipeline Prototype Script
End-to-end prototype for ingesting, normalizing, filtering, and exporting Plaso timelines.
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

# Add project root to sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.normalizer import PlasoNormalizer
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
    filter_artifact: str = None
):
    print_banner()
    print(f"[*] Loading and normalizing raw Plaso output from: {input_file}")

    # Step 1: Normalize raw Plaso input
    events = PlasoNormalizer.normalize_file(input_file)
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

    args = parser.parse_args()
    run_pipeline(
        input_file=args.input,
        output_file=args.output,
        output_format=args.format,
        filter_user=args.user,
        filter_artifact=args.artifact
    )


if __name__ == "__main__":
    main()
