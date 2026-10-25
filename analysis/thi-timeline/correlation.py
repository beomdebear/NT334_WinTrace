from datetime import datetime, timezone
from itertools import combinations
from pathlib import PureWindowsPath

# Du lieu forensic gia lap
EVENTS = [
    {
        "id": "E01",
        "time": "2026-10-25T02:10:00+00:00",
        "artifact": "ShellBags",
        "path": r"C:\Users\Alice\Documents\Project"
    },
    {
        "id": "E02",
        "time": "2026-10-25T02:12:00+00:00",
        "artifact": "LNK",
        "path": r"C:\Users\Alice\Documents\Project\report.docx"
    },
    {
        "id": "E03",
        "time": "2026-10-25T02:14:00+00:00",
        "artifact": "Prefetch",
        "path": r"C:\Windows\WINWORD.EXE"
    },
    {
        "id": "E04",
        "time": "2026-10-25T02:19:00+00:00",
        "artifact": "Recycle Bin",
        "path": r"C:\Users\Alice\Documents\Project\old.txt"
    }
]


def parse_time(value):
    timestamp = datetime.fromisoformat(value)

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must have a timezone")

    return timestamp.astimezone(timezone.utc)


def path_relation(path1, path2):
    a = tuple(p.casefold() for p in PureWindowsPath(path1).parts)
    b = tuple(p.casefold() for p in PureWindowsPath(path2).parts)

    if a == b:
        return "Same path"

    if len(a) < len(b) and b[:len(a)] == a:
        return "Parent-child path"

    if len(b) < len(a) and a[:len(b)] == b:
        return "Parent-child path"

    return None


def correlate_events(events, window_minutes=5):
    findings = []

    for event_a, event_b in combinations(events, 2):

        delta = abs(
            (parse_time(event_a["time"]) -
             parse_time(event_b["time"])).total_seconds()
        ) / 60

        matched_rules = []

        # R01: Temporal Proximity
        if delta <= window_minutes:
            matched_rules.append("R01")

        # R02: Object Association
        relation = path_relation(
            event_a["path"],
            event_b["path"]
        )

        if relation:
            matched_rules.append("R02")

        # R03: Cross-Artifact Candidate
        if (
            event_a["artifact"] != event_b["artifact"]
            and (delta <= window_minutes or relation)
        ):
            matched_rules.append("R03")

        if matched_rules:
            findings.append({
                "event_a": event_a["id"],
                "event_b": event_b["id"],
                "time_delta_minutes": round(delta, 2),
                "matched_rules": matched_rules
            })

    return findings


if __name__ == "__main__":
    results = correlate_events(EVENTS)

    print("=== WinTrace Correlation Results ===")

    for finding in results:
        print(finding)
