# threathunt/utils.py
import json
from datetime import datetime


def parse_timestamp(ts_str):
    """
    Try to parse timestamps from Zeek/JSON/etc.
    Fallback: return None if parse fails.
    """
    if ts_str is None:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%s"):
        try:
            if fmt == "%s":
                return datetime.utcfromtimestamp(float(ts_str))
            return datetime.strptime(ts_str, fmt)
        except Exception:
            continue
    return None


def load_json_lines(path):
    """
    Load a JSONL file.
    """
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def print_findings(findings, title="Findings"):
    print(f"\n=== {title} ===")
    if not findings:
        print("No findings.")
        return
    for f in findings:
        print(json.dumps(f, indent=2, default=str))
