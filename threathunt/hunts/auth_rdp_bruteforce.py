# threathunt/hunts/auth_rdp_bruteforce.py
import json
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def _is_success(result_val):
    """
    Map Zeek rdp.log 'result' field to True/False/None.
    Adjust the keyword lists as needed for your environment.
    """
    if result_val is None:
        return None

    v = str(result_val).strip().lower()

    success_tokens = {
        "ok",
        "success",
        "succeeded",
        "connection_success",
        "connected",
    }

    failure_tokens = {
        "failed",
        "fail",
        "denied",
        "auth_failed",
        "connection_failed",
        "error",
    }

    if v in success_tokens:
        return True
    if v in failure_tokens:
        return False

    # Unknown / neutral
    return None


def run(input_path, output_path=None):
    """
    Detect RDP brute-force activity from Zeek rdp.log.

    Heuristics:
      - Group by (src_ip, dst_ip)
      - Count failures vs successes
      - Flag if failures exceed thresholds and dominate the ratio
    """
    rows = load_zeek_tsv(input_path)

    # key: (src, dst) -> list of (ts, "user", is_success)
    pairs = defaultdict(list)

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h")
        dst = row.get("id.resp_h")
        if not src or not dst:
            continue

        # Zeek rdp.log often lacks clean username; cookie may contain a hint.
        user = (
            row.get("user")
            or row.get("username")
            or row.get("cookie")
            or "-"
        )

        is_success = _is_success(row.get("result"))
        pairs[(src, dst)].append((ts, user, is_success))

    findings = []

    # Tune these thresholds for your environment
    MIN_FAILURES = 15          # minimum failed attempts from src->dst
    MIN_FAILURE_RATIO = 0.75   # at least 75% of attempts are failures

    for (src, dst), events in pairs.items():
        if not events:
            continue

        total = len(events)
        fail_count = sum(1 for _, _, ok in events if ok is False)
        success_count = sum(1 for _, _, ok in events if ok is True)

        if total == 0:
            continue

        fail_ratio = fail_count / total if total else 0.0
        if fail_count < MIN_FAILURES or fail_ratio < MIN_FAILURE_RATIO:
            continue

        users = [u for u, _, _ in [(e[1], e[2], e[0]) for e in events]]  # keep consistent but simple
        # Better: just extract from events directly:
        users = [u for _, u, _ in events]
        unique_users = set(users)

        first_ts = min(e[0] for e in events)
        last_ts = max(e[0] for e in events)
        duration_sec = (last_ts - first_ts).total_seconds() if last_ts > first_ts else 0

        findings.append({
            "type": "rdp_bruteforce",
            "src": src,
            "dst": dst,
            "total_attempts": total,
            "failed_attempts": fail_count,
            "successful_attempts": success_count,
            "failure_ratio": round(fail_ratio, 3),
            "unique_user_tokens": len(unique_users),
            "example_user_tokens": list(sorted(unique_users))[:10],
            "first_seen": first_ts.isoformat(),
            "last_seen": last_ts.isoformat(),
            "duration_seconds": duration_sec,
        })

    print_findings(findings, title="RDP Brute-Force Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
