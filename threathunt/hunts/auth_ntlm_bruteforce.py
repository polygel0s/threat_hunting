# threathunt/hunts/auth_ntlm_bruteforce.py
import json
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def _is_success(value):
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in ("t", "true", "1", "yes"):
        return True
    if v in ("f", "false", "0", "no"):
        return False
    return None


def run(input_path, output_path=None):
    """
    Detect NTLM brute-force / password spraying behavior from Zeek ntlm.log.
    """
    rows = load_zeek_tsv(input_path)

    pairs = defaultdict(list)  # key: (src, dst) -> list of (ts, username, is_success)

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h")
        dst = row.get("id.resp_h")
        if not src or not dst:
            continue

        username = row.get("username") or row.get("user") or "-"
        is_success = _is_success(row.get("success"))

        pairs[(src, dst)].append((ts, username, is_success))

    findings = []

    # Simple heuristic thresholds – tune as needed
    MIN_FAILURES = 10
    MIN_USERS_FOR_SPRAY = 5
    MIN_FAILURE_RATIO = 0.7  # 70%+ failures

    for (src, dst), events in pairs.items():
        if not events:
            continue

        # Aggregate stats
        total = len(events)
        fail_count = sum(1 for _, _, ok in events if ok is False)
        success_count = sum(1 for _, _, ok in events if ok is True)
        usernames = [u for _, u, _ in events]
        unique_users = set(usernames)

        if total == 0:
            continue

        fail_ratio = fail_count / total if total else 0.0

        if fail_count < MIN_FAILURES or fail_ratio < MIN_FAILURE_RATIO:
            continue

        first_ts = min(e[0] for e in events)
        last_ts = max(e[0] for e in events)
        duration_sec = (last_ts - first_ts).total_seconds() if last_ts > first_ts else 0

        # Classify as brute force vs spray
        if len(unique_users) >= MIN_USERS_FOR_SPRAY:
            attack_type = "password_spray_ntlm"
        else:
            attack_type = "brute_force_ntlm"

        findings.append({
            "type": attack_type,
            "src": src,
            "dst": dst,
            "total_attempts": total,
            "failed_attempts": fail_count,
            "successful_attempts": success_count,
            "failure_ratio": round(fail_ratio, 3),
            "unique_usernames": len(unique_users),
            "example_usernames": list(sorted(unique_users))[:10],
            "first_seen": first_ts.isoformat(),
            "last_seen": last_ts.isoformat(),
            "duration_seconds": duration_sec,
        })

    print_findings(findings, title="NTLM Brute-Force / Spray Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
