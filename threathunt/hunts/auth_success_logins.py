# threathunt/hunts/auth_success_logins.py
import json
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def _is_success_from_row(row: dict):
    """
    Try to infer whether this row represents a successful login.

    We look at common Zeek fields used in ssh/ntlm/rdp logs:
      - success
      - auth_success
      - result
    """
    # Priority 1: explicit boolean-ish success fields
    for field in ("success", "auth_success"):
        if field in row and row[field] is not None:
            v = str(row[field]).strip().lower()
            if v in ("t", "true", "1", "yes"):
                return True
            if v in ("f", "false", "0", "no"):
                return False

    # Priority 2: result-like fields (e.g., rdp.log)
    result_val = row.get("result")
    if result_val is not None:
        v = str(result_val).strip().lower()
        success_tokens = {
            "ok",
            "success",
            "succeeded",
            "connection_success",
            "connected",
            "login_success",
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


def _extract_username(row: dict) -> str:
    """
    Try common username-ish fields used in Zeek logs.
    """
    return (
        row.get("user")
        or row.get("username")
        or row.get("logon_name")
        or row.get("account")
        or row.get("client_user")
        or "-"
    )


def _extract_hostname(row: dict) -> str:
    """
    Try common hostname-ish fields that may exist in auth logs.

    For RDP:
      - client_name, hostname
    For others:
      - computer, computer_name, host
    """
    return (
        row.get("client_name")
        or row.get("hostname")
        or row.get("computer_name")
        or row.get("computer")
        or row.get("host")
        or "-"
    )


def run(input_path, output_path=None):
    """
    Summarize successful logins by (username, remote host IP, hostname if present).

    Intended to work on:
      - Zeek ssh.log (auth_success / success fields)
      - Zeek ntlm.log (success field)
      - Zeek rdp.log (result field)
      - Other auth-style Zeek logs with similar fields

    Output:
      One record per (username, dst_ip, hostname) combination with:
        - total_successes
        - distinct source IPs
        - first_seen / last_seen
    """

    rows = load_zeek_tsv(input_path)

    # key: (username, dst_ip, hostname) -> stats
    buckets = defaultdict(lambda: {
        "src_ips": set(),
        "timestamps": [],
    })

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        is_success = _is_success_from_row(row)
        if is_success is not True:
            # Only keep clearly successful logins
            continue

        src_ip = row.get("id.orig_h") or "-"
        dst_ip = row.get("id.resp_h") or "-"
        username = _extract_username(row)
        hostname = _extract_hostname(row)

        key = (username, dst_ip, hostname)

        buckets[key]["src_ips"].add(src_ip)
        buckets[key]["timestamps"].append(ts)

    findings = []

    for (username, dst_ip, hostname), data in buckets.items():
        times = data["timestamps"]
        if not times:
            continue

        times_sorted = sorted(times)
        first_ts = times_sorted[0]
        last_ts = times_sorted[-1]

        findings.append({
            "type": "auth_success_summary",
            "username": username,
            "remote_host_ip": dst_ip,
            "remote_hostname": hostname,
            "total_successes": len(times),
            "distinct_src_ips": len(data["src_ips"]),
            "example_src_ips": sorted(list(data["src_ips"]))[:20],
            "first_seen": first_ts.isoformat(),
            "last_seen": last_ts.isoformat(),
        })

    print_findings(findings, title="Successful Login Summary")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
