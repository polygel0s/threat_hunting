# threathunt/hunts/network_lateral_movement.py
import os
import json
import ipaddress
from collections import defaultdict
from datetime import datetime

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import load_json_lines, parse_timestamp, print_findings


def is_internal_ip(ip):
    """
    Return True if ip is RFC1918/private.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def load_conn_lateral_flows(conn_path):
    """
    Load Zeek conn.log and return a list of interesting internal->internal
    lateral movement candidate connections:
        - RDP (port 3389 or service rdp)
        - SSH (port 22 or service ssh)
        - SMB/MSRPC (ports 445,139 or service smb, msrpc)
    Each entry is a dict with: ts, src, dst, proto, service, resp_p
    """
    if not os.path.exists(conn_path):
        return []

    conns = load_zeek_tsv(conn_path)
    candidates = []

    for c in conns:
        src = c.get("id.orig_h")
        dst = c.get("id.resp_h")
        port = c.get("id.resp_p")
        proto = c.get("proto")
        service = (c.get("service") or "").lower()

        if not (src and dst and port):
            continue
        if not (is_internal_ip(src) and is_internal_ip(dst)):
            # only care about internal-to-internal for lateral movement
            continue

        # Normalize port
        try:
            port_int = int(port)
        except Exception:
            port_int = None

        is_rdp = service == "rdp" or port_int == 3389
        is_ssh = service == "ssh" or port_int == 22
        is_smb = service in ("smb", "msrpc") or port_int in (445, 139)

        if not (is_rdp or is_ssh or is_smb):
            continue

        ts = parse_timestamp(c.get("ts"))
        if not ts:
            # Zeek often has epoch timestamps; try that
            try:
                ts = datetime.utcfromtimestamp(float(c.get("ts")))
            except Exception:
                ts = None

        candidates.append({
            "ts": ts,
            "src": src,
            "dst": dst,
            "proto": proto,
            "service": service or ("rdp" if is_rdp else "ssh" if is_ssh else "smb"),
            "resp_p": port_int,
        })

    return candidates


def load_windows_auth_events(auth_path):
    """
    Load Windows Security events (JSONL) and extract relevant remote logons.

    Expected JSON fields (flexible, we try multiple keys):
      - EventID / event_id: 4624, 4625
      - LogonType / logon_type: 3 or 10 (network / remote interactive)
      - IpAddress / ip_address / SourceIp / source_ip
      - Computer / computer / TargetHostName
      - TargetUserName / target_user / User
    """
    if not os.path.exists(auth_path):
        return []

    raw_events = load_json_lines(auth_path)
    events = []

    for e in raw_events:
        # Event ID
        event_id = e.get("EventID") or e.get("event_id") or e.get("EventId")
        try:
            event_id = int(event_id)
        except Exception:
            continue

        if event_id not in (4624, 4625):
            continue

        # Logon Type
        logon_type = e.get("LogonType") or e.get("logon_type")
        try:
            logon_type = int(logon_type)
        except Exception:
            # sometimes nested in event data; you can extend here if needed
            continue

        # 3 = network, 10 = remote interactive
        if logon_type not in (3, 10):
            continue

        # Source IP
        ip = (
            e.get("IpAddress") or e.get("ip_address") or
            e.get("SourceIp") or e.get("source_ip")
        )
        if not ip:
            continue

        # Destination host
        dest = (
            e.get("Computer") or e.get("computer") or
            e.get("TargetHostName") or e.get("WorkstationName")
        )

        # User
        user = (
            e.get("TargetUserName") or e.get("target_user") or
            e.get("User") or e.get("user")
        )

        # Timestamp
        ts_str = (
            e.get("TimeCreated") or e.get("time_created") or
            e.get("EventTime") or e.get("time")
        )
        ts = parse_timestamp(ts_str)

        events.append({
            "event_id": event_id,
            "logon_type": logon_type,
            "src_ip": ip,
            "dest_host": dest,
            "user": user,
            "ts": ts,
            "raw": e,
        })

    return events


def build_lateral_stats(conn_flows, auth_events):
    """
    Build combined stats keyed by (src_ip, dest_host_or_ip).
    """
    stats = defaultdict(lambda: {
        "rdp_conn": 0,
        "ssh_conn": 0,
        "smb_conn": 0,
        "first_ts": None,
        "last_ts": None,
        "auth_success": 0,
        "auth_fail": 0,
        "users": set(),
    })

    # 1) network flows
    for f in conn_flows:
        src = f["src"]
        dst = f["dst"]
        service = f["service"]
        ts = f["ts"] or None

        key = (src, dst)

        s = stats[key]
        if service == "rdp":
            s["rdp_conn"] += 1
        elif service == "ssh":
            s["ssh_conn"] += 1
        elif service == "smb":
            s["smb_conn"] += 1

        if ts:
            if not s["first_ts"] or ts < s["first_ts"]:
                s["first_ts"] = ts
            if not s["last_ts"] or ts > s["last_ts"]:
                s["last_ts"] = ts

    # 2) auth events
    for a in auth_events:
        src_ip = a["src_ip"]
        dest = a["dest_host"] or ""  # might be hostname vs IP
        user = a["user"]
        ts = a["ts"]
        event_id = a["event_id"]

        # We don't always know if dest is IP or hostname; we treat as-is.
        key = (src_ip, dest)

        s = stats[key]
        if event_id == 4624:
            s["auth_success"] += 1
        elif event_id == 4625:
            s["auth_fail"] += 1

        if user:
            s["users"].add(user)

        if ts:
            if not s["first_ts"] or ts < s["first_ts"]:
                s["first_ts"] = ts
            if not s["last_ts"] or ts > s["last_ts"]:
                s["last_ts"] = ts

    return stats


def score_lateral_candidates(stats):
    """
    Turn stats into findings with heuristic scoring.
    """
    findings = []

    for (src, dst), s in stats.items():
        total_lateral_conns = s["rdp_conn"] + s["ssh_conn"] + s["smb_conn"]

        # We only care about pairs that actually have lateral-ish connections
        if total_lateral_conns == 0 and (s["auth_success"] + s["auth_fail"]) == 0:
            continue

        reasons = []
        severity = "low"

        if s["rdp_conn"] > 0:
            reasons.append(f"rdp_conn:{s['rdp_conn']}")
        if s["ssh_conn"] > 0:
            reasons.append(f"ssh_conn:{s['ssh_conn']}")
        if s["smb_conn"] > 0:
            reasons.append(f"smb_conn:{s['smb_conn']}")

        if s["auth_fail"] >= 5:
            reasons.append(f"auth_fail_high:{s['auth_fail']}")
            severity = "medium"

        # multiple failures followed by successes -> likely brute force / spray
        if s["auth_fail"] >= 5 and s["auth_success"] >= 1:
            reasons.append("auth_fail_then_success")
            severity = "high"

        # many lateral connections + any auth activity
        if total_lateral_conns >= 10 and (s["auth_success"] + s["auth_fail"]) > 0:
            reasons.append("high_lateral_volume")
            severity = "high"

        # fallback: any lateral conn + any auth data
        if total_lateral_conns > 0 and (s["auth_success"] + s["auth_fail"]) > 0 and severity == "low":
            severity = "medium"

        if not reasons:
            continue

        findings.append({
            "type": "lateral_movement_candidate",
            "src": src,
            "dst": dst,
            "rdp_conn": s["rdp_conn"],
            "ssh_conn": s["ssh_conn"],
            "smb_conn": s["smb_conn"],
            "auth_success": s["auth_success"],
            "auth_fail": s["auth_fail"],
            "users": list(s["users"]),
            "first_seen": s["first_ts"],
            "last_seen": s["last_ts"],
            "severity": severity,
            "reasons": reasons,
        })

    # Sort high severity / most auth failures first
    findings.sort(key=lambda x: (x["severity"], x["auth_fail"]), reverse=True)
    return findings


def run(input_path, output_path=None):
    """
    Lateral movement hunt.

    input_path:
        - If directory:
            expects:
              conn.log                  (Zeek TSV)
              windows_security.jsonl    (JSONL Windows auth events)
        - If file:
            treated as Zeek conn.log only (network-only heuristics)
    """
    if os.path.isdir(input_path):
        conn_path = os.path.join(input_path, "conn.log")
        win_auth_path = os.path.join(input_path, "windows_security.jsonl")
    else:
        conn_path = input_path
        win_auth_path = None

    conn_flows = load_conn_lateral_flows(conn_path)

    if win_auth_path:
        auth_events = load_windows_auth_events(win_auth_path)
    else:
        auth_events = []

    stats = build_lateral_stats(conn_flows, auth_events)
    findings = score_lateral_candidates(stats)

    print_findings(findings, title="Lateral Movement Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                # convert datetime to ISO strings
                if isinstance(fnd.get("first_seen"), datetime):
                    fnd["first_seen"] = fnd["first_seen"].isoformat()
                if isinstance(fnd.get("last_seen"), datetime):
                    fnd["last_seen"] = fnd["last_seen"].isoformat()
                f.write(json.dumps(fnd) + "\n")
