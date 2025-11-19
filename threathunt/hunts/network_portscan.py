# threathunt/hunts/network_portscan.py
import json
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def run(input_path, output_path=None):
    """
    Detect simple horizontal / vertical port scanning from Zeek conn.log.
    """

    rows = load_zeek_tsv(input_path)

    # For each src -> dst, track ports & timestamps
    ports_per_pair = defaultdict(set)         # (src, dst) -> set of dst ports
    ts_per_pair = defaultdict(list)           # (src, dst) -> list of ts
    dsts_per_src = defaultdict(set)           # src -> set of dst IPs

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h")
        dst = row.get("id.resp_h")
        dport = row.get("id.resp_p")

        if not src or not dst or not dport:
            continue

        try:
            dport_int = int(dport)
        except (ValueError, TypeError):
            continue

        key = (src, dst)

        ports_per_pair[key].add(dport_int)
        ts_per_pair[key].append(ts)
        dsts_per_src[src].add(dst)

    findings = []

    # Thresholds – tune per environment
    MIN_PORTS_VERTICAL = 20      # lots of ports to same host
    MIN_HOSTS_HORIZONTAL = 10    # a lot of hosts total
    MIN_PORTS_FOR_HORIZONTAL = 3 # at least a few ports across many hosts

    # Vertical scans (many ports against single host)
    for (src, dst), ports in ports_per_pair.items():
        if len(ports) >= MIN_PORTS_VERTICAL:
            times = ts_per_pair[(src, dst)]
            first_ts = min(times)
            last_ts = max(times)
            duration_sec = (last_ts - first_ts).total_seconds() if last_ts > first_ts else 0

            findings.append({
                "type": "vertical_portscan",
                "src": src,
                "dst": dst,
                "unique_ports": len(ports),
                "example_ports": sorted(list(ports))[:20],
                "first_seen": first_ts.isoformat(),
                "last_seen": last_ts.isoformat(),
                "duration_seconds": duration_sec,
            })

    # Horizontal scans (one src scanning many dests)
    for src, dsts in dsts_per_src.items():
        if len(dsts) < MIN_HOSTS_HORIZONTAL:
            continue

        # aggregate all ports
        all_ports = set()
        for dst in dsts:
            all_ports.update(ports_per_pair.get((src, dst), set()))

        if len(all_ports) < MIN_PORTS_FOR_HORIZONTAL:
            continue

        findings.append({
            "type": "horizontal_portscan",
            "src": src,
            "unique_dsts": len(dsts),
            "unique_ports": len(all_ports),
            "example_dsts": list(sorted(dsts))[:20],
            "example_ports": sorted(list(all_ports))[:20],
        })

    print_findings(findings, title="Port Scan Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
