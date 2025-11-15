# threathunt/hunts/network_dns_tunnel.py
import math
import json
from collections import defaultdict, Counter

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def shannon_entropy(s):
    c = Counter(s)
    total = len(s)
    if total == 0:
        return 0.0
    return -sum((v / total) * math.log2(v / total) for v in c.values())


def run(input_path, output_path=None):
    dns = load_zeek_tsv(input_path)

    buckets = defaultdict(lambda: {
        "count": 0,
        "long_qnames": 0,
        "high_entropy": 0,
        "first_ts": None,
        "last_ts": None,
    })

    for d in dns:
        qname = d.get("query", "")
        ts = parse_timestamp(d.get("ts"))
        if not qname or not ts:
            continue

        # Use the registered domain-ish (last two labels) as key
        parts = qname.strip(".").split(".")
        if len(parts) >= 2:
            key = ".".join(parts[-2:])
        else:
            key = qname

        ent = shannon_entropy(qname)
        info = buckets[key]
        info["count"] += 1
        if len(qname) > 50:
            info["long_qnames"] += 1
        if ent > 4.0:
            info["high_entropy"] += 1

        if not info["first_ts"] or ts < info["first_ts"]:
            info["first_ts"] = ts
        if not info["last_ts"] or ts > info["last_ts"]:
            info["last_ts"] = ts

    findings = []
    for domain, info in buckets.items():
        duration_sec = (info["last_ts"] - info["first_ts"]).total_seconds() or 1.0
        rate = info["count"] / duration_sec
        long_ratio = info["long_qnames"] / max(info["count"], 1)
        entropy_ratio = info["high_entropy"] / max(info["count"], 1)

        if info["count"] > 50 and (long_ratio > 0.3 or entropy_ratio > 0.3 or rate > 0.5):
            findings.append({
                "type": "dns_tunnel_suspect",
                "domain": domain,
                "count": info["count"],
                "rate_qps": rate,
                "long_qname_ratio": long_ratio,
                "high_entropy_ratio": entropy_ratio,
            })

    print_findings(findings, title="DNS Tunneling Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
