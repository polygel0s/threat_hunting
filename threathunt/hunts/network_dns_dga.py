# threathunt/hunts/network_dns_dga.py
import json
import math
from collections import defaultdict, Counter

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def _extract_domain_parts(query: str):
    """
    Return (full_fqdn, leftmost_label).
    """
    if not query:
        return None, None
    q = query.strip().lower().rstrip(".")
    if not q:
        return None, None
    parts = q.split(".")
    left = parts[0] if parts else None
    return q, left


def run(input_path, output_path=None):
    """
    Detect suspicious / DGA-like DNS queries from Zeek dns.log.

    Signals:
      - High entropy left-most label
      - Long label length
      - High NXDOMAIN ratio
    """
    rows = load_zeek_tsv(input_path)

    # fqdn -> stats
    domains = defaultdict(lambda: {
        "count": 0,
        "nxdomain": 0,
        "left_label": None,
        "src_ips": set(),
        "first_ts": None,
        "last_ts": None,
    })

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h") or "-"
        query = row.get("query") or row.get("qname")

        fqdn, left = _extract_domain_parts(query)
        if not fqdn or not left:
            continue

        rcode_name = (row.get("rcode_name") or "").lower()

        d = domains[fqdn]
        d["count"] += 1
        d["src_ips"].add(src)
        d["left_label"] = left

        if rcode_name in ("nxdomain", "nxdomain_error", "nxdomainerror"):
            d["nxdomain"] += 1

        if d["first_ts"] is None or ts < d["first_ts"]:
            d["first_ts"] = ts
        if d["last_ts"] is None or ts > d["last_ts"]:
            d["last_ts"] = ts

    findings = []

    # Thresholds (tune for your env)
    MIN_QUERIES = 5
    MIN_LABEL_LEN = 10
    MIN_ENTROPY = 3.5   # 0..~4.7 for typical ascii letters
    MIN_NXDOMAIN_RATIO = 0.5

    for fqdn, info in domains.items():
        count = info["count"]
        if count < MIN_QUERIES:
            continue

        left = info["left_label"] or ""
        label_len = len(left)
        entropy = _shannon_entropy(left)

        nxdomain_ratio = info["nxdomain"] / count if count else 0.0

        # Simple heuristic: if any of these are suspicious, flag
        suspicious_reasons = []

        if label_len >= MIN_LABEL_LEN:
            suspicious_reasons.append(f"long_label(len={label_len})")
        if entropy >= MIN_ENTROPY:
            suspicious_reasons.append(f"high_entropy({entropy:.2f})")
        if nxdomain_ratio >= MIN_NXDOMAIN_RATIO:
            suspicious_reasons.append(f"high_nxdomain_ratio({nxdomain_ratio:.2f})")

        if not suspicious_reasons:
            continue

        first_ts = info["first_ts"]
        last_ts = info["last_ts"]
        duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0

        findings.append({
            "type": "dns_dga_suspect",
            "fqdn": fqdn,
            "left_label": left,
            "label_length": label_len,
            "entropy": round(entropy, 3),
            "total_queries": count,
            "nxdomain_count": info["nxdomain"],
            "nxdomain_ratio": round(nxdomain_ratio, 3),
            "distinct_src_ips": len(info["src_ips"]),
            "example_src_ips": sorted(list(info["src_ips"]))[:20],
            "first_seen": first_ts.isoformat() if first_ts else None,
            "last_seen": last_ts.isoformat() if last_ts else None,
            "duration_seconds": duration,
            "reasons": suspicious_reasons,
        })

    print_findings(findings, title="DNS DGA / Weird Domain Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
