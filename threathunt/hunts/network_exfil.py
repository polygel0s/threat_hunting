# threathunt/hunts/network_exfil.py
import json
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import print_findings


def run(input_path, output_path=None):
    conns = load_zeek_tsv(input_path)

    stats = defaultdict(lambda: {
        "total_orig_bytes": 0,
        "conns": 0,
        "ports": set(),
    })

    for c in conns:
        src = c.get("id.orig_h")
        dst = c.get("id.resp_h")
        port = c.get("id.resp_p")
        try:
            bytes_out = float(c.get("orig_bytes", 0) or 0)
        except ValueError:
            bytes_out = 0

        if not (src and dst and port):
            continue

        key = (src, dst)
        s = stats[key]
        s["total_orig_bytes"] += bytes_out
        s["conns"] += 1
        s["ports"].add(port)

    findings = []
    for (src, dst), s in stats.items():
        if s["total_orig_bytes"] > 100 * 1024 * 1024:  # > 100 MB
            findings.append({
                "type": "exfil_candidate",
                "src": src,
                "dst": dst,
                "total_orig_bytes": s["total_orig_bytes"],
                "conn_count": s["conns"],
                "ports": list(s["ports"]),
            })

    print_findings(findings, title="Exfil Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
