# threathunt/hunts/network_tls_anomaly.py
import json
from collections import defaultdict, Counter

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def run(input_path, output_path=None):
    """
    Detect suspicious TLS connections based on rare JA3/issuer and cert anomalies
    from Zeek ssl.log (or equivalent).

    Signals:
      - Rare JA3 fingerprint
      - Rare issuer organization
      - Self-signed certs (issuer == subject)
      - Non-OK validation_status
    """

    rows = load_zeek_tsv(input_path)

    records = []
    ja3_counter = Counter()
    issuer_counter = Counter()

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h") or "-"
        dst = row.get("id.resp_h") or "-"

        ja3 = row.get("ja3") or row.get("client_ja3") or ""
        ja3s = row.get("ja3s") or row.get("server_ja3") or ""
        issuer = (row.get("issuer") or row.get("certificate.issuer") or "").strip()
        subject = (row.get("subject") or row.get("certificate.subject") or "").strip()
        version = row.get("version") or ""
        cipher = row.get("cipher") or ""
        validation_status = (row.get("validation_status") or "").lower()

        rec = {
            "ts": ts,
            "src": src,
            "dst": dst,
            "ja3": ja3,
            "ja3s": ja3s,
            "issuer": issuer,
            "subject": subject,
            "version": version,
            "cipher": cipher,
            "validation_status": validation_status,
        }

        records.append(rec)

        if ja3:
            ja3_counter[ja3] += 1
        if issuer:
            issuer_counter[issuer] += 1

    findings = []

    # Thresholds:
    MIN_RARE_JA3_COUNT = 3      # anything <= this is "rare"
    MIN_RARE_ISSUER_COUNT = 3
    VALIDATION_OK = {"ok", "succeeded", "success", "valid"}

    for rec in records:
        reasons = []

        ja3 = rec["ja3"]
        issuer = rec["issuer"]
        subject = rec["subject"]
        validation_status = rec["validation_status"]

        if ja3 and ja3_counter[ja3] <= MIN_RARE_JA3_COUNT:
            reasons.append(f"rare_ja3(count={ja3_counter[ja3]})")

        if issuer and issuer_counter[issuer] <= MIN_RARE_ISSUER_COUNT:
            reasons.append(f"rare_issuer(count={issuer_counter[issuer]})")

        if issuer and subject and issuer == subject:
            reasons.append("self_signed_cert")

        if validation_status and validation_status not in VALIDATION_OK:
            reasons.append(f"validation_status={validation_status}")

        if not reasons:
            continue

        findings.append({
            "type": "tls_anomaly",
            "src": rec["src"],
            "dst": rec["dst"],
            "ja3": ja3,
            "ja3s": rec["ja3s"],
            "issuer": issuer,
            "subject": subject,
            "version": rec["version"],
            "cipher": rec["cipher"],
            "validation_status": validation_status,
            "reasons": reasons,
            "timestamp": rec["ts"].isoformat(),
            "ja3_count": ja3_counter[ja3] if ja3 else 0,
            "issuer_count": issuer_counter[issuer] if issuer else 0,
        })

    print_findings(findings, title="TLS / JA3 / Cert Anomalies")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
