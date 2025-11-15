# threathunt/hunts/network_beaconing.py
import json
import numpy as np
from collections import defaultdict
from sklearn.ensemble import IsolationForest

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


def run(input_path, output_path=None):
    conns = load_zeek_tsv(input_path)

    buckets = defaultdict(list)  # key: (src, dst), value: list of timestamps

    for c in conns:
        ts = parse_timestamp(c.get("ts"))
        if not ts:
            continue
        key = (c.get("id.orig_h"), c.get("id.resp_h"))
        buckets[key].append(ts)

    features = []
    keys = []

    for key, times in buckets.items():
        if len(times) < 5:
            continue
        times = sorted(times)
        deltas = [(t2 - t1).total_seconds() for t1, t2 in zip(times[:-1], times[1:])]
        if not deltas:
            continue
        mean_int = float(np.mean(deltas))
        std_int = float(np.std(deltas))
        mad_int = float(np.median(np.abs(deltas - np.median(deltas))))
        count = len(deltas)
        # simple feature vector
        features.append([mean_int, std_int, mad_int, count])
        keys.append(key)

    if not features:
        print("No sufficient data for beacon analysis.")
        return

    X = np.array(features)
    clf = IsolationForest(contamination=0.02, random_state=42)
    scores = clf.fit_predict(X)
    decision = clf.decision_function(X)

    findings = []
    for (src, dst), score, dec, vec in zip(keys, scores, decision, X):
        if score == -1:
            findings.append({
                "type": "beaconing_suspect",
                "src": src,
                "dst": dst,
                "mean_interval": vec[0],
                "std_interval": vec[1],
                "mad_interval": vec[2],
                "count": int(vec[3]),
                "anomaly_score": float(-dec),
            })

    print_findings(findings, title="Beaconing Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
