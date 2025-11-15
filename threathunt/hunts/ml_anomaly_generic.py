import json
import numpy as np

from threathunt.utils import load_json_lines, print_findings
from threathunt.loaders import load_zeek_tsv  # <-- NEW
from sklearn.ensemble import IsolationForest


def _is_number_like(v):
    """
    Return True if v looks like a numeric value we can float() cleanly.
    Ignore typical Zeek placeholders like '-' or empty strings.
    """
    if v in (None, "", "-", "(empty)"):
        return False
    try:
        float(v)
        return True
    except Exception:
        return False


def _build_features_from_zeek(records):
    """
    Given a list of Zeek TSV records (dicts), discover numeric fields
    and build feature vectors for each event.

    Returns:
        feature_vecs: list[list[float]]
        kept_events:  list[dict]  (original Zeek records kept in sync with feature_vecs)
        numeric_keys: list[str]   (field names used as features, in order)
    """
    if not records:
        return [], [], []

    # 1) Discover which keys are numeric across the dataset
    numeric_keys = set()
    for rec in records:
        for k, v in rec.items():
            if _is_number_like(v):
                numeric_keys.add(k)

    numeric_keys = sorted(numeric_keys)
    if not numeric_keys:
        return [], [], []

    # 2) Build feature vectors
    feature_vecs = []
    kept_events = []
    for rec in records:
        vec = []
        has_any = False
        for k in numeric_keys:
            v = rec.get(k)
            if _is_number_like(v):
                val = float(v)
                has_any = True
            else:
                val = 0.0
            vec.append(val)
        if has_any:
            feature_vecs.append(vec)
            kept_events.append(rec)

    return feature_vecs, kept_events, numeric_keys


def run(input_path, output_path=None):
    """
    Generic ML anomaly hunter.

    Behavior:
      1) Try to load JSONL (expects each event to have a 'features' list).
      2) If no JSONL events, treat input_path as a Zeek .log file (TSV),
         infer numeric fields, and run IsolationForest on them.
    """
    # --- Mode 1: JSONL with explicit 'features' ---
    events = load_json_lines(input_path)

    feature_vecs = []
    kept_events = []

    if events:
        # JSONL mode
        for e in events:
            feats = e.get("features")
            if not isinstance(feats, list) or not feats:
                continue
            try:
                vec = [float(x) for x in feats]
            except Exception:
                continue
            feature_vecs.append(vec)
            kept_events.append(e)

        mode = "jsonl"
    else:
        # --- Mode 2: Zeek TSV (.log) ---
        zeek_records = load_zeek_tsv(input_path)
        if not zeek_records:
            print("No events (neither JSONL nor Zeek records found).")
            return

        feature_vecs, kept_events, numeric_keys = _build_features_from_zeek(zeek_records)
        mode = "zeek"

    if not feature_vecs:
        print("No usable feature vectors.")
        return

    X = np.array(feature_vecs)
    clf = IsolationForest(contamination=0.01, random_state=42)
    scores = clf.fit_predict(X)
    decision = clf.decision_function(X)

    findings = []
    for e, s, d in zip(kept_events, scores, decision):
        if s == -1:
            findings.append({
                "type": "ml_anomaly",
                "anomaly_score": float(-d),
                "event": e,
                "mode": mode,
            })

    # Take top 100 anomalies by score
    findings = sorted(findings, key=lambda x: x["anomaly_score"], reverse=True)[:100]

    print_findings(findings, title="ML Anomalies")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")

