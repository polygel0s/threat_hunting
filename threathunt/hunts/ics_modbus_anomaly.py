import json

from threathunt.utils import print_findings


def load_modbus_tsv(path):
    """
    Parse custom Modbus log lines like:

    ts                  uid                 src         sport   dst         dport len unit func_name        dir extra
    1588061458.247119   C4Mfyh2mvZPouAqKyf  10.10.10.3  56885   10.10.10.66 502   941 1   WRITE_SINGLE_COIL RESP -

    Returns a list of dicts with normalized fields.
    """
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("\t")
            # Expect at least 9–11 columns based on your example
            if len(parts) < 9:
                continue

            ts_str = parts[0]
            uid = parts[1]
            src = parts[2]
            sport = parts[3]
            dst = parts[4]
            dport = parts[5]
            length = parts[6] if len(parts) > 6 else None
            unit = parts[7] if len(parts) > 7 else None
            func_name = parts[8] if len(parts) > 8 else None
            direction = parts[9] if len(parts) > 9 else None

            # Best-effort numeric parsing
            try:
                ts = float(ts_str)
            except Exception:
                ts = None

            try:
                sport = int(sport)
            except Exception:
                pass

            try:
                dport = int(dport)
            except Exception:
                pass

            try:
                length = int(length) if length is not None else None
            except Exception:
                length = None

            try:
                unit = int(unit) if unit is not None else None
            except Exception:
                unit = None

            events.append({
                "ts": ts,
                "uid": uid,
                "src": src,
                "sport": sport,
                "dst": dst,
                "dport": dport,
                "length": length,
                "unit_id": unit,
                "function_name": func_name,
                "direction": direction,
                "raw_line": line,
            })

    return events


def run(input_path, output_path=None):
    """
    Hunt for suspicious Modbus write operations in modbus.log.

    For your current format, we don't have register addresses, only function
    names like WRITE_SINGLE_COIL, WRITE_MULTIPLE_REGISTERS, etc.

    So this version flags any function_name containing 'WRITE'.
    Later you can refine by allowed coils/registers if you add address info.
    """
    events = load_modbus_tsv(input_path)
    findings = []

    for e in events:
        func = (e.get("function_name") or "").upper()

        # Simple heuristic: treat any WRITE_* function as a potential write op
        if "WRITE" in func:
            findings.append({
                "type": "ics_modbus_write_operation",
                "src": e.get("src"),
                "dst": e.get("dst"),
                "unit_id": e.get("unit_id"),
                "function_name": func,
                "direction": e.get("direction"),
                "length": e.get("length"),
                "dport": e.get("dport"),
                "raw_line": e.get("raw_line"),
            })

    print_findings(findings, title="ICS Modbus Write Operations")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")

