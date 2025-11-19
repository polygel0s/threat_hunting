# threathunt/hunts/network_http_exec_downloads.py
import json
from urllib.parse import urlparse
from collections import defaultdict

from threathunt.loaders import load_zeek_tsv
from threathunt.utils import parse_timestamp, print_findings


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".msi", ".scr",
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".hta", ".jar", ".apk", ".com",
}

SUSPICIOUS_MIME_SUBSTRINGS = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-ms-installer",
    "application/vnd.microsoft.portable-executable",
    "application/octet-stream",  # generic, but still interesting if paired w/ exe-like extension
}


def _get_path_and_ext(uri: str):
    if not uri:
        return "", ""
    try:
        parsed = urlparse(uri)
        path = parsed.path or uri
    except Exception:
        path = uri
    dot_idx = path.rfind(".")
    ext = path[dot_idx:].lower() if dot_idx != -1 else ""
    return path, ext


def _is_suspicious_mime(mime_str: str) -> bool:
    if not mime_str:
        return False
    v = mime_str.lower()
    for sub in SUSPICIOUS_MIME_SUBSTRINGS:
        if sub in v:
            return True
    return False


def run(input_path, output_path=None):
    """
    Detect suspicious executable/script downloads over HTTP from Zeek http.log.

    Signals:
      - File extensions indicative of binaries/scripts
      - Response MIME types indicative of executables
      - 2xx response codes (successful download)
    """

    rows = load_zeek_tsv(input_path)

    findings = []
    # Optionally aggregate by (src, host) later; for now, per-transaction

    for row in rows:
        ts = parse_timestamp(row.get("ts"))
        if not ts:
            continue

        src = row.get("id.orig_h") or "-"
        dst = row.get("id.resp_h") or "-"
        host = row.get("host") or row.get("server_name") or dst
        uri = row.get("uri") or row.get("request_uri") or "/"
        method = (row.get("method") or "GET").upper()
        user_agent = row.get("user_agent") or "-"
        status_code_raw = row.get("status_code") or row.get("status")
        try:
            status_code = int(status_code_raw)
        except (TypeError, ValueError):
            status_code = None

        # Only care about 2xx responses
        if status_code is None or not (200 <= status_code < 300):
            continue

        path, ext = _get_path_and_ext(uri)

        # MIME types (Zeek might log as resp_mime_types, resp_mime_type, etc.)
        mime = (
            row.get("resp_mime_types")
            or row.get("resp_mime_type")
            or ""
        )
        # Sometimes Zeek puts multiple MIME types in a set-like string
        if isinstance(mime, str) and mime.startswith("["):
            mime_str = mime.strip("[]")
        else:
            mime_str = str(mime)

        suspicious_reasons = []

        if ext and ext in SUSPICIOUS_EXTENSIONS:
            suspicious_reasons.append(f"suspicious_extension({ext})")

        if mime_str and _is_suspicious_mime(mime_str):
            suspicious_reasons.append(f"suspicious_mime({mime_str})")

        # If neither extension nor MIME suggests an executable/script, skip
        if not suspicious_reasons:
            continue

        full_url = f"http://{host}{uri}" if not uri.startswith("http") else uri

        findings.append({
            "type": "http_exec_download",
            "src": src,
            "dst": dst,
            "host": host,
            "method": method,
            "status_code": status_code,
            "url": full_url,
            "path": path,
            "extension": ext,
            "mime": mime_str,
            "user_agent": user_agent,
            "timestamp": ts.isoformat(),
            "reasons": suspicious_reasons,
        })

    print_findings(findings, title="HTTP Executable / Script Download Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
