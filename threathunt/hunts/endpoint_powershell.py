# threathunt/hunts/endpoint_powershell.py
import json
import re

from threathunt.utils import load_json_lines, print_findings

SUSPICIOUS_PATTERNS = [
    r"-enc(odedcommand)?\s+[A-Za-z0-9/+]{20,}={0,2}",
    r"FromBase64String",
    r"iex\s*\(",
    r"Invoke-Expression",
    r"DownloadString",
    r"Invoke-WebRequest",
    r"Add-MpPreference",
    r"Bypass.*AMSI",
    r"amsiInitFailed",
    r"PowerView",
    r"Invoke-Mimikatz",
]


def run(input_path, output_path=None):
    events = load_json_lines(input_path)
    findings = []

    for e in events:
        cmd = (e.get("Message") or e.get("CommandLine") or "").lower()
        if not cmd:
            continue

        matches = []
        for pat in SUSPICIOUS_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                matches.append(pat)

        if matches:
            findings.append({
                "type": "powershell_suspicious",
                "patterns": matches,
                "host": e.get("Computer"),
                "user": e.get("User"),
                "command": cmd,
                "orig_event": e,
            })

    print_findings(findings, title="Suspicious PowerShell Activity")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
