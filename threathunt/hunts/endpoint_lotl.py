# threathunt/hunts/endpoint_lotl.py
import json

from threathunt.utils import load_json_lines, print_findings

LOLBINS = [
    "certutil.exe",
    "bitsadmin.exe",
    "powershell.exe",
    "rundll32.exe",
    "wmic.exe",
    "mshta.exe",
    "regsvr32.exe",
    "installutil.exe",
    "schtasks.exe",
]

SUSPICIOUS_ARGS = [
    "http://",
    "https://",
    "-urlcache",
    "-url",
    "DownloadFile",
    "/create",
    "/sc",
    "regsvr32 /s /u",
    "script:",
]


def run(input_path, output_path=None):
    events = load_json_lines(input_path)
    findings = []

    for e in events:
        image = (e.get("Image") or e.get("ProcessPath") or "").lower()
        cmd = (e.get("CommandLine") or "").lower()
        if not image:
            continue

        exe = image.split("\\")[-1]
        if exe in LOLBINS:
            reasons = [f"LOLBIN:{exe}"]
            for s in SUSPICIOUS_ARGS:
                if s.lower() in cmd:
                    reasons.append(f"arg_contains:{s}")
            findings.append({
                "type": "lotl_suspect",
                "image": image,
                "command_line": cmd,
                "user": e.get("User"),
                "host": e.get("Computer"),
                "reasons": reasons,
            })

    print_findings(findings, title="LOLBin Abuse Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
