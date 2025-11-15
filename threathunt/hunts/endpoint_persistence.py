# threathunt/hunts/endpoint_persistence.py
import json
import os

from threathunt.utils import load_json_lines, print_findings

# Example shape of events:
# {
#   "type": "run_key" / "service" / "scheduled_task",
#   "path": "C:\\ProgramData\\something.exe",
#   "signed": false,
#   "user": "DOMAIN\\user",
#   "name": "blah"
# }


SUSPICIOUS_DIR_HINTS = [
    "\\temp\\",
    "\\users\\public\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
]


def run(input_path, output_path=None):
    events = load_json_lines(input_path)
    findings = []

    for e in events:
        etype = e.get("type", "").lower()
        path = (e.get("path") or "").lower()
        signed = e.get("signed")
        user = e.get("user")
        name = e.get("name")

        if not path:
            continue

        suspicious = False
        reasons = []

        if not signed:
            suspicious = True
            reasons.append("unsigned")

        for hint in SUSPICIOUS_DIR_HINTS:
            if hint in path:
                suspicious = True
                reasons.append(f"path_contains:{hint.strip('\\')}")

        if "temp" in path and path.endswith(".exe"):
            suspicious = True
            reasons.append("exe_in_temp")

        if suspicious:
            findings.append({
                "type": "persistence_suspect",
                "artifact_type": etype,
                "path": path,
                "signed": signed,
                "user": user,
                "name": name,
                "reasons": reasons,
            })

    print_findings(findings, title="Persistence Candidates")

    if output_path and findings:
        with open(output_path, "w", encoding="utf-8") as f:
            for fnd in findings:
                f.write(json.dumps(fnd) + "\n")
