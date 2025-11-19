# hunt.py
import argparse
import os
import yaml

from threathunt.hunts import (
    network_beaconing,
    network_dns_tunnel,
    network_exfil,
    endpoint_powershell,
    endpoint_persistence,
    endpoint_lotl,
    ics_modbus_anomaly,
    ml_anomaly_generic,
    network_lateral_movement,
    auth_ntlm_bruteforce,
    auth_ssh_bruteforce,
    auth_rdp_bruteforce,
    auth_success_logins,
    network_portscan,
    network_dns_dga,
    network_tls_anomaly,
    network_http_exec_downloads,
)

# ----------------------------------------------------------------------
# Hunt registry
# ----------------------------------------------------------------------
# Each entry defines:
#   - func:   the run() function
#   - desc:   short description (for --list/--describe)
#   - input:  hint about expected input log type
HUNTS = {
    "beaconing": {
        "func": network_beaconing.run,
        "desc": "Detect periodic network beaconing from Zeek conn.log.",
        "input": "Zeek conn.log TSV",
    },
    "dns_tunnel": {
        "func": network_dns_tunnel.run,
        "desc": "Detect potential DNS tunneling from Zeek dns.log.",
        "input": "Zeek dns.log TSV",
    },
    "exfil": {
        "func": network_exfil.run,
        "desc": "Detect possible data exfiltration from network flows.",
        "input": "Zeek conn.log TSV (or equivalent)",
    },
    "powershell": {
        "func": endpoint_powershell.run,
        "desc": "Hunt for suspicious PowerShell usage on endpoints.",
        "input": "Endpoint logs (e.g., Sysmon / Windows event JSON/TSV)",
    },
    "persistence": {
        "func": endpoint_persistence.run,
        "desc": "Detect persistence mechanisms on endpoints.",
        "input": "Endpoint logs (persistence-related events)",
    },
    "lotl": {
        "func": endpoint_lotl.run,
        "desc": "Living-off-the-land (LOTL) endpoint activity.",
        "input": "Endpoint logs (process/command-line events)",
    },
    "ics_modbus": {
        "func": ics_modbus_anomaly.run,
        "desc": "ICS Modbus anomaly detection.",
        "input": "Zeek modbus.log TSV",
    },
    "ml_anomaly": {
        "func": ml_anomaly_generic.run,
        "desc": "Generic ML-based anomaly detection on structured data.",
        "input": "Structured JSON/TSV (depends on your model)",
    },
    "lateral": {
        "func": network_lateral_movement.run,
        "desc": "Network lateral movement patterns.",
        "input": "Zeek conn.log / auth logs",
    },
    "ntlm_bruteforce": {
        "func": auth_ntlm_bruteforce.run,
        "desc": "NTLM brute-force / password spray detection.",
        "input": "Zeek ntlm.log TSV",
    },
    "ssh_bruteforce": {
        "func": auth_ssh_bruteforce.run,
        "desc": "SSH brute-force detection.",
        "input": "Zeek ssh.log TSV",
    },
    "rdp_bruteforce": {
        "func": auth_rdp_bruteforce.run,
        "desc": "RDP brute-force detection.",
        "input": "Zeek rdp.log TSV",
    },
    "auth_success": {
        "func": auth_success_logins.run,
        "desc": "Summarize successful logins (user → host).",
        "input": "Zeek auth-like logs (ssh/ntlm/rdp, etc.)",
    },
    "portscan": {
        "func": network_portscan.run,
        "desc": "Horizontal/vertical port scan detection.",
        "input": "Zeek conn.log TSV",
    },
    "dns_dga": {
        "func": network_dns_dga.run,
        "desc": "DGA / weird DNS domain candidates.",
        "input": "Zeek dns.log TSV",
    },
    "tls_anomaly": {
        "func": network_tls_anomaly.run,
        "desc": "TLS / JA3 / certificate anomalies.",
        "input": "Zeek ssl.log TSV",
    },
    "http_exec_downloads": {
        "func": network_http_exec_downloads.run,
        "desc": "Suspicious executable/script downloads over HTTP.",
        "input": "Zeek http.log TSV",
    },
}

# ----------------------------------------------------------------------
# Starter campaigns (used for --init-campaigns)
# ----------------------------------------------------------------------
STARTER_CAMPAIGNS = {
    "campaigns": {
        "network_initial_access": {
            "desc": "Baseline network-focused hunt (beaconing, DNS, TLS, HTTP, portscan).",
            "items": [
                {"hunt": "beaconing",          "input": "conn.log"},
                {"hunt": "portscan",           "input": "conn.log"},
                {"hunt": "dns_tunnel",         "input": "dns.log"},
                {"hunt": "dns_dga",            "input": "dns.log"},
                {"hunt": "tls_anomaly",        "input": "ssl.log"},
                {"hunt": "http_exec_downloads","input": "http.log"},
            ],
        },
        "auth_surface": {
            "desc": "Authentication-focused hunt (SSH/NTLM/RDP brute force + successful logins).",
            "items": [
                {"hunt": "ssh_bruteforce",     "input": "ssh.log"},
                {"hunt": "ntlm_bruteforce",    "input": "ntlm.log"},
                {"hunt": "rdp_bruteforce",     "input": "rdp.log"},
                {"hunt": "auth_success",       "input": "ssh.log"},
            ],
        },
        "ics_focus": {
            "desc": "ICS / lateral focus (Modbus anomalies + network lateral movement).",
            "items": [
                {"hunt": "ics_modbus",         "input": "modbus.log"},
                {"hunt": "lateral",            "input": "conn.log"},
            ],
        },
    }
}


def load_campaigns(config_path):
    """
    Load campaigns from a YAML file.

    Expected structure:
      campaigns:
        name:
          desc: "..."
          items:
            - hunt: beaconing
              input: conn.log
            - ...
    """
    if not os.path.exists(config_path):
        return {}

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    raw_campaigns = data.get("campaigns", {}) or {}
    campaigns = {}

    for name, meta in raw_campaigns.items():
        if not isinstance(meta, dict):
            continue

        key = str(name).lower()
        desc = meta.get("desc", "")
        items = meta.get("items", []) or []
        cleaned_items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            h = item.get("hunt")
            inp = item.get("input")
            if not h or not inp:
                continue
            cleaned_items.append({
                "hunt": str(h).lower(),
                "input": str(inp),
            })

        campaigns[key] = {"desc": desc, "items": cleaned_items}

    return campaigns


def write_campaign_template(path):
    """
    Write a starter campaigns YAML file to 'path'.

    Does not overwrite an existing file.
    """
    if os.path.exists(path):
        print(f"[!] Refusing to overwrite existing campaign config: {path}")
        print("    Move or delete the existing file, or specify a different --campaign-config path.")
        return

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(STARTER_CAMPAIGNS, f, sort_keys=False)

    print(f"[+] Wrote starter campaign configuration to: {path}")
    print("    Edit this file to customize campaigns for your environment.")


def run_campaign(campaign_name, campaigns, input_dir, output_dir=None):
    """
    Execute a named campaign: run a sequence of hunts against log files
    under a base input directory.
    """
    name = str(campaign_name).lower()
    meta = campaigns.get(name)
    if not meta:
        print(f"Unknown campaign: {name}")
        print("\nUse --list or --describe-campaign to see valid names.")
        raise SystemExit(1)

    items = meta.get("items", [])
    if not items:
        print(f"Campaign '{name}' has no items defined.")
        return

    base_input = input_dir or "."
    print(f"[*] Running campaign: {name}")
    print(f"    Description: {meta.get('desc', 'N/A')}")
    print(f"    Input dir:   {os.path.abspath(base_input)}")
    if output_dir:
        print(f"    Output dir:  {os.path.abspath(output_dir)}")
        os.makedirs(output_dir, exist_ok=True)
    print("")

    for item in items:
        hunt_name = item["hunt"]
        rel_input = item["input"]

        hunt_meta = HUNTS.get(hunt_name)
        if not hunt_meta:
            print(f"[!] Skipping unknown hunt '{hunt_name}' in campaign '{name}'.")
            continue

        func = hunt_meta["func"]
        input_path = os.path.join(base_input, rel_input)

        if not os.path.exists(input_path):
            print(f"[!] [{name}] Skipping hunt '{hunt_name}': input file not found: {input_path}")
            continue

        if output_dir:
            out_path = os.path.join(output_dir, f"{name}_{hunt_name}.jsonl")
        else:
            out_path = None

        print(f"[+] [{name}] Running hunt '{hunt_name}' on {input_path}")
        func(input_path, out_path)

    print(f"\n[*] Campaign '{name}' completed.")


def main():
    parser = argparse.ArgumentParser(description="Threat Hunting Suite")

    # Core single-hunt options
    parser.add_argument("--hunt", help="Which hunt to run (see --list)")
    parser.add_argument("--input", help="Input file (Zeek, JSON, etc.)")
    parser.add_argument("--output", help="Optional output file (JSONL)")

    # Campaign options
    parser.add_argument(
        "--campaign",
        help="Run a named hunt campaign (set of hunts). See --list for options.",
    )
    parser.add_argument(
        "--input-dir",
        default=".",
        help="Base directory for campaign input logs (default: current directory).",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write campaign outputs (one JSONL per hunt).",
    )
    parser.add_argument(
        "--campaign-config",
        default="campaigns.yml",
        help="Path to YAML file defining hunt campaigns (default: campaigns.yml).",
    )
    parser.add_argument(
        "--init-campaigns",
        action="store_true",
        help="Write a starter campaigns YAML file to --campaign-config and exit.",
    )

    # Meta options
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available hunts and campaigns, then exit",
    )
    parser.add_argument(
        "--describe",
        metavar="HUNT",
        help="Describe a specific hunt and exit (e.g. --describe beaconing)",
    )
    parser.add_argument(
        "--describe-campaign",
        metavar="CAMPAIGN",
        help="Describe a specific campaign and exit (e.g. --describe-campaign auth_surface)",
    )

    args = parser.parse_args()

    # Load campaigns from YAML (if present)
    campaigns = load_campaigns(args.campaign_config)

    # --------------------------------------------------------------
    # Handle --init-campaigns (write starter YAML and exit)
    # --------------------------------------------------------------
    if args.init_campaigns:
        write_campaign_template(args.campaign_config)
        return

    # --------------------------------------------------------------
    # Handle --list
    # --------------------------------------------------------------
    if args.list:
        print("Available hunts:\n")
        for name in sorted(HUNTS.keys()):
            meta = HUNTS[name]
            desc = meta.get("desc", "").strip()
            print(f"  {name:20} {desc}")

        print("\nAvailable campaigns:\n")
        if not campaigns:
            print("  (none defined; use --init-campaigns to create a starter file)")
        else:
            for cname in sorted(campaigns.keys()):
                cmeta = campaigns[cname]
                cdesc = cmeta.get("desc", "").strip()
                print(f"  {cname:20} {cdesc}")
        return

    # --------------------------------------------------------------
    # Handle --describe <hunt>
    # --------------------------------------------------------------
    if args.describe:
        hunt_name = args.describe.lower()
        meta = HUNTS.get(hunt_name)
        if not meta:
            print(f"Unknown hunt: {hunt_name}")
            print("\nUse --list to see all valid hunt names.")
            raise SystemExit(1)

        print(f"Hunt:        {hunt_name}")
        print(f"Description: {meta.get('desc', 'N/A')}")
        print(f"Input hint:  {meta.get('input', 'N/A')}")
        print("\nExample:")
        print(f"  python hunt.py --hunt {hunt_name} --input <path> --output findings.jsonl")
        return

    # --------------------------------------------------------------
    # Handle --describe-campaign <campaign>
    # --------------------------------------------------------------
    if args.describe_campaign:
        cname = args.describe_campaign.lower()
        cmeta = campaigns.get(cname)
        if not cmeta:
            print(f"Unknown campaign: {cname}")
            print("\nUse --list to see all valid campaigns.")
            raise SystemExit(1)

        print(f"Campaign:    {cname}")
        print(f"Description: {cmeta.get('desc', 'N/A')}")
        print("\nHunts in this campaign:")
        for item in cmeta.get("items", []):
            hname = item["hunt"]
            hin = item["input"]
            hmeta = HUNTS.get(hname, {})
            hdesc = hmeta.get("desc", "N/A")
            print(f"  - {hname:16} input: {hin:12} | {hdesc}")
        print("\nExample:")
        print(
            f"  python hunt.py --campaign {cname} "
            f"--input-dir /path/to/zeek/logs --output-dir /path/to/findings"
        )
        return

    # --------------------------------------------------------------
    # Campaign execution path
    # --------------------------------------------------------------
    if args.campaign:
        if args.hunt or args.input:
            print("Error: --campaign cannot be used together with --hunt or --input.")
            raise SystemExit(1)
        if not campaigns:
            print("No campaigns defined. Use --init-campaigns to create a starter YAML file.")
            raise SystemExit(1)
        run_campaign(args.campaign, campaigns, args.input_dir, args.output_dir)
        return

    # --------------------------------------------------------------
    # Normal single-hunt execution path
    # --------------------------------------------------------------
    if not args.hunt or not args.input:
        parser.error(
            "--hunt and --input are required unless using "
            "--campaign, --list, --describe, --describe-campaign, or --init-campaigns"
        )

    hunt = args.hunt.lower()
    meta = HUNTS.get(hunt)
    if not meta:
        print(f"Unknown hunt: {hunt}")
        print("\nUse --list to see all valid hunt names.")
        raise SystemExit(1)

    # Call the registered function
    func = meta["func"]
    func(args.input, args.output)


if __name__ == "__main__":
    main()

