# hunt.py
import argparse
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
)


def main():
    parser = argparse.ArgumentParser(description="Threat Hunting Suite")
    parser.add_argument("--hunt", required=True, help="Which hunt to run")
    parser.add_argument("--input", required=True, help="Input file (Zeek, JSON, etc.)")
    parser.add_argument("--output", help="Optional output file (JSONL)")
    args = parser.parse_args()

    hunt = args.hunt.lower()

    if hunt == "beaconing":
        network_beaconing.run(args.input, args.output)
    elif hunt == "dns_tunnel":
        network_dns_tunnel.run(args.input, args.output)
    elif hunt == "exfil":
        network_exfil.run(args.input, args.output)
    elif hunt == "powershell":
        endpoint_powershell.run(args.input, args.output)
    elif hunt == "persistence":
        endpoint_persistence.run(args.input, args.output)
    elif hunt == "lotl":
        endpoint_lotl.run(args.input, args.output)
    elif hunt == "ics_modbus":
        ics_modbus_anomaly.run(args.input, args.output)
    elif hunt == "ml_anomaly":
        ml_anomaly_generic.run(args.input, args.output)
    elif hunt == "lateral":
        network_lateral_movement.run(args.input, args.output)
    else:
        raise SystemExit(f"Unknown hunt: {hunt}")


if __name__ == "__main__":
    main()
