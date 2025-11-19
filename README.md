# threat_hunting
threat hunting tool to run against zeek logs

# Beaconing from Zeek conn.log
python hunt.py --hunt beaconing --input conn.log --output beaconing.jsonl

# DNS tunnel hunt from dns.log
python hunt.py --hunt dns_tunnel --input dns.log

# PowerShell hunt from JSONL
python hunt.py --hunt powershell --input powershell_4104.jsonl

# Modbus anomaly hunt
python hunt.py --hunt ics_modbus --input modbus.log

#Network only lateral - 1st step
python hunt.py --hunt lateral --input /path/to/conn.log --output lateral.jsonl

#Network and host lateral - 2nd step
python hunt.py --hunt lateral --input /path/to/file --output lateral.jsonl
