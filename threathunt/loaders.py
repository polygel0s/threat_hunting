# threathunt/loaders.py
import csv


def load_zeek_tsv(path):
    """
    Load a Zeek TSV file (conn.log, dns.log, etc.)
    Skips lines starting with '#'.
    Returns list of dicts.
    """
    records = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        # First, find the header line
        header = None
        data_lines = []
        for line in f:
            if line.startswith("#fields"):
                header = line.strip().split()[1:]  # after '#fields'
            elif line.startswith("#"):
                continue
            else:
                data_lines.append(line.strip())

        if not header:
            return records

        reader = csv.reader(data_lines, delimiter="\t")
        for row in reader:
            if len(row) != len(header):
                continue
            rec = dict(zip(header, row))
            records.append(rec)
    return records
