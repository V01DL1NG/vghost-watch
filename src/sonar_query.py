#!/usr/bin/env python3
"""
Filter Rapid7 Open Data / Project Sonar scan files for vhost-adjacent
services (libvirt, Proxmox, QEMU/KVM management ports).

Rapid7 Sonar publishes periodic internet-wide scan results for free at
https://opendata.rapid7.com/ (account required for bulk download, but the
scanning itself was already done under their own authorization -- this
script only reads their output).

Usage:
    python3 sonar_query.py --file sonar_tcp_16509.json.gz --port 16509
    python3 sonar_query.py --file sonar_tcp_8006.json.gz --port 8006 --grep proxmox

Sonar files are typically newline-delimited JSON (gzipped), one record per
observed host:port. Field names vary by study; adjust FIELD_MAP if a given
dataset uses different keys.
"""
import argparse, csv, gzip, json, sys
from csvsafe import safe_rows
from pathlib import Path

FIELD_MAP = {"ip": ("ip", "saddr", "addr"), "port": ("port", "dport"),
             "data": ("data", "banner", "response")}

def pick(d, keys):
    for k in keys:
        if k in d:
            return d[k]
    return None

def open_maybe_gz(path):
    return gzip.open(path, "rt") if path.endswith(".gz") else open(path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="Sonar NDJSON(.gz) file")
    ap.add_argument("--port", type=int, action="append", default=[],
                     help="only keep records on this port (repeatable)")
    ap.add_argument("--grep", help="only keep records whose banner/data contains this substring")
    ap.add_argument("--out", default="data/sonar_candidates.csv")
    a = ap.parse_args()

    rows = []
    with open_maybe_gz(a.file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = pick(rec, FIELD_MAP["ip"])
            port = pick(rec, FIELD_MAP["port"])
            data = str(pick(rec, FIELD_MAP["data"]) or "")
            try:
                port = int(port)
            except (TypeError, ValueError):
                pass
            if a.port and port not in a.port:
                continue
            if a.grep and a.grep.lower() not in data.lower():
                continue
            if ip:
                rows.append({"ip": ip, "port": port, "banner": data[:200],
                             "source": "sonar"})

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "port", "banner", "source"])
        w.writeheader(); w.writerows(safe_rows(rows))
    print(f"[+] wrote {len(rows)} candidates to {a.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
