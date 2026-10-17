#!/usr/bin/env python3
"""
Import your own host list (CSV) into the pipeline. The CSV needs an IP
column, a domain column, or both; any other columns are carried through.
Domains are resolved with a plain DNS lookup (no connection to the host).
An IP-column value may also be a CIDR range (e.g. 203.0.113.0/24) -- it is
expanded into individual addresses listed as candidates for the passive
lookups in whois_contacts.py. This never connects to any of them; expanding
a range is just arithmetic over the address space, not scanning it.

Writes data/list_candidates.csv, which merge_and_triage.py picks up.

Usage:
    python3 import_list.py --in hosts.csv
    python3 import_list.py --in hosts.csv --domain-col hostname --ip-col address --port-col port
    python3 import_list.py --in ranges.csv --max-hosts 4096   # ip col holds CIDRs
"""
import argparse, csv, ipaddress, socket, sys
from csvsafe import safe_rows
from pathlib import Path

def resolve(domain):
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})

def expand(value, max_hosts):
    """Return (ips, truncated). A bare IP is passed through; a CIDR is
    expanded up to max_hosts addresses (dropped network/broadcast for IPv4
    beyond /31)."""
    if "/" not in value:
        return [value], False
    net = ipaddress.ip_network(value, strict=False)
    total = net.num_addresses
    hosts = list(net.hosts()) if total > 2 else list(net)
    truncated = len(hosts) > max_hosts
    return [str(h) for h in hosts[:max_hosts]], truncated

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="CSV with ip and/or domain column")
    ap.add_argument("--out", default="data/list_candidates.csv")
    ap.add_argument("--ip-col", default="ip", help="may hold a single IP or a CIDR range")
    ap.add_argument("--domain-col", default="domain")
    ap.add_argument("--port-col", default="port")
    ap.add_argument("--max-hosts", type=int, default=65536,
                     help="cap expanded addresses per CIDR row, to keep runs bounded")
    a = ap.parse_args()

    with open(a.inp, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames or []
        if a.ip_col not in cols and a.domain_col not in cols:
            sys.exit(f"[!] need column {a.ip_col!r} and/or {a.domain_col!r}; found {cols}")
        rows = list(reader)

    out, unresolved, truncated_ranges = [], [], []
    for r in rows:
        ip_field = (r.get(a.ip_col) or "").strip()
        domain = (r.get(a.domain_col) or "").strip().lower()
        extra = {k: v for k, v in r.items() if k not in (a.ip_col, a.domain_col, a.port_col)}
        port = (r.get(a.port_col) or "").strip()
        if ip_field:
            try:
                ips, truncated = expand(ip_field, a.max_hosts)
            except ValueError as e:
                print(f"[!] skipping invalid ip/range {ip_field!r}: {e}", file=sys.stderr)
                continue
            if truncated:
                truncated_ranges.append(ip_field)
        else:
            ips, truncated = (resolve(domain) if domain else []), False
        if not ips:
            if domain:
                unresolved.append(domain)
            continue
        for i in ips:
            out.append({"ip": i, "domain": domain, "port": port, **extra, "source": "list"})

    fields = ["ip", "domain", "port"] + [c for c in cols if c not in (a.ip_col, a.domain_col, a.port_col)] + ["source"]
    fields = list(dict.fromkeys(fields))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(safe_rows(out))
    print(f"[+] wrote {len(out)} rows to {a.out}", file=sys.stderr)
    if unresolved:
        print(f"[!] {len(unresolved)} domains did not resolve: {', '.join(unresolved[:10])}"
              f"{' ...' if len(unresolved) > 10 else ''}", file=sys.stderr)
    if truncated_ranges:
        print(f"[!] {len(truncated_ranges)} range(s) exceeded --max-hosts "
              f"({a.max_hosts}) and were truncated: {', '.join(truncated_ranges[:10])}"
              f"{' ...' if len(truncated_ranges) > 10 else ''}", file=sys.stderr)

if __name__ == "__main__":
    main()
