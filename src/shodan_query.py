#!/usr/bin/env python3
"""
Query Shodan for vhost-adjacent exposed services, using a free-tier API key.
Reads data Shodan already collected under its own authorization -- this
script sends no probes of its own.

Set SHODAN_API_KEY in the environment (free account at shodan.io).

Usage:
    python3 shodan_query.py --query 'product:QEMU' --query 'port:16509,16514' --out data/shodan_candidates.csv
"""
import argparse, csv, os, sys, time
import urllib.request, urllib.parse, json
from csvsafe import safe_rows
from pathlib import Path

API = "https://api.shodan.io/shodan/host/search"

def search(query, key, page=1):
    qs = urllib.parse.urlencode({"key": key, "query": query, "page": page})
    with urllib.request.urlopen(f"{API}?{qs}", timeout=30) as r:
        return json.load(r)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", action="append", required=True,
                     help="Shodan search query, e.g. 'product:QEMU' (repeatable)")
    ap.add_argument("--max-pages", type=int, default=3,
                     help="free-tier credits are limited; keep this small")
    ap.add_argument("--out", default="data/shodan_candidates.csv")
    a = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("[!] set SHODAN_API_KEY (free account at shodan.io)")

    rows = []
    for q in a.query:
        for page in range(1, a.max_pages + 1):
            try:
                res = search(q, key, page)
            except Exception as e:
                print(f"[!] query {q!r} page {page} failed: {e}", file=sys.stderr)
                break
            matches = res.get("matches", [])
            if not matches:
                break
            for m in matches:
                rows.append({
                    "ip": m.get("ip_str"), "port": m.get("port"),
                    "org": m.get("org"), "product": m.get("product"),
                    "banner": (m.get("data") or "")[:200],
                    "query": q, "source": "shodan",
                })
            time.sleep(1.2)  # be polite with limited free credits

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ip","port","org","product","banner","query","source"])
        w.writeheader(); w.writerows(safe_rows(rows))
    print(f"[+] wrote {len(rows)} candidates to {a.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
