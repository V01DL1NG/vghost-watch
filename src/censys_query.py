#!/usr/bin/env python3
"""
Query Censys Search for vhost-adjacent exposed services, using free-tier
API credentials. Reads data Censys already collected under its own
authorization -- this script sends no probes of its own.

Set CENSYS_API_ID and CENSYS_API_SECRET in the environment
(free account at search.censys.io).

Usage:
    python3 censys_query.py --query 'services.port: 16509' --out data/censys_candidates.csv
"""
import argparse, csv, os, sys, time, base64
import urllib.request, json
from csvsafe import safe_rows
from pathlib import Path

API = "https://search.censys.io/api/v2/hosts/search"

def search(query, api_id, api_secret, cursor=None):
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url = f"{API}?q={urllib.parse.quote(query)}&per_page=50"
    if cursor:
        url += f"&cursor={cursor}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

import urllib.parse

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", action="append", required=True,
                     help="Censys query, e.g. 'services.port: 16509' (repeatable)")
    ap.add_argument("--max-pages", type=int, default=3)
    ap.add_argument("--out", default="data/censys_candidates.csv")
    a = ap.parse_args()

    api_id = os.environ.get("CENSYS_API_ID")
    api_secret = os.environ.get("CENSYS_API_SECRET")
    if not (api_id and api_secret):
        sys.exit("[!] set CENSYS_API_ID and CENSYS_API_SECRET (free account at search.censys.io)")

    rows = []
    for q in a.query:
        cursor = None
        for page in range(a.max_pages):
            try:
                res = search(q, api_id, api_secret, cursor)
            except Exception as e:
                print(f"[!] query {q!r} page {page} failed: {e}", file=sys.stderr)
                break
            hits = res.get("result", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                rows.append({"ip": h.get("ip"),
                             "services": ";".join(str(s.get("port")) for s in h.get("services", [])),
                             "location": (h.get("location") or {}).get("country"),
                             "query": q, "source": "censys"})
            cursor = res.get("result", {}).get("links", {}).get("next")
            if not cursor:
                break
            time.sleep(1.0)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["ip","services","location","query","source"])
        w.writeheader(); w.writerows(safe_rows(rows))
    print(f"[+] wrote {len(rows)} candidates to {a.out}", file=sys.stderr)

if __name__ == "__main__":
    main()
