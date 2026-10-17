#!/usr/bin/env python3
"""
Merge candidate CSVs from sonar_query.py / shodan_query.py / censys_query.py /
import_list.py, dedupe by IP, and score how likely each is to be a
vhost-relevant exposed management interface (not a vulnerability
confirmation -- just triage).

Naming convention: --in-glob (default data/*_candidates.csv) only picks up
files ending in "_candidates.csv". Every producer script in src/ writes its
output under that pattern (shodan_candidates.csv, list_candidates.csv, ...)
-- if you add a new producer or rename an output file, keep that suffix or
pass --in-glob explicitly, or this will silently merge zero rows from it.
"""
import argparse, csv, glob, json
from pathlib import Path
from csvsafe import safe_rows

DEFAULT_CONFIG = {
    "hint_ports": {"16509": 3, "16514": 3, "8006": 2, "5900": 1, "2179": 1, "9440": 1},
    "hint_words": ["libvirt", "proxmox", "qemu", "kvm", "vhost"],
    "word_weight": 2,
}

def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    return cfg

def score(row, cfg):
    s = 0
    port = str(row.get("port") or "")
    services = str(row.get("services", "")).split(";")
    for p, w in cfg["hint_ports"].items():
        if str(p) == port or str(p) in services:
            s += w
    text = " ".join(str(v) for v in row.values()).lower()
    for w in cfg["hint_words"]:
        if w.lower() in text:
            s += cfg["word_weight"]
    return s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-glob", default="data/*_candidates.csv")
    ap.add_argument("--out", default="reports/candidates.csv")
    ap.add_argument("--config", default="config/scoring.json",
                     help="JSON with hint_ports / hint_words / word_weight")
    a = ap.parse_args()

    cfg = load_config(a.config)
    merged = {}
    paths = glob.glob(a.in_glob)
    if not paths:
        print(f"[!] no files matched --in-glob {a.in_glob!r}; "
              f"nothing to merge (check the naming convention noted at the top of this file)")
    for path in paths:
        with open(path) as f:
            for row in csv.DictReader(f):
                ip = row.get("ip")
                if not ip:
                    continue
                row["score"] = score(row, cfg)
                existing = merged.get(ip)
                if not existing or row["score"] > existing["score"]:
                    merged[ip] = row

    rows = sorted(merged.values(), key=lambda r: -int(r["score"]))
    fields = sorted({k for r in rows for k in r.keys()}, key=lambda k: (k != "ip", k != "score", k))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(safe_rows(rows))
    print(f"[+] {len(rows)} unique candidates -> {a.out}")

if __name__ == "__main__":
    main()
