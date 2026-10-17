#!/usr/bin/env python3
"""
Fill templates/remediation_note.md per candidate into reports/remediation/,
for your own tracked assets -- turn these into tickets in your own tracker.
Unlike draft_notices.py, this needs no contact lookup (no RDAP/security.txt
step): you already know who owns the asset, it's yours.
"""
import argparse, csv, sys
from pathlib import Path
from csvsafe import safe_ip_filename

TEMPLATE = Path("templates/remediation_note.md")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="reports/candidates.csv")
    ap.add_argument("--out", default="reports/remediation")
    ap.add_argument("--min-score", type=int, default=2,
                     help="skip low-confidence candidates (raise false-positive risk otherwise)")
    a = ap.parse_args()

    tpl = TEMPLATE.read_text()
    outdir = Path(a.out); outdir.mkdir(parents=True, exist_ok=True)

    with open(a.inp) as f:
        rows = list(csv.DictReader(f))

    written, skipped_invalid = 0, 0
    for row in rows:
        if int(row.get("score", 0)) < a.min_score:
            continue
        filename = safe_ip_filename(row.get("ip"))
        if not filename:
            skipped_invalid += 1
            continue
        domain = row.get("domain") or ""
        text = tpl
        for key, val in {
            "ip": row["ip"],
            "domain_suffix": f" ({domain})" if domain else "",
            "port": row.get("port") or "?",
            "owner": row.get("owner") or "(not set in your input list)",
            "source": row.get("source") or "passive scan",
            "score": row.get("score", "?"),
        }.items():
            text = text.replace("{" + key + "}", str(val))
        (outdir / filename).write_text(text)
        written += 1

    print(f"[+] wrote {written} remediation notes in {outdir}")
    if skipped_invalid:
        print(f"[!] skipped {skipped_invalid} row(s) with an invalid 'ip' value "
              f"(not a real IP address -- possibly a crafted/corrupted input file)",
              file=sys.stderr)

if __name__ == "__main__":
    main()
