#!/usr/bin/env python3
"""
Fill templates/disclosure_email.md per candidate with a contact, into
reports/notices/<ip>.md -- for manual review and sending. Nothing here
sends email. Candidates with no contact found are skipped and listed
separately, since they should go via CSIRT instead of a direct notice.
"""
import argparse, csv, sys
from pathlib import Path
from csvsafe import safe_ip_filename

TEMPLATE = Path("templates/disclosure_email.md")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="reports/candidates_contacts.csv")
    ap.add_argument("--out", default="reports/notices")
    ap.add_argument("--sender-name", default="[your name]")
    ap.add_argument("--min-score", type=int, default=2,
                     help="skip low-confidence candidates (raise false-positive risk otherwise)")
    a = ap.parse_args()

    tpl = TEMPLATE.read_text()
    outdir = Path(a.out); outdir.mkdir(parents=True, exist_ok=True)
    no_contact, needs_review = [], []

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
        sec_contact = row.get("security_txt_contact")
        sec_insecure = bool(row.get("security_txt_insecure"))
        rdap_contact = row.get("rdap_abuse_contact")
        if sec_contact and not sec_insecure:
            contact = sec_contact  # read over HTTPS -- verified
        elif rdap_contact:
            contact = rdap_contact  # independent channel, not affected by the HTTP downgrade
        elif sec_contact:
            # Only an HTTP-sourced (unauthenticated) contact exists: an
            # on-path attacker could have forced that fallback just by
            # blocking the HTTPS port, no cert-spoofing needed, so this
            # address isn't verified. Don't auto-draft to it -- flag for
            # manual confirmation instead.
            needs_review.append(f"{row['ip']}: {sec_contact} (unverified, from plaintext HTTP)")
            continue
        else:
            no_contact.append(row["ip"])
            continue
        text = tpl
        for key, val in {"source": row.get("source") or "passive scan",
                         "ip": row["ip"] + (f" ({row['domain']})" if row.get("domain") else ""),
                         "port": row.get("port") or "?",
                         "sender_name": a.sender_name}.items():
            text = text.replace("{" + key + "}", str(val))
        (outdir / filename).write_text(f"<!-- send to: {contact} -->\n\n" + text)
        written += 1

    if skipped_invalid:
        print(f"[!] skipped {skipped_invalid} row(s) with an invalid 'ip' value "
              f"(not a real IP address -- possibly a crafted/corrupted input file)",
              file=sys.stderr)

    print(f"[+] drafted {written} notices in {outdir}")
    if no_contact:
        Path(outdir / "_no_contact_found.txt").write_text("\n".join(no_contact))
        print(f"[!] {len(no_contact)} candidates had no contact -- route these to your "
              f"national CSIRT instead (see README). Listed in _no_contact_found.txt")
    if needs_review:
        Path(outdir / "_needs_manual_verification.txt").write_text("\n".join(needs_review))
        print(f"[!] {len(needs_review)} candidate(s) only had an unverified (plaintext HTTP) "
              f"contact -- not auto-drafted. Confirm independently (e.g. via RDAP, or retry "
              f"later in case HTTPS was just temporarily down) before using them. Listed in "
              f"_needs_manual_verification.txt")

if __name__ == "__main__":
    main()
