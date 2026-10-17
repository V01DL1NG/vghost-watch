#!/usr/bin/env python3
"""
Run the full passive pipeline end to end: optional Shodan query, optional
import of your own host list, merge+triage, contact lookup, draft notices.
Meant to be invoked by hand, or by the optional cron / Task Scheduler
wrappers in scripts/ for a weekly local run -- there is no CI/remote
scheduler in this repo, this only runs on your own machine.

Each step is a subprocess call to the existing script (same ones the
Quick start section in README.md calls individually), so this file adds
no new network or filesystem behavior of its own.

If a .env file exists at the repo root (see scripts/init_env.sh /
init_env.ps1), it's loaded into the environment first (without overriding
anything already set).

Steps and how to skip them:
  - Shodan query    -- runs only if SHODAN_API_KEY is set in the environment
  - Import list     -- runs only if --hosts-csv points at an existing file
  - whois_contacts  -- OPTIONAL (scope change): this is the one step that
    reaches out about a host's *owner* (RDAP/security.txt), which only
    makes sense if you don't already know who owns it -- i.e. third-party
    disclosure. Checking your own perimeter, you already know the owner,
    so pass --self to skip this step and get a remediation note (for your
    own tracker) instead of a disclosure-notice draft.
  - merge_and_triage -- always runs
  - draft_notices (default) or draft_remediation (--self) -- always runs

Usage:
    python3 run_pipeline.py
    python3 run_pipeline.py --hosts-csv input/hosts.csv --sender-name "Jane Doe"
    python3 run_pipeline.py --shodan-query 'product:QEMU' --shodan-query 'port:16509,16514,8006'
    python3 run_pipeline.py --self --hosts-csv input/our_ranges.csv   # skip whois_contacts
"""
import argparse, os, subprocess, sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
ENV_FILE = Path(".env")

# Only these keys are honored from .env -- run_pipeline.py spawns every
# other script as a subprocess that inherits the full environment, so an
# unfiltered loader would let a .env file inject arbitrary variables
# (PYTHONPATH, LD_PRELOAD, etc.) into those subprocesses. Keep this list in
# sync with what scripts/init_env.sh|.ps1 write.
DOTENV_ALLOWED_KEYS = {"SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
                       "SENDER_NAME", "SHODAN_QUERY"}

def load_dotenv(path=ENV_FILE):
    """Minimal stdlib .env loader: KEY=VALUE lines, '#' comments, blank
    lines skipped. Only keys in DOTENV_ALLOWED_KEYS are applied. Never
    overrides a variable already set in the environment (so an explicit
    `export FOO=...` still wins)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key not in DOTENV_ALLOWED_KEYS:
            continue
        if key and key not in os.environ:
            os.environ[key] = val.strip()

def run(args, label):
    print(f"[*] {label}: {' '.join(args)}", file=sys.stderr)
    r = subprocess.run([sys.executable, *args], cwd=Path.cwd())
    if r.returncode != 0:
        sys.exit(f"[!] {label} failed (exit {r.returncode}); stopping")

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hosts-csv", default="input/hosts.csv",
                     help="your own list, passed to import_list.py if it exists (default: input/hosts.csv)")
    ap.add_argument("--shodan-query", action="append", default=[],
                     help="Shodan query, repeatable; skipped entirely if none given or no SHODAN_API_KEY")
    ap.add_argument("--sender-name", default="[your name]")
    ap.add_argument("--min-score", type=int, default=2)
    ap.add_argument("--self", action="store_true",
                     help="checking your own perimeter: skip whois_contacts (no need to look up "
                          "your own abuse contact) and write remediation notes instead of disclosure drafts")
    a = ap.parse_args()

    load_dotenv()

    if a.shodan_query:
        if os.environ.get("SHODAN_API_KEY"):
            args = [str(SRC / "shodan_query.py")]
            for q in a.shodan_query:
                args += ["--query", q]
            run(args, "Shodan query")
        else:
            print("[!] --shodan-query given but SHODAN_API_KEY not set; skipping", file=sys.stderr)

    if Path(a.hosts_csv).exists():
        run([str(SRC / "import_list.py"), "--in", a.hosts_csv], "Import host list")
    else:
        print(f"[*] {a.hosts_csv} not found; skipping host-list import", file=sys.stderr)

    run([str(SRC / "merge_and_triage.py")], "Merge + triage")

    if a.self:
        run([str(SRC / "draft_remediation.py"), "--min-score", str(a.min_score)],
            "Draft remediation notes")
        print("[+] pipeline complete -- review reports/remediation/ and file tickets as needed",
              file=sys.stderr)
    else:
        run([str(SRC / "whois_contacts.py")], "Lookup contacts")
        run([str(SRC / "draft_notices.py"), "--sender-name", a.sender_name,
             "--min-score", str(a.min_score)], "Draft notices")
        print("[+] pipeline complete -- review reports/notices/ before sending anything",
              file=sys.stderr)

if __name__ == "__main__":
    main()
