# Scope

This repo targets **CVE-2026-74580** ("Vghost") — see the
[Red Hat CVE record](https://access.redhat.com/security/cve/CVE-2026-74580)
and [OSV entry](https://osv.dev/vulnerability/CVE-2026-74580) (the OSV
entry's fixed-version table is the source for the versions used
throughout this repo's templates and `vghost_scan.py`).

This repo supports two distinct scenarios. They have different
authorization bases, so keep them separate rather than mixing them.

## Scenario A: third-party discovery + disclosure

Finding hosts you don't own or control, so you can notify the owner.

**In scope:**
- Querying **already-published, third-party-authorized** scan datasets and
  APIs: Rapid7 Open Data/Sonar, Shodan, Censys, and similar services whose
  own scanning is conducted under their own legal basis.
- RDAP/WHOIS lookups and fetching `/.well-known/security.txt` from
  candidate hosts (both are standard, intended-for-this-purpose,
  unauthenticated reads of public metadata — not probing the host's
  services).
- Drafting (not sending) disclosure notices for manual review
  (`draft_notices.py`).

**Out of scope -- deliberately not done, ever, in this scenario:**
- **No active scanning** (nmap, masscan, zmap, custom port probes, banner
  grabs) against hosts you don't own or lack written authorization for.
- **No authentication attempts** (SSH, API, web login) against third-party
  hosts. `vghost_scan.py` (Scenario B, below) must never be pointed at a
  host sourced from Scenario A's discovery scripts.
- **No automated mass-emailing.** Notices are drafted to a local folder for
  you to read and send yourself.
- **No exploitation or PoC execution** against third-party hosts, ever,
  under any circumstance, even "just to confirm."
- Confirming exploitability on a specific third-party host requires that
  owner's explicit, written authorization -- at which point you've moved
  into Scenario B for that host, not this one.

## Scenario B: your own (or your org's) assets

Checking infrastructure you already have a legitimate basis to access --
your own IP ranges/domains, internal or external, fed in as a predefined
CSV (`import_list.py --domain-col`/`--ip-col`, including CIDR ranges and
internal FQDNs) that you control. **There is no auto-discovery here and
never will be** -- nothing in this repo crawls, enumerates, or scans the
broader internet (or your internal network) to *find* targets for this
scenario; every host checked is one you explicitly listed.

**In scope:**
- Triaging your own predefined host list (`merge_and_triage.py`) and
  drafting remediation notes for your own tracker (`draft_remediation.py`,
  `run_pipeline.py --self`) -- no contact lookup needed, you already know
  who owns it.
- **`vghost_scan.py`** -- the one actively-verifying script in this repo,
  scoped narrowly to this scenario only: it reads `uname -r` and whether
  vhost kernel modules are loaded, nothing exploit-related, nothing that
  modifies the host. `--local` needs no extra flag (checking the machine
  you're already running on is self-evidently authorized). `--ssh-host`
  requires `--confirm-authorized` and uses *your own* existing SSH access
  (keys/agent/config) -- it never discovers hosts, brute-forces
  credentials, or accepts a list/range as a target; you name one host at
  a time, explicitly, every time.

**Out of scope here too:**
- `vghost_scan.py` is not a scanner: no bulk/list input, no credential
  guessing, no CIDR expansion of its own. One explicitly named host per
  invocation.
- Still no exploitation/PoC execution -- confirming the kernel version and
  whether vhost is loaded is as far as this repo goes, even against your
  own assets.

## Rate limits / good citizenship

- Respect Rapid7 Open Data, Shodan, and Censys's own terms of service and
  rate limits — scripts here default to conservative request pacing.
- RDAP/`security.txt` fetches are capped and cached locally
  (`data/contacts_cache.json`) to avoid hammering registrars or target
  servers even with benign, read-only requests.
