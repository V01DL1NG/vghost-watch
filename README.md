# vghost-watch

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](requirements.txt)
[![Passive only](https://img.shields.io/badge/scanning-passive%20only-success.svg)](SCOPE.md)

A perimeter-check and responsible-disclosure helper for
**CVE-2026-74580** ("Vghost") — a real Linux kernel `vhost` metadata-cache
bug ([CVE record](https://access.redhat.com/security/cve/CVE-2026-74580),
[OSV entry](https://osv.dev/vulnerability/CVE-2026-74580)) that gives
local-privesc / VM-escape on exposed vhost/hypervisor hosts.

**Primary use case: check your own perimeter.** Feed in your own IP
ranges, CIDRs, or domains (`import_list.py`) — internal or external — and
triage them for vhost-adjacent exposure (libvirt/Proxmox/QEMU management
ports), then get remediation notes for your own tracker
(`run_pipeline.py --self`, see "Checking your own perimeter" below). No
auto-discovery, no mass contact lookup — you already own the host.

**Secondary capability: third-party discovery via public scan data.**
This project does **not** scan the internet itself — it can optionally
query datasets/APIs that already did the scanning (Rapid7 Open Data /
Sonar, Shodan, Censys) to find *other* exposed hosts, then help you draft
disclosure notices to their owners. Worth knowing before you invest time
here: there's no bounty for this (CSIRTs don't pay, and "known CVE,
unpatched instance" reports are rarely bounty-eligible — see "Impact"
below) — it's unpaid, good-citizen notification work, and most real
usage of this repo is the perimeter-check case above, not this one.

## Impact: when is this applicable / critical?

CVE-2026-74580 is a **kernel-level, local** bug, not a web/network-facing
one -- a few things follow from that which matter for triage:

**Applicable only if all of these hold:**
- The host runs an unpatched **Linux kernel** (below 5.10.265, 5.15.216,
  6.1.183, 6.6.152, 6.12.104, 6.18.45, 7.1.9, or the distro backport).
- It uses **vhost-backed virtualization** (`vhost-net`/`vhost-scsi` via
  QEMU/KVM, typically through libvirt or Proxmox). A bare-metal host with
  no VMs, or VMs on plain `virtio` without vhost offload, isn't exposed to
  this bug regardless of patch level.
- **Local code execution is a prerequisite.** This is privesc/VM-escape,
  not remote code execution -- an attacker needs to already be running
  code somewhere that reaches the vulnerable interface: a guest VM, a
  shared-kernel container, or a local account on the host. "Already
  running code" doesn't require direct access like SSH -- in practice it's
  most often one of:
  - **A legitimate tenant**, on a multi-tenant/cloud hypervisor -- a
    customer who simply rented a VM already has full code execution
    inside it, by design, no breach needed.
  - **An unrelated compromise inside the guest** -- most commonly a
    vulnerable web app getting RCE'd (an outdated plugin, SSRF-to-RCE,
    deserialization bug, etc.), but any guest-side compromise works the
    same way. The vhost bug doesn't care how the attacker got in, only
    that they now have code execution to pivot from.

**The real severity driver is who already has (or can get) code
execution -- not whether the host is internet-facing.** Internet exposure
only affects how easily an *outside* attacker finds the target or reaches
the initial foothold remotely; it changes nothing about whether the bug
is exploitable once someone has that foothold. Internal-only, private
infrastructure is **not** inherently lower risk:

**Most critical, regardless of internet exposure:**
- **Any multi-tenant or multi-user hypervisor** -- hosting providers,
  but just as much an internal private cloud, an internal VM-per-team
  platform, or a shared dev/test environment with ordinary user accounts
  on VMs/apps. Every one of those users or tenants *already* has the
  code-execution prerequisite, by design, with zero breach required --
  internet-facing or not.
- **Any host where an attacker already has a toehold** (compromised VM,
  insider shell, a co-located container escape, a compromised internal
  app) with vhost offload in use -- this turns "I have a low-priv shell"
  into "I own the host," regardless of how that shell was obtained.

**Where internet exposure actually matters (a secondary factor, not the
primary one):**
- It makes the *initial* foothold easier for an *external* attacker to
  get remotely (e.g. a web app RCE, see the WAF note below) and makes
  the host easier to find in the first place -- **exposed management
  ports** (libvirt 16509/16514, Proxmox 8006) are a reconnaissance
  signal for that, which is what `merge_and_triage.py`'s scoring looks
  for. An exposed port proves nothing by itself, though -- it only
  matters once something attacker-controlled can execute locally, which
  passive scan data can't show (see "Why passive-only" below for why
  this repo doesn't try to confirm that against hosts you don't own).
- An **internal-only** host with the same multi-user/multi-tenant
  exposure is equally critical -- it just needs an internal user, a
  contractor, or a compromised internal app to supply the foothold
  instead of an internet-facing one. Don't read "not internet-facing" as
  "lower priority."

**Genuinely lower severity:**
- **Single-tenant, no untrusted guests, users, or apps at all** -- the
  only "attacker" would be you, so real-world risk is much lower. Still
  worth patching so a future unrelated compromise can't chain into this.
- **No vIOMMU** -- per the advisory, the VM-escape path specifically needs
  a vIOMMU-enabled setup; without it, impact is likely capped at local
  privesc inside the kernel rather than crossing the guest/host boundary.

**Does a WAF help?** Not against this bug directly -- a WAF inspects
HTTP(S) traffic, and this bug lives in the kernel's vhost metadata-cache
path, not in request parsing. It's simply not in the exposure path for
the vulnerability itself.

Where a WAF *does* matter is one step earlier: the most common real-world
chain is **web app RCE → code execution inside the guest → vhost exploit
→ host escape → lateral movement to every other tenant**. A WAF (or other
web-security controls) can block the web-app RCE that hands an attacker
their initial foothold, which prevents them from ever reaching the
prerequisite for this bug in the first place. So: irrelevant to the vhost
bug itself, but relevant to one of the most common *paths into* the
precondition for it.

What actually reduces risk, end to end: patching the kernel, disabling
vhost offload where it's not needed, not exposing libvirt/Proxmox
management ports to the internet, hardening the web apps/services running
inside guests (reducing the odds of that initial RCE), and tenant-isolation
hardening (seccomp, namespaces) to make any foothold harder to get.

## Why passive-only, by design

Actively port-scanning or SSH-probing systems you don't own or have written
authorization for is unauthorized access in most jurisdictions (in the EU,
this falls under Directive 2013/40/EU implementations; Czech law covers it
under § 230 trestního zákoníku) and a ToS violation for most hosts/clouds —
**regardless of good intent**. This repo only ever reads data that
third-party scanners already collected and published/sold access to under
their own authorization. See [`SCOPE.md`](SCOPE.md).

If you want to verify a specific finding (confirm a host is actually
vulnerable, not just "looks exposed"), that requires the owner's
permission — see the disclosure template, which asks for exactly that.

## Pipeline

1. **`src/sonar_query.py`** — parse Rapid7 Open Data / Sonar scan files
   (free download, no account) for vhost-adjacent ports/banners.
2. **`src/shodan_query.py`** / **`src/censys_query.py`** — optional,
   free-tier API queries for the same signatures (useful for fresher data
   than Sonar's periodic dumps).
3. **`src/merge_and_triage.py`** — merges results, dedupes, scores
   likelihood of exposure, outputs `reports/candidates.csv`.
4. **`src/whois_contacts.py`** — *optional* (see below) — looks up
   abuse/security contact per candidate (RDAP + `security.txt` fetch) for
   disclosure routing.
5. **`src/draft_notices.py`** — fills `templates/disclosure_email.md` per
   candidate into `reports/notices/`, for YOU to review and send manually.

Nothing in this pipeline emails or contacts anyone automatically — notices
are drafted for manual review and sending, and findings for large numbers
of orgs should go through your national CSIRT instead (see below).

### Checking your own perimeter instead of a third party's

Steps 4–5 above (contact lookup, disclosure drafting) only make sense when
you *don't* already know who owns a host -- i.e. notifying a stranger. If
you're instead feeding in your own IP ranges/domains (Option B below) to
see what public scan data says about your own exposure, you already know
the owner, so skip `whois_contacts.py` entirely and use
**`src/draft_remediation.py`** instead of `draft_notices.py` -- it fills
`templates/remediation_note.md` per candidate into `reports/remediation/`
(a ticket for your own tracker, not a disclosure email; no RDAP/
`security.txt` lookup needed). `run_pipeline.py --self` does this
automatically (see "Optional: run it weekly" below).

**This also works for internal hosts**, not just internet-facing ones.
`import_list.py`/`merge_and_triage.py` never connect to the target host in
`--self` mode -- they only resolve DNS (for domains/FQDNs) and do CIDR
arithmetic, then score metadata you already supplied. So private IP
ranges (`10.x`, `172.16.x`, `192.168.x`), internal FQDNs, and CNAMEs all
work, as long as wherever you run this can resolve/reach them (e.g. your
internal network or VPN) -- `--self` already skips the one step
(`whois_contacts.py`) that has SSRF restrictions, since there's no third
party to look up a contact for. Shodan/Censys/Sonar obviously won't cover
internal hosts (they only index the public internet); feed your own
internal inventory through Option B instead.

**Confirming a flagged host, not just triaging it:** everything above is
passive triage (port/banner signals) -- it never tells you whether a
given host's kernel is actually unpatched. For that, on a host you
already have authorized access to (per `SCOPE.md`'s Scenario B), use
**`src/vghost_scan.py`**: it reads `uname -r` and whether vhost kernel
modules are loaded (nothing exploit-related, nothing that modifies the
host), then checks that against the fixed-version table above.

```bash
python3 src/vghost_scan.py --local                                          # the machine you're already on
python3 src/vghost_scan.py --ssh-host admin@10.0.0.5 --confirm-authorized   # a host you control, via your own SSH access
```

It checks one explicitly-named host per run -- no bulk/list input, no
credential guessing, no discovery. `--ssh-host` uses your existing SSH
access (keys/agent/config) as-is; it never reads, prompts for, or stores
credentials itself.

## Quick start

Run everything from the repo root -- every script uses paths relative to
the current directory (`data/`, `reports/`, `templates/`, `config/`), not
relative to the script itself.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Option A: free Rapid7 Sonar datasets (no key, large download)
python3 src/sonar_query.py --file sonar_tcp_16509.json.gz --port 16509 --port 16514 --port 8006

# Option B: your own list -- CSV with an "ip" and/or "domain" column (+ optional "port", other columns kept).
# The "ip" column may also hold a CIDR range (e.g. 203.0.113.0/24); it's expanded to
# individual addresses as passive-lookup candidates, capped by --max-hosts (default 65536).
python3 src/import_list.py --in hosts.csv
python3 src/import_list.py --in ranges.csv --max-hosts 4096

# Option C: Shodan free tier (set SHODAN_API_KEY env var)
python3 src/shodan_query.py --query 'product:QEMU' --query 'port:16509,16514'

# scoring ports/keywords live in config/scoring.json
python3 src/merge_and_triage.py --out reports/candidates.csv
python3 src/whois_contacts.py --in reports/candidates.csv --out reports/candidates_contacts.csv
python3 src/draft_notices.py --in reports/candidates_contacts.csv --out reports/notices/
```

Everything above runs locally -- there's no CI/scheduled job in this repo.
API keys (`SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`) are read
from your own shell's environment, and any list CSV you use (Option B)
stays on your machine unless you choose to commit or share it.

To set those keys up once instead of exporting them by hand each time, run
`scripts/init_env.sh` (Linux/macOS) or `scripts/init_env.ps1` (Windows) --
it interactively writes a `.env` at the repo root (gitignored, never
committed). `src/run_pipeline.py` below loads it automatically.

### Optional: run it weekly on your own machine

`src/run_pipeline.py` chains the steps above (import list if present →
merge/triage → contacts → draft notices; Shodan only if you pass
`--shodan-query` and `SHODAN_API_KEY` is set). Pass `--self` to check your
own perimeter instead of a third party's -- this skips `whois_contacts.py`
and writes remediation notes (`reports/remediation/`) instead of
disclosure drafts:

```bash
python3 src/run_pipeline.py --hosts-csv input/hosts.csv --sender-name "Jane Doe"
python3 src/run_pipeline.py --self --hosts-csv input/our_ranges.csv
```

To run that on a schedule without any CI/remote service, two opt-in
wrappers are included -- neither is installed automatically, you register
them yourself:

- **cron** (Linux/macOS): `scripts/weekly_cron.sh` -- see the comment at
  the top of the file for the `crontab -e` line to add.
- **Task Scheduler** (Windows): `scripts/weekly_task.ps1` -- see the
  comment at the top of the file for the `schtasks /Create` command.

Both just run `run_pipeline.py` from the repo root on your machine, at
whatever interval you set; nothing leaves your machine except the API/RDAP
requests the scripts already make.

## Reporting at scale

For more than a handful of findings, route through your national CSIRT
instead of individually emailing every owner — they have the mandate and
relationships to notify at scale and will often already have overlapping
data:

- Czech Republic: **CSIRT.CZ** (CZ.NIC) — https://csirt.cz
- General EU: your national CSIRT via https://cert.europa.eu or ENISA's
  network of CSIRTs
- For a specific org, always prefer their own `/.well-known/security.txt`
  contact if published.

## Legal

Read [`SCOPE.md`](SCOPE.md) before running anything. You are responsible
for how you use the output. This is published as-is, no warranty — see
[`LICENSE`](LICENSE).
