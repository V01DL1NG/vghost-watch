#!/usr/bin/env python3
"""
For each candidate IP, find a contact to notify:
  1. RDAP lookup (via rdap.org bootstrap) for the network's abuse contact.
  2. GET http://<domain or ip>/.well-known/security.txt (read-only, standard-intended
     metadata fetch -- not a probe of any service logic).

Both are passive, read-only, and exactly what these mechanisms exist for.
Results are cached locally to avoid repeat lookups.
"""
import argparse, csv, ipaddress, json, re, socket, sys, time
import http.client, ssl
import urllib.request
from csvsafe import safe_rows
from pathlib import Path

CACHE = Path("data/contacts_cache.json")
MISS_TTL_SECONDS = 30 * 24 * 3600  # re-try "no contact found" after 30 days
                                    # (a transient RDAP/DNS hiccup shouldn't
                                    # be cached as a permanent no-contact)

def load_cache():
    return json.loads(CACHE.read_text()) if CACHE.exists() else {}

def cache_is_fresh(entry):
    """A verified hit -- an RDAP contact, or a security_txt contact read
    over HTTPS -- is cached indefinitely. An HTTP-sourced (insecure,
    unverified) security_txt contact with no RDAP corroboration is
    treated like a miss instead and expires after MISS_TTL_SECONDS: an
    on-path attacker can force that fallback just by blocking port 443
    once, so caching it forever would let a single successful downgrade
    permanently poison this value instead of the script ever retrying
    for a verified contact once HTTPS is reachable again."""
    rdap_hit = entry.get("rdap_abuse_contact")
    sec_hit = entry.get("security_txt_contact")
    sec_insecure = bool(entry.get("security_txt_insecure"))
    verified_hit = rdap_hit or (sec_hit and not sec_insecure)
    if verified_hit:
        return True
    return (time.time() - entry.get("fetched_at", 0)) < MISS_TTL_SECONDS

def save_cache(c):
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(c))

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")

def resolve_public(host):
    """SSRF guard: resolve once and return the addresses only if ALL are globally
    routable (else None). Callers must connect to the returned IP, not re-resolve."""
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        if not HOST_RE.match(host.lower()):
            return None
        try:
            addrs = sorted({i[4][0] for i in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
        except socket.gaierror:
            return None
    if addrs and all(ipaddress.ip_address(a).is_global for a in addrs):
        return addrs
    return None

def is_public_host(host):
    return resolve_public(host) is not None

class _PinnedHTTP(http.client.HTTPConnection):
    """Connects to a pre-validated IP; Host header still carries the hostname."""
    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._ip = ip
    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)

class _PinnedHTTPS(http.client.HTTPSConnection):
    """As above, with TLS verification and SNI against the original hostname."""
    def __init__(self, host, ip, **kw):
        super().__init__(host, context=ssl.create_default_context(), **kw)
        self._ip = ip
    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

def clean_contact(value):
    """Accept only a plain email, mailto: or https: URL from untrusted security.txt."""
    v = (value or "").strip()
    if v.lower().startswith("mailto:"):
        v = v[7:].split("?", 1)[0]
        return v if EMAIL_RE.match(v) else ""
    if v.lower().startswith("https://") and not re.search(r"[\s<>\"]", v):
        return v
    return v if EMAIL_RE.match(v) else ""

def rdap_abuse(ip):
    if not is_public_host(ip):
        return None
    try:
        with urllib.request.urlopen(f"https://rdap.org/ip/{ip}", timeout=15) as r:
            data = json.load(r)
    except Exception:
        return None
    for ent in data.get("entities", []):
        if "abuse" in ent.get("roles", []):
            for vc in ent.get("vcardArray", [[], []])[1]:
                if vc[0] == "email":
                    return clean_contact(vc[3]) or None
    return None

def _fetch_security_txt(cls, host, ip):
    conn = cls(host, ip, timeout=8)
    try:
        conn.request("GET", "/.well-known/security.txt",
                     headers={"User-Agent": "vghost-watch-disclosure-research"})
        resp = conn.getresponse()  # redirects are never followed
        if resp.status != 200:
            return None
        text = resp.read(4000).decode("utf-8", "ignore")
        for line in text.splitlines():
            if line.lower().startswith("contact:"):
                return clean_contact(line.split(":", 1)[1]) or None
        return None
    finally:
        conn.close()

def security_txt(host):
    """Returns (contact, insecure). insecure=True means the contact was
    read over plaintext HTTP, not HTTPS -- callers must not treat that the
    same as a verified contact (see security_txt_insecure handling in
    draft_notices.py): an on-path attacker can force this fallback simply
    by blocking the HTTPS port, with no cert-spoofing needed, so an
    HTTP-sourced contact is unauthenticated and should require independent
    confirmation (e.g. the RDAP abuse contact) before anything is sent to
    it."""
    addrs = resolve_public(host)
    if not addrs:
        return None, False
    ip = addrs[0]  # validated once; the connection is pinned to it (no re-resolution)

    try:
        contact = _fetch_security_txt(_PinnedHTTPS, host, ip)
        return contact, False
    except ssl.SSLError:
        # TLS handshake/certificate verification failed -- possibly an
        # active on-path attacker presenting an invalid cert. Fail closed
        # rather than falling back to plaintext HTTP: that would hand
        # that same attacker control over the contact address this
        # script routes disclosure to.
        return None, False
    except Exception:
        pass  # https unreachable for an unrelated reason (connection
              # refused, timeout, ...) -- plausibly this host just
              # doesn't serve https.

    try:
        contact = _fetch_security_txt(_PinnedHTTP, host, ip)
        return contact, bool(contact)
    except Exception:
        return None, False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", default="reports/candidates.csv")
    ap.add_argument("--out", default="reports/candidates_contacts.csv")
    ap.add_argument("--max-third-party-lookups", type=int, default=50,
                     help="cap on new RDAP/security.txt lookups for third-party-sourced "
                          "candidates (source != 'list', i.e. not your own import_list.py "
                          "input) per run. Past this many strangers in one run, a 'passive "
                          "lookup' starts to look like a contact-harvesting campaign rather "
                          "than a handful of disclosure lookups. Your own list (--self "
                          "workflows, source='list') is never capped by this -- raise this "
                          "explicitly if you really mean to look up this many strangers.")
    a = ap.parse_args()

    cache = load_cache()
    with open(a.inp) as f:
        rows = list(csv.DictReader(f))

    def row_key(row):
        domain = (row.get("domain") or "").strip()
        return f"{row['ip']}|{domain}" if domain else row["ip"]

    pending_third_party = [
        row for row in rows
        if (row.get("source") or "") != "list"
        and (row_key(row) not in cache or not cache_is_fresh(cache[row_key(row)]))
    ]
    if len(pending_third_party) > a.max_third_party_lookups:
        sys.exit(
            f"[!] {len(pending_third_party)} third-party-sourced candidates (not from your "
            f"own list) need a new RDAP/security.txt lookup this run -- over the "
            f"--max-third-party-lookups cap ({a.max_third_party_lookups}). Stopping before "
            f"making any of those requests. Re-run with a higher "
            f"--max-third-party-lookups if you really mean to look up this many strangers, "
            f"or filter reports/candidates.csv down first."
        )

    for row in rows:
        ip = row["ip"]
        domain = (row.get("domain") or "").strip()
        key = f"{ip}|{domain}" if domain else ip
        if key not in cache or not cache_is_fresh(cache[key]):
            sec_contact, sec_insecure = security_txt(domain or ip)
            cache[key] = {
                "security_txt_contact": sec_contact or "",
                "security_txt_insecure": "insecure-http" if (sec_contact and sec_insecure) else "",
                "rdap_abuse_contact": rdap_abuse(ip) or "",
                "fetched_at": time.time(),
            }
            save_cache(cache)
            time.sleep(0.5)
        row.update({k: v for k, v in cache[key].items() if k != "fetched_at"})

    fields = list(rows[0].keys()) if rows else ["ip"]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(safe_rows(rows))
    print(f"[+] wrote {len(rows)} rows with contacts -> {a.out}")

if __name__ == "__main__":
    main()
