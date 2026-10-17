"""Neutralise spreadsheet formula injection and path traversal in
untrusted CSV cell values (candidates.csv / candidates_contacts.csv may
have come from a shared/crafted file, not just this pipeline's own
scripts)."""
import ipaddress, re

_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
# Allow-list for filenames built from an "ip" value: digits, letters, dot,
# underscore, hyphen. Everything else (colons, '%' IPv6 zone-id markers,
# '/', '\') is replaced with '_'. A blocklist isn't enough here -- an
# IPv6 zone id like "fe80::1%..\..\..\evil" passes ipaddress.ip_address()
# validation (it only rejects '/' in the address) and still contains
# backslashes, which traverse directories on Windows even though they
# don't on POSIX.
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

def safe(value):
    if isinstance(value, str) and value.startswith(_TRIGGERS):
        return "'" + value
    return value

def safe_row(row):
    return {k: safe(v) for k, v in row.items()}

def safe_rows(rows):
    return [safe_row(r) for r in rows]

def safe_ip_filename(ip, suffix=".md"):
    """Validate that `ip` is really an IP address and return a filename
    derived from it -- or None if it isn't a valid IP at all.

    Used wherever an output filename is built from a CSV's "ip" column.
    Two defenses, since a crafted/corrupted candidates.csv may not have
    come from this pipeline's own scripts:
      1. it must parse as a real IP address at all (rejects e.g.
         ip="../../../etc/cron.d/evil" outright), and
      2. the filename is then built from an allow-list of characters, not
         just colons blanked out -- an IPv6 zone id can smuggle other
         separators (e.g. backslashes, which traverse on Windows) through
         step 1, since ipaddress.ip_address() only rejects '/'."""
    try:
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    return _FILENAME_UNSAFE.sub("_", ip) + suffix
