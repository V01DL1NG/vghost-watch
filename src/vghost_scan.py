#!/usr/bin/env python3
"""
Check whether a host you're already authorized to access is running a
kernel vulnerable to CVE-2026-74580 ("Vghost"). This is the one
*actively-verifying* script in this repo, and it's scoped narrowly on
purpose (see SCOPE.md's "two separate, differently-authorized steps"):

  - It only reads `uname -r` and whether vhost kernel modules are loaded.
  - Nothing exploit-related, nothing that modifies the host.
  - It never authenticates on its own -- --local just runs locally;
    --ssh-host uses *your own* existing SSH access (keys/agent/config),
    the same as running `ssh host uname -r` yourself. No credentials are
    read, prompted for, or stored here.

Usage:
    python3 vghost_scan.py --local
    python3 vghost_scan.py --ssh-host admin@10.0.0.5 --confirm-authorized
    python3 vghost_scan.py --ssh-host myvm --ssh-opts "-i ~/.ssh/id_ed25519 -p 2222" --confirm-authorized
"""
import argparse, re, shlex, subprocess, sys

# Fixed-in versions per branch, from README's "Applicable only if" / the
# advisory this repo's templates link to. A branch not listed here isn't
# necessarily fine -- it's just outside what this script knows to check;
# verify against your distro's own advisory in that case.
FIXED_VERSIONS = {
    (5, 10): 265,
    (5, 15): 216,
    (6, 1): 183,
    (6, 6): 152,
    (6, 12): 104,
    (6, 18): 45,
    (7, 1): 9,
}

KERNEL_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_kernel(release):
    m = KERNEL_RE.match(release)
    return tuple(int(x) for x in m.groups()) if m else None


def classify(major, minor, patch):
    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return "unknown-branch"
    return "fixed" if patch >= fixed_patch else "vulnerable"


def run(cmd, ssh_target, ssh_opts):
    """cmd is always one of this file's own fixed literal strings, never
    built from user input -- ssh_opts is split with shlex (argv, not a
    shell) so it can't inject anything either way."""
    if ssh_target:
        argv = ["ssh", *(shlex.split(ssh_opts) if ssh_opts else []), ssh_target, cmd]
    else:
        argv = ["sh", "-c", cmd]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", action="store_true", help="check this machine")
    ap.add_argument("--ssh-host",
                     help="check a remote host via your own existing SSH access "
                          "(user@host, or an alias from your ssh config)")
    ap.add_argument("--ssh-opts",
                     help="extra args passed to ssh verbatim, e.g. '-i ~/.ssh/id_ed25519 -p 2222'")
    ap.add_argument("--confirm-authorized", action="store_true",
                     help="required with --ssh-host: confirms you have the owner's explicit "
                          "authorization to check this host (see SCOPE.md). Not required for "
                          "--local -- checking the machine you're already running on needs no "
                          "separate confirmation.")
    a = ap.parse_args()

    if bool(a.local) == bool(a.ssh_host):
        sys.exit("[!] specify exactly one of --local or --ssh-host")
    if a.ssh_host and not a.confirm_authorized:
        sys.exit("[!] --ssh-host requires --confirm-authorized -- you must have the owner's "
                  "explicit authorization to check this host (see SCOPE.md). If it's your own "
                  "host, running --local on it directly needs no such flag.")

    target = a.ssh_host  # None for --local

    rc, release, err = run("uname -r", target, a.ssh_opts)
    if rc != 0 or not release:
        sys.exit(f"[!] couldn't read kernel version: {err or 'no output'}")

    parsed = parse_kernel(release)
    if not parsed:
        sys.exit(f"[!] couldn't parse kernel release string: {release!r} "
                  f"(not a Linux kernel version? this check only applies to Linux)")
    major, minor, patch = parsed
    verdict = classify(major, minor, patch)

    _, vhost_out, _ = run(
        "lsmod 2>/dev/null | grep -E '^vhost' ; "
        "ls /sys/module/vhost_net /sys/module/vhost_scsi 2>/dev/null",
        target, a.ssh_opts,
    )
    vhost_in_use = bool(vhost_out.strip())

    print(f"kernel release : {release}")
    print(f"parsed version : {major}.{minor}.{patch}")
    print(f"vhost in use   : {'yes' if vhost_in_use else 'no'}")

    if verdict == "fixed":
        print(f"[+] {major}.{minor}.{patch} is at/above the fixed patch for the {major}.{minor} "
              f"branch -- not vulnerable to CVE-2026-74580")
    elif verdict == "vulnerable":
        print(f"[!] {major}.{minor}.{patch} is BELOW the fixed patch for the {major}.{minor} branch")
        if vhost_in_use:
            print("    vhost is in use on this host -- treat as vulnerable to CVE-2026-74580, "
                  "patch/upgrade the kernel")
        else:
            print("    vhost doesn't appear to be loaded right now -- the bug needs vhost-backed "
                  "virtualization to be exploitable, but patch anyway: that can change (a VM "
                  "started later, a module loaded on demand) without this check being re-run")
    else:
        print(f"[?] {major}.{minor} isn't one of the branches this script's fixed-version table "
              f"knows about -- check your distro's own security advisory for CVE-2026-74580")


if __name__ == "__main__":
    main()
