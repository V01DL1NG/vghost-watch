Subject: Possible exposed vhost/hypervisor management interface — CVE-2026-74580

Hello,

I'm doing unpaid, volunteer security-notification work, not acting on
behalf of any company, and I am not asking for payment or access.

Passive internet-scan data (source: {source}) shows a host at {ip}
(port {port}) responding in a way consistent with an exposed
libvirt/Proxmox/QEMU management interface. If this is one of your systems:

You may want to check whether it's affected by **CVE-2026-74580**
("Vghost"), a Linux kernel vhost metadata-cache bug that can allow local
privilege escalation and, in virtualized setups using vIOMMU, a VM-escape
path to the host. Public writeup and PoC are already circulating:
https://www.openwall.com/lists/oss-security/2026/10/14/2
CVE record: https://access.redhat.com/security/cve/CVE-2026-74580

Fixed upstream kernel versions: 5.10.265, 5.15.216, 6.1.183, 6.6.152,
6.12.104, 6.18.45, 7.1.9 (or your distro's backported equivalent —
Debian, RHEL/Amazon Linux, and Oracle all have advisories out already).

I have not attempted to log into, authenticate against, or otherwise
access this host — this notice is based solely on passive, already-public
scan data showing an open port. If you'd like help verifying or scoping
this further, I'm happy to, but only with your explicit go-ahead.

Best,
{sender_name}

---
(This is a template filled by draft_notices.py — review before sending.
Do not mass-send; personalize and send individually.)
