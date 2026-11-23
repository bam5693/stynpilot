"""Deterministic gate: may an AI even ask the owner to approve this package set? (pure functions, no I/O)

The AI may now NAME Ubuntu packages (owner decision 2026-11-23), so this gate decides, with fixed rules and
no AI input, what is refused outright and what the owner is told plainly before he approves.

* REFUSED (BLACK for an AI): kernels, bootloader, firmware, login/privilege machinery (sudo, PAM, polkit,
  ssh server), core system packages, firewalls and network managers, remote-access servers, container
  runtimes (they arrive through a separately reviewed container executor), display managers, anything that
  would remove a package, upgrade a core package, or that StyNpilot itself owns. After download the root
  installer also refuses a package that ships files under /boot, /lib/modules, sudoers, PAM, ssh, apt or
  polkit-rules directories.
* NOTES (shown to the owner, same approval): adds a server that may listen on the network, ships a
  background service or a setuid program, is very large, upgrades packages that are already installed.

A signed Ubuntu source proves where a package came from. It does not prove the package is harmless: every
Ubuntu package may run install scripts as root. The summary says so every time.

The same functions run in the owner-side request tool (early, friendly refusal) and in the root installer
(authoritative). Keep this table short and boring; extend it only with the owner's review.
"""
from __future__ import annotations

import fnmatch
import re

# (pattern, stable code, plain words)  -- first match wins
_REFUSED = (
    ("linux-image-*", "kernel_or_boot", "a Linux kernel"), ("linux-modules-*", "kernel_or_boot", "kernel modules"),
    ("linux-modules", "kernel_or_boot", "kernel modules"),
    ("linux-generic*", "kernel_or_boot", "a kernel package"), ("linux-lowlatency*", "kernel_or_boot", "a kernel package"),
    ("linux-virtual*", "kernel_or_boot", "a kernel package"), ("linux-kvm*", "kernel_or_boot", "a kernel package"),
    ("grub*", "kernel_or_boot", "the bootloader"), ("shim*", "kernel_or_boot", "the secure-boot loader"),
    ("efibootmgr", "kernel_or_boot", "boot entries"), ("systemd-boot*", "kernel_or_boot", "the bootloader"),
    ("initramfs-tools*", "kernel_or_boot", "the boot image tools"), ("dracut*", "kernel_or_boot", "the boot image tools"),
    ("fwupd*", "kernel_or_boot", "firmware updates"), ("linux-firmware", "kernel_or_boot", "firmware"),
    ("sudo", "login_or_privilege", "sudo"), ("sudo-*", "login_or_privilege", "sudo"), ("doas", "login_or_privilege", "doas"),
    ("libpam*", "login_or_privilege", "login (PAM)"), ("pam-*", "login_or_privilege", "login (PAM)"),
    ("polkit*", "login_or_privilege", "polkit"), ("libpolkit*", "login_or_privilege", "polkit"),
    ("pkexec", "login_or_privilege", "polkit"), ("policykit*", "login_or_privilege", "polkit"),
    ("openssh-server", "remote_access", "an SSH server"), ("ssh", "remote_access", "an SSH server"),
    ("xrdp", "remote_access", "a remote desktop server"), ("x11vnc", "remote_access", "a remote desktop server"),
    ("tigervnc-*server*", "remote_access", "a remote desktop server"), ("tightvncserver", "remote_access", "a remote desktop server"),
    ("vino", "remote_access", "a remote desktop server"), ("telnetd", "remote_access", "a remote login server"),
    ("vsftpd", "remote_access", "an FTP server"), ("proftpd*", "remote_access", "an FTP server"),
    ("pure-ftpd*", "remote_access", "an FTP server"), ("nfs-kernel-server", "remote_access", "a file-sharing server"),
    ("samba", "remote_access", "a file-sharing server"), ("tailscale*", "network_or_firewall", "Tailscale"),
    ("systemd", "core_system", "systemd"), ("systemd-*", "core_system", "systemd"), ("libsystemd*", "core_system", "systemd"),
    ("udev", "core_system", "udev"), ("dbus", "core_system", "the system message bus"),
    ("dbus-daemon", "core_system", "the system message bus"), ("dbus-user-session", "core_system", "the session bus"),
    ("apt", "core_system", "apt"), ("apt-*", "core_system", "apt"), ("libapt*", "core_system", "apt"),
    ("dpkg", "core_system", "dpkg"), ("dpkg-*", "core_system", "dpkg"), ("libc6*", "core_system", "the C library"),
    ("libc-bin", "core_system", "the C library"), ("base-files", "core_system", "base system files"),
    ("base-passwd", "core_system", "base system files"), ("login", "core_system", "login"), ("passwd", "core_system", "passwords"),
    ("util-linux", "core_system", "core system tools"), ("coreutils", "core_system", "core system tools"),
    ("bash", "core_system", "the shell"), ("dash", "core_system", "the shell"), ("init-system-helpers", "core_system", "init"),
    ("ca-certificates", "core_system", "the certificate store"), ("ubuntu-keyring", "core_system", "package signing keys"),
    ("ubuntu-pro-client*", "core_system", "Ubuntu Pro"), ("ubuntu-advantage-tools", "core_system", "Ubuntu Pro"),
    ("software-properties-*", "core_system", "software sources"),
    ("ufw", "network_or_firewall", "a firewall"), ("gufw", "network_or_firewall", "a firewall"),
    ("iptables*", "network_or_firewall", "a firewall"), ("nftables", "network_or_firewall", "a firewall"),
    ("firewalld", "network_or_firewall", "a firewall"), ("netplan*", "network_or_firewall", "network configuration"),
    ("network-manager*", "network_or_firewall", "network configuration"),
    ("networkd-dispatcher", "network_or_firewall", "network configuration"), ("wpasupplicant", "network_or_firewall", "network configuration"),
    ("ifupdown", "network_or_firewall", "network configuration"), ("resolvconf", "network_or_firewall", "network configuration"),
    ("docker*", "container_runtime", "a container runtime"), ("containerd*", "container_runtime", "a container runtime"),
    ("runc", "container_runtime", "a container runtime"), ("podman*", "container_runtime", "a container runtime"),
    ("lxd*", "container_runtime", "a container runtime"), ("libvirt-daemon*", "container_runtime", "a virtual machine manager"),
    ("sddm*", "login_or_privilege", "the login screen"), ("gdm3", "login_or_privilege", "the login screen"),
    ("lightdm*", "login_or_privilege", "the login screen"), ("kubuntu-desktop", "core_system", "the desktop itself"),
    ("ubuntu-desktop*", "core_system", "the desktop itself"), ("plasma-desktop", "core_system", "the desktop itself"),
    ("cryptsetup*", "disk_or_encryption", "disk encryption"), ("lvm2", "disk_or_encryption", "disk volumes"),
    ("mdadm", "disk_or_encryption", "disk arrays"), ("zfs*", "disk_or_encryption", "disk volumes"),
    ("stynpilot*", "stynpilot_itself", "StyNpilot itself"), ("forgejo*", "stynpilot_itself", "software StyNpilot already manages"),
)
# Shown to the owner; not refused.
_SERVER_LIKE = ("*-server", "*-daemon", "nginx*", "apache2*", "postgresql*", "mysql-server*", "mariadb-server*", "redis-server*",
                "mongodb*", "bind9*", "dnsmasq*", "squid*", "mosquitto*", "cups-browsed")
LARGE_KB = 500 * 1024
CORE_PRIORITIES = ("required", "important")
_PLAIN_REFUSAL = {
    "kernel_or_boot": "kernels, boot loaders and firmware",
    "login_or_privilege": "login, sudo, polkit and the login screen",
    "remote_access": "remote-access and file-sharing servers",
    "core_system": "core operating-system packages",
    "network_or_firewall": "firewalls and network configuration",
    "container_runtime": "container runtimes (they need StyNpilot's separately reviewed container installer)",
    "disk_or_encryption": "disk and encryption tools",
    "stynpilot_itself": "StyNpilot's own software",
}


def _match(name):
    for pattern, code, words in _REFUSED:
        if fnmatch.fnmatchcase(name, pattern):
            return code, words
    return None


def refusal_for(name):
    """Stable refusal code if this package name is never installable by an AI, else None."""
    found = _match(name)
    return found[0] if found else None


def explain(code):
    """One plain sentence for a refusal code, for the AI and the owner."""
    if code in _PLAIN_REFUSAL:
        return "StyNpilot does not let an AI install %s." % _PLAIN_REFUSAL[code]
    return {"would_remove_packages": "That install would remove installed software.",
            "would_upgrade_core_package": "That install would change a core operating-system package.",
            "package_touches_login_or_boot_files": "That package changes login, boot, sudo or package-signing files."}.get(
        code, "StyNpilot refuses this package set.")


def check_transaction(requested, transaction):
    """(refusal_code or None, [plain notes]) for a simulated install.

    transaction: {"installs": {name: version}, "upgrades": {name: old_version}, "removals": [names],
                  "meta": {name: {"essential": bool, "priority": str, "installed_size_kb": int}}}
    Only names apt would actually install or upgrade are judged; unchanged dependencies are not.
    """
    installs = dict(transaction.get("installs") or {})
    upgrades = dict(transaction.get("upgrades") or {})
    meta = transaction.get("meta") or {}
    if transaction.get("removals"):
        return "would_remove_packages", []
    for name in sorted(set(requested) | set(installs)):
        found = _match(name)
        if found:
            return found[0], []
    for name in sorted(upgrades):
        info = meta.get(name) or {}
        if info.get("essential") or info.get("priority") in CORE_PRIORITIES:
            return "would_upgrade_core_package", []
    for name in sorted(installs):
        if (meta.get(name) or {}).get("essential"):
            return "core_system", []
    notes = []
    servers = sorted(n for n in installs if any(fnmatch.fnmatchcase(n, p) for p in _SERVER_LIKE))
    if servers:
        notes.append("Likely adds a server that may listen on the network: %s." % ", ".join(servers[:5]))
    if upgrades:
        notes.append("Also upgrades %d package(s) that are already installed: %s." % (
            len(upgrades), ", ".join("%s (%s to %s)" % (n, upgrades[n], installs.get(n, "?")) for n in sorted(upgrades)[:5])))
    size = sum(int((meta.get(n) or {}).get("installed_size_kb") or 0) for n in installs)
    if size > LARGE_KB:
        notes.append("Large: about %d MB once installed." % (size // 1024))
    return None, notes


_LISTING = re.compile(r"^(?P<mode>[-dlhbcp][rwxsStT-]{9})\s+\S+\s+\d+\s+\S+\s+\S+\s+(?P<path>.+?)(?: -> .*)?$")
_FORBIDDEN_PATHS = ("boot/", "lib/modules/", "usr/lib/modules/", "etc/sudoers", "etc/pam.d/", "etc/pam.conf", "etc/security/",
                    "etc/ssh/", "etc/apt/", "etc/polkit-1/rules.d/", "usr/share/polkit-1/rules.d/", "etc/ld.so",
                    "usr/lib/apt/", "lib/security/", "usr/lib/x86_64-linux-gnu/security/", "etc/shadow", "etc/passwd",
                    "etc/gshadow", "etc/group", "etc/crypttab", "etc/fstab")
_UNIT = re.compile(r"(?:usr/)?lib/systemd/system/([^/]+\.(?:service|socket|timer))$")


def inspect_listing(text):
    """(refusal_code or None, [plain notes]) from ``dpkg-deb -c`` output for ONE package."""
    notes, units, setuid = [], set(), set()
    for line in text.splitlines():
        m = _LISTING.match(line.strip())
        if not m:
            continue
        path = m.group("path").lstrip("./")
        if m.group("mode")[0] != "d":
            for forbidden in _FORBIDDEN_PATHS:
                if path.startswith(forbidden) or ("/" + path).startswith("/" + forbidden):
                    return "package_touches_login_or_boot_files", []
        mode = m.group("mode")
        if mode[0] == "-" and (mode[3] in "sS" or mode[6] in "sS"):
            setuid.add(path.rsplit("/", 1)[-1])
        unit = _UNIT.search(path)
        if unit:
            units.add(unit.group(1))
    if units:
        notes.append("Ships background service files: %s." % ", ".join(sorted(units)[:5]))
    if setuid:
        notes.append("Installs program(s) that run with extra privileges (setuid/setgid): %s." % ", ".join(sorted(setuid)[:5]))
    return None, notes
