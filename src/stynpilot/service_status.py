"""Read-only status of StyNpilot catalog software on this Ryzen (GREEN: changes nothing).

Answers "is Forgejo installed, enabled, listening and answering?" without a person at the
keyboard. It only reads public system files (/etc/systemd, /etc/passwd, /proc/net) and
makes one or two loopback HTTP GET requests to the recipe's own fixed address.

It never runs a command, reads a secret or config file content, follows a caller-supplied
path or URL, or contacts any non-loopback host. The caller names a catalog id only; every
path, port and URL comes from the fixed table below, which a test keeps identical to the
install catalog. Ported from the GitLab prototype (src/stynpilot_service_status.py, MR !29).
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import stat
from pathlib import Path

# Exact facts from the reviewed Forgejo recipe (GitLab tools/stynpilot_software_catalog.py).
# When the catalog is ported, a test must keep these two identical.
SERVICES = {
    "forgejo": {
        "title": "Forgejo (self-hosted Git forge)",
        "catalog_version": "15.0.3",
        "binary": "/usr/local/bin/forgejo",
        "unit_name": "forgejo.service",
        "unit_path": "/etc/systemd/system/forgejo.service",
        "wants_link": "/etc/systemd/system/multi-user.target.wants/forgejo.service",
        "user": "forgejo",
        "host": "127.0.0.1",
        "port": 3000,
    },
}

_ID = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
_VERSION = re.compile(r"[0-9A-Za-z.+~-]{1,64}\Z")
_LISTEN = "0A"  # TCP_LISTEN in /proc/net/tcp
MAX_BODY = 65536
HTTP_TIMEOUT = 3.0


class UnknownSoftware(KeyError):
    pass


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def check_binary(path):
    info = _lstat(path)
    if info is None:
        return {"present": False}
    return {"present": True,
            "regular_file": stat.S_ISREG(info.st_mode),
            "root_owned": info.st_uid == 0,
            "not_world_writable": not info.st_mode & 0o022,
            "size_bytes": info.st_size if stat.S_ISREG(info.st_mode) else None}


def check_unit(unit_path, expected_content=None):
    """Unit file presence; when the catalog text is given, whether it is unchanged."""
    info = _lstat(unit_path)
    if info is None:
        return {"present": False}
    result = {"present": True, "regular_file": stat.S_ISREG(info.st_mode), "root_owned": info.st_uid == 0}
    if expected_content is not None and stat.S_ISREG(info.st_mode) and info.st_size <= MAX_BODY:
        try:
            with open(unit_path, "rb") as handle:
                data = handle.read(MAX_BODY + 1)
            result["matches_catalog"] = (hashlib.sha256(data).hexdigest()
                                         == hashlib.sha256(expected_content.encode("utf-8")).hexdigest())
        except OSError:
            result["matches_catalog"] = None
    return result


def check_enabled(wants_link, unit_path):
    """systemctl enable creates this symlink; reading it needs no D-Bus or subprocess."""
    info = _lstat(wants_link)
    if info is None or not stat.S_ISLNK(info.st_mode):
        return False
    try:
        return os.readlink(wants_link) == unit_path
    except OSError:
        return False


def user_uid(name, passwd="/etc/passwd"):
    try:
        with open(passwd, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 3 and fields[0] == name and fields[2].isdigit():
                    return int(fields[2])
    except OSError:
        pass
    return None


# /proc/net/tcp6 shows each 32-bit word of the address in host (little-endian) order.
_V6_LOOPBACK = "00000000000000000000000001000000"          # ::1
_V6_ANY = "0" * 32                                          # ::
_V6_MAPPED_V4_LOOPBACK = "0000000000000000FFFF00000100007F"  # ::ffff:127.0.0.1
_V4_ANY = "00000000"                                        # 0.0.0.0


def _v4_hex(host):
    return bytes(int(x) for x in host.split("."))[::-1].hex().upper()


def listeners(host, port, proc_net=("/proc/net/tcp", "/proc/net/tcp6")):
    """Listening sockets on the recipe's port: who owns them and whether they reach past loopback.

    Matches only the recipe's own address (127.0.0.1), its IPv6 equivalents (::1 and the
    IPv4-mapped form) and the any-address forms (0.0.0.0, ::). The any-address forms are
    flagged, because they would also accept connections from other machines. Other
    addresses on the same port are ignored.
    """
    port_hex = "%04X" % port
    loop4 = _v4_hex(host)
    seen, readable = [], False
    for table in proc_net:
        v6 = str(table).endswith("6")
        try:
            with open(table, encoding="ascii", errors="replace") as handle:
                lines = handle.readlines()[1:]
            readable = True
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 8 or fields[3] != _LISTEN or not fields[7].isdigit():
                continue
            address, _, lport = fields[1].upper().partition(":")
            if lport != port_hex:
                continue
            if v6:
                if address in (_V6_LOOPBACK, _V6_MAPPED_V4_LOOPBACK):
                    beyond = False
                elif address == _V6_ANY:
                    beyond = True
                else:
                    continue
            else:
                if address == loop4:
                    beyond = False
                elif address == _V4_ANY:
                    beyond = True
                else:
                    continue
            seen.append({"uid": int(fields[7]), "family": "ipv6" if v6 else "ipv4", "beyond_loopback": beyond})
    return seen if readable else None


def _get(host, port, path, connection=http.client.HTTPConnection):
    """One bounded loopback GET; returns (status, headers dict, body bytes) or None."""
    try:
        conn = connection(host, port, timeout=HTTP_TIMEOUT)
        try:
            conn.request("GET", path, headers={"Accept": "application/json, text/html",
                                               "User-Agent": "StyNpilot-status"})
            response = conn.getresponse()
            body = response.read(MAX_BODY + 1)[:MAX_BODY]
            headers = {k.lower(): v for k, v in response.getheaders()}
            return response.status, headers, body
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, ValueError):
        return None


def _json(body):
    try:
        value = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def probe_forgejo(host, port, get=_get):
    """Ask the program on the port to prove it is Forgejo. Anything unproven stays unverified.

    Proof is one of: Forgejo's health document (200, JSON, status pass/warn/fail with a
    checks map), its version document (200, JSON, a version string), or Forgejo's own
    first-run installer page. Any other answer (404, redirects, someone else's page,
    malformed JSON) means "something answered", never "Forgejo is running".
    """
    out = {"answered": False, "identified": False, "healthy": None, "version": None, "setup_required": None}
    health = get(host, port, "/api/healthz")
    if health is not None:
        out["answered"] = True
        doc = _json(health[2]) if health[0] == 200 else None
        if doc and doc.get("status") in ("pass", "warn", "fail") and isinstance(doc.get("checks"), dict):
            out["identified"], out["healthy"] = True, doc["status"] != "fail"
    version = get(host, port, "/api/v1/version")
    if version is not None:
        out["answered"] = True
        doc = _json(version[2]) if version[0] == 200 else None
        value = doc.get("version") if doc else None
        if type(value) is str and _VERSION.fullmatch(value):
            out["identified"], out["version"] = True, value
    if out["version"] is not None:
        out["setup_required"] = False
    elif out["answered"]:
        # Before first-run setup (INSTALL_LOCK=false) Forgejo serves only its installer page.
        front = get(host, port, "/")
        if front is not None and front[0] == 200:
            text = front[2].decode("utf-8", "replace").lower()
            if ("forgejo" in text or "gitea" in text) and "db_type" in text and "install" in text:
                out["identified"], out["setup_required"] = True, True
    return out


STATES = {
    "not_installed": "Not installed. An assistant can request the install for your phone approval.",
    "partially_installed": "Some files exist but the install is incomplete. Ask an assistant to review before reinstalling.",
    "port_used_by_another_program": "Another account's program is using this port. Nothing was changed.",
    "installed_not_listening": "Installed, but nothing is listening on its port. The service may be stopped or failing.",
    "listening_not_answering": "The port is open but nothing answered.",
    "unverified": ("Something answered on the port, but it did not prove it is Forgejo "
                   "(no valid health, version or setup page). Treat as not running."),
    "exposed_beyond_loopback": ("Listening on an address other computers can reach. The recipe allows "
                                "this computer only. Nothing was changed."),
    "setup_required": "Forgejo is answering, but its one-time web setup is not finished.",
    "unhealthy": "Forgejo is answering but reports itself unhealthy.",
    "running": "Forgejo answered with its own health or version information.",
}


def service_status(software, *, root="/", unit_content=None, proc_net=None, get=_get):
    """Return a bounded, secret-free status report for one catalog id.

    Wording is deliberately narrow: a socket owned by the service's user account shows who
    owns the port, not which systemd unit runs it, and only Forgejo's own answers count as
    proof that Forgejo is running.
    """
    if type(software) is not str or not _ID.fullmatch(software) or software not in SERVICES:
        raise UnknownSoftware("unknown_software")
    spec = SERVICES[software]

    def at(path):
        return str(Path(root) / path.lstrip("/"))

    binary = check_binary(at(spec["binary"]))
    unit = check_unit(at(spec["unit_path"]), unit_content)
    enabled = check_enabled(at(spec["wants_link"]), spec["unit_path"])
    uid = user_uid(spec["user"], at("/etc/passwd"))
    found = listeners(spec["host"], spec["port"],
                      proc_net if proc_net is not None else (at("/proc/net/tcp"), at("/proc/net/tcp6")))
    probe = probe_forgejo(spec["host"], spec["port"], get=get)

    listening = bool(found)
    owned = None if (found is None or uid is None or not found) else all(row["uid"] == uid for row in found)
    beyond = bool(found) and any(row["beyond_loopback"] for row in found)
    installed = binary.get("present", False) and unit.get("present", False) and uid is not None

    if not installed:
        state = "not_installed" if not (binary["present"] or unit["present"]) else "partially_installed"
    elif listening and owned is False:
        state = "port_used_by_another_program"
    elif not listening:
        state = "installed_not_listening"
    elif beyond:
        state = "exposed_beyond_loopback"
    elif not probe["answered"]:
        state = "listening_not_answering"
    elif not probe["identified"]:
        state = "unverified"
    elif probe["setup_required"]:
        state = "setup_required"
    elif probe["healthy"] is False:
        state = "unhealthy"
    else:
        state = "running"

    summary = STATES[state]
    if state == "setup_required":
        summary += " Open http://%s:%d/ on that computer itself to finish it." % (spec["host"], spec["port"])

    return {
        "software": software,
        "title": spec["title"],
        "state": state,
        "summary": summary,
        "installed": installed,
        "verified_running": state in ("running", "setup_required", "unhealthy"),
        "service_enabled_at_boot": enabled,
        "listening": listening if found is not None else None,
        "listener_owned_by_service_account": owned,
        "listening_beyond_loopback": beyond if found is not None else None,
        "identified_as_forgejo": probe["identified"],
        "address": "http://%s:%d/" % (spec["host"], spec["port"]),
        "version": probe["version"],
        "catalog_version": spec["catalog_version"],
        "setup_required": probe["setup_required"],
        "healthy": probe["healthy"],
        "checks": {
            "binary": binary,
            "unit_file": unit,
            "service_user_exists": uid is not None,
            "listener_count": len(found) if found is not None else None,
        },
    }


def read_service_status(software, unit_content=None):
    """Production entry point: the real filesystem and loopback HTTP."""
    return service_status(software, unit_content=unit_content)
