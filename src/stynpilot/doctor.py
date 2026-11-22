"""``stynpilot doctor``: read-only health and permission checks. It never writes, starts, stops or repairs
anything and never prints a secret. Each check is (name, level, detail) with level ok / warn / fail."""
from __future__ import annotations

import importlib
import json
import os
import stat
import sys
from pathlib import Path

OK, WARN, FAIL = "ok", "warn", "fail"
REQUIRED_MODULES = ("mcp", "jwt", "cryptography", "starlette", "uvicorn", "httpx", "pydantic")
UNIT_FILES = {"installer": "/usr/lib/systemd/system/stynpilot-installer.service",
              "owner": "/usr/lib/systemd/user/stynpilot-owner.service"}
LEGACY_HINTS = ("stynpilot-remote-broker.service", "stynpilot-commander-user.service")


def _mode(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def check_python(version=None):
    version = version or sys.version_info
    return ("python", OK if tuple(version[:2]) >= (3, 11) else FAIL, "%d.%d" % tuple(version[:2]))


def check_modules(importer=importlib.import_module):
    missing = []
    for name in REQUIRED_MODULES:
        try:
            importer(name)
        except Exception:
            missing.append(name)
    return ("dependencies", FAIL if missing else OK, "missing: " + ", ".join(missing) if missing else "all present")


def check_private(path, label, *, directory=False):
    info = _mode(path)
    if info is None:
        return (label, FAIL, "not found")
    if stat.S_ISLNK(info.st_mode):
        return (label, FAIL, "is a symlink")
    if info.st_mode & 0o077:
        return (label, FAIL, "readable by others (mode %o)" % (info.st_mode & 0o777))
    if info.st_uid != os.geteuid() and os.geteuid() != 0:
        return (label, FAIL, "owned by another user")
    return (label, OK, "private")


def check_owner_state(config):
    from .service import PROVISIONED
    out = [check_private(config.state_dir, "owner state folder", directory=True)]
    missing = [n for n in PROVISIONED if not (config.state_dir / n).exists()]
    out.append(("owner state files", FAIL if missing else OK,
                ("missing: %s (restore a backup or run `stynpilot service provision`; never recreate by hand)"
                 % ", ".join(missing)) if missing else "all present"))
    for n in PROVISIONED:
        if (config.state_dir / n).exists():
            out.append(check_private(config.state_dir / n, "state file " + n))
    return out


def check_ports(config, listeners):
    """``listeners(host, port)`` -> list of bound addresses (service_status.listeners). Loopback only."""
    out = []
    for label, port in (("approval page", config.approval_port), ("AI endpoint", config.mcp_port)):
        found = listeners("127.0.0.1", port)
        if found is None:
            out.append((label + " listener", WARN, "could not read listeners"))
        elif not found:
            out.append((label + " listener", WARN, "not running on 127.0.0.1:%d" % port))
        else:
            out.append((label + " listener", OK, "127.0.0.1:%d" % port))
    if config.approval_port == config.mcp_port:
        out.append(("ports", FAIL, "approval page and AI endpoint share a port"))
    return out


def check_socket(path, owner_uid=None):
    info = _mode(path)
    if info is None:
        return ("installer socket", WARN, "not present (installer not running?)")
    if not stat.S_ISSOCK(info.st_mode):
        return ("installer socket", FAIL, "not a socket")
    if info.st_mode & 0o077:
        return ("installer socket", FAIL, "mode %o: others can reach it" % (info.st_mode & 0o777))
    if owner_uid is not None and info.st_uid != owner_uid:
        return ("installer socket", FAIL, "not owned by the enrolled owner")
    return ("installer socket", OK, "0600, owner only")


def check_installer_answers(client):
    try:
        client.status("0" * 64)
        return ("installer answers", OK, "status call works")
    except Exception as error:
        return ("installer answers", WARN, "no answer: %s" % getattr(error, "code", type(error).__name__))


def check_pairing(path):
    try:
        from .devices import PairingDeviceGrants
        grants = PairingDeviceGrants(path)
        try:
            n = len(grants.paired_devices())
        finally:
            grants.close()
    except Exception as error:
        return ("pairing database", FAIL, "cannot be read read-only: %s" % type(error).__name__)
    return ("pairing database", OK if n == 1 else FAIL, "%d paired device(s); exactly one is required" % n)


def check_units(unit_paths=UNIT_FILES, packaged=None):
    out = []
    for name, path in unit_paths.items():
        info = _mode(path)
        if info is None:
            out.append(("unit " + name, FAIL, "not installed"))
        elif packaged and name in packaged and Path(path).read_bytes() != Path(packaged[name]).read_bytes():
            out.append(("unit " + name, WARN, "differs from the packaged file"))
        else:
            out.append(("unit " + name, OK, "installed"))
    return out


def check_legacy(search=("/etc/systemd/system", "/usr/lib/systemd/system", "/usr/lib/systemd/user")):
    found = [h for d in search for h in LEGACY_HINTS if (Path(d) / h).exists()]
    return ("existing Preview26 service", OK, ("found and left untouched: " + ", ".join(found)) if found
            else "not found (nothing to preserve)")


def run_checks(*, owner_config=None, listeners=None, client=None, pairing=None, units=True):
    checks = [check_python(), check_modules()]
    if owner_config is not None:
        checks += check_owner_state(owner_config)
        if listeners is not None:
            checks += check_ports(owner_config, listeners)
        checks.append(check_socket(owner_config.broker_socket, os.geteuid()))
        checks.append(check_pairing(pairing or owner_config.pairing_db))
    if client is not None:
        checks.append(check_installer_answers(client))
    if units:
        checks += check_units()
    checks.append(check_legacy())
    return checks


def render(checks):
    marks = {OK: "OK  ", WARN: "WARN", FAIL: "FAIL"}
    lines = ["%s %-28s %s" % (marks[level], name, detail) for name, level, detail in checks]
    bad = sum(1 for _, level, _ in checks if level == FAIL)
    warn = sum(1 for _, level, _ in checks if level == WARN)
    lines.append("")
    lines.append("Result: %s (%d problem(s), %d warning(s)). Nothing was changed." %
                 ("NEEDS ATTENTION" if bad else "healthy" if not warn else "healthy with warnings", bad, warn))
    return "\n".join(lines)


def exit_code(checks):
    return 1 if any(level == FAIL for _, level, _ in checks) else 0


def render_html(checks):
    import html
    colour = {OK: "#1a7f37", WARN: "#9a6700", FAIL: "#cf222e"}
    rows = "".join("<tr><td style='color:%s;font-weight:700'>%s</td><td>%s</td><td>%s</td></tr>"
                   % (colour[l], l.upper(), html.escape(n), html.escape(d)) for n, l, d in checks)
    bad = sum(1 for _, l, _ in checks if l == FAIL)
    head = "Needs attention" if bad else "Healthy"
    return ("<!doctype html><meta charset=utf-8><title>StyNpilot Doctor</title><body style='font-family:system-ui;"
            "max-width:48rem;margin:2rem auto'><h1>StyNpilot Doctor: %s</h1><table cellpadding=6>%s</table>"
            "<p>This report only reads. Nothing was changed.</p>" % (head, rows))


def show_html(checks):                                       # pragma: no cover - opens a browser
    import tempfile
    import webbrowser
    fd, path = tempfile.mkstemp(prefix="stynpilot-doctor-", suffix=".html")
    with os.fdopen(fd, "w") as handle:
        handle.write(render_html(checks))
    webbrowser.open("file://" + path)
