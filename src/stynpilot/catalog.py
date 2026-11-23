"""Software the assistants may ask for by name, turned into one exact validated plan each.

An assistant supplies only a catalog id. It can never supply a package name, image,
URL, path, port, user or command. Every entry compiles to the *general* plan format
(``plan.validate_plan``: Ubuntu archive packages at exact versions, or containers
pinned by digest), so there is no per-app installer code (owner decision 2026-11-21).

Forgejo is the one ``legacy`` entry: the previous (GitLab) build installed it with its
own recipe. Its facts are kept for status checks and rollback, and a new install
request is refused because it is already installed. Its fields are tied to the
GitLab recipe by a test.

Exact apt versions are resolved on the owner's computer at request time by
``resolve_apt(names) -> [{"name", "version"}, ...]`` (``broker.apt.resolve``, a read-only
simulation). It returns the requested packages AND every dependency apt would add, so
the owner approves the complete set. The executor stops if the machine would install
anything different.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

from . import impact
from .plan import MAX_REQUESTED, validate_plan

PLAN_LIFETIME = timedelta(hours=1)
BACKUP, ROLLBACK = "required-before-mutation", "restore-verified-snapshot"

_ENTRIES = {
    "forgejo": {
        "kind": "legacy",
        "title": "Forgejo (self-hosted Git forge)",
        "version": "15.0.3",
        "note": "Installed by the previous StyNpilot build; managed by its recipe until the new executor takes over.",
        "legacy_recipe": {
            "binary": "/usr/local/bin/forgejo",
            "unit_name": "forgejo.service",
            "unit_path": "/etc/systemd/system/forgejo.service",
            "user": "forgejo",
            "listen": ("127.0.0.1", 3000),
        },
    },
    "htop": {
        "kind": "apt",
        "title": "htop (interactive process viewer)",
        "packages": ("htop",),
        "note": "Small, read-only system monitor from the Ubuntu archive. Used to prove the general install path.",
    },
}
CATALOG = MappingProxyType(_ENTRIES)


class CatalogError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def entry(software):
    if type(software) is not str or software not in CATALOG:
        raise CatalogError("unknown_software")
    return CATALOG[software]


def listing():
    """What assistants can see: ids, titles and notes. Nothing they could inject."""
    return [{"id": key, "title": value["title"], "kind": value["kind"], "note": value["note"]}
            for key, value in sorted(CATALOG.items())]


GENERIC_PREFIX = "apt-"
_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")


def generic_slug(requested):
    """Deterministic software id for an install of arbitrary Ubuntu packages: apt-<first name>-<8 hex of all names>.

    Derived from the requested names only, so the root installer recomputes it and a mismatch is refused.
    """
    names = sorted(requested)
    base = re.sub(r"[^a-z0-9]+", "-", names[0])[:28].strip("-") or "pkg"
    return "%s%s-%s" % (GENERIC_PREFIX, base, hashlib.sha256("\n".join(names).encode()).hexdigest()[:8])


def is_generic(software):
    return type(software) is str and software.startswith(GENERIC_PREFIX)


def check_names(packages):
    """1..MAX_REQUESTED distinct, strictly shaped package names (sorted). Raises CatalogError("invalid_package_name")."""
    if (type(packages) is not list or not 1 <= len(packages) <= MAX_REQUESTED
            or not all(type(n) is str and _NAME.fullmatch(n) for n in packages)):
        raise CatalogError("invalid_package_name")
    if len(set(packages)) != len(packages):
        raise CatalogError("invalid_package_name")
    return sorted(packages)


def describe(software, requested=None):
    """Plain title for a catalog id or a generic install (used by status and rollback)."""
    if is_generic(software):
        return "Ubuntu package%s %s" % ("s" if requested and len(requested) > 1 else "", ", ".join(requested or [software]))
    return entry(software)["title"]


def _expiry(now):
    return (now + PLAN_LIFETIME).strftime("%Y-%m-%dT%H:%M:%SZ")


def install_plan(software, *, owner, device, resolve_apt, now=None):
    """Return (ValidatedPlan, plain-English summary lines). Raises CatalogError or PlanError."""
    item = entry(software)
    if item["kind"] == "legacy":
        raise CatalogError("already_installed_by_previous_build")
    now = datetime.now(timezone.utc) if now is None else now
    if item["kind"] != "apt":
        raise CatalogError("unsupported_entry")
    if not callable(resolve_apt):
        raise CatalogError("version_resolution_unavailable")
    try:
        packages = resolve_apt(list(item["packages"]))
    except Exception:
        raise CatalogError("package_not_available") from None
    if (type(packages) is not list or not packages
            or not all(type(p) is dict and set(p) == {"name", "version"} for p in packages)
            or not set(item["packages"]) <= {p["name"] for p in packages}):
        raise CatalogError("package_not_available")
    raw = {"schema": 1, "owner": owner, "device": device, "software": software,
           "steps": [{"kind": "apt", "packages": packages}],
           "backup": BACKUP, "rollback": ROLLBACK, "expires_at": _expiry(now)}
    validated = validate_plan(raw, expected_owner=owner, expected_device=device, now=now)
    summary = ["Install %s from the Ubuntu archive." % item["title"]]
    summary += ["Package %s, exact version %s%s." % (p["name"], p["version"],
                "" if p["name"] in item["packages"] else " (needed by it)") for p in packages]
    summary += ["A backup is taken before anything changes; rollback restores it.",
                "Expires %s UTC if not approved." % raw["expires_at"].replace("T", " ").rstrip("Z")]
    return validated, summary


def generic_install_plan(packages, *, owner, device, analyze, installed, now=None):
    """Plan for 1..3 AI-named Ubuntu packages. Returns (ValidatedPlan, summary lines, info).

    ``analyze(names) -> {installs, upgrades, removals, origins, meta}`` simulates the install (no change).
    ``installed(names) -> {name: version or None}``.
    Raises CatalogError with a stable code: invalid_package_name, package_not_available, already_installed,
    blocked_package:<code>, version_resolution_unavailable.
    """
    names = check_names(packages)
    now = datetime.now(timezone.utc) if now is None else now
    if not callable(analyze) or not callable(installed):
        raise CatalogError("version_resolution_unavailable")
    for name in names:
        code = impact.refusal_for(name)
        if code:
            raise CatalogError("blocked_package:" + code)
    try:
        have = installed(names)
        analysis = analyze(names)
    except Exception:
        raise CatalogError("package_not_available") from None
    if not analysis.get("installs"):
        if all(have.get(n) for n in names):
            raise CatalogError("already_installed")
        raise CatalogError("package_not_available")
    if not all(all(o.startswith("Ubuntu:") for o in analysis["origins"].get(n, [])) and analysis["origins"].get(n)
               for n in analysis["installs"]):
        raise CatalogError("package_not_available")
    code, notes = impact.check_transaction(names, analysis)
    if code:
        raise CatalogError("blocked_package:" + code)
    requested = [n for n in names if n in analysis["installs"]]
    already = [n for n in names if n not in analysis["installs"]]
    if already and not all(have.get(n) for n in already):
        raise CatalogError("package_not_available")
    packages_out = [{"name": n, "version": v} for n, v in sorted(analysis["installs"].items())]
    slug = generic_slug(requested)
    raw = {"schema": 1, "owner": owner, "device": device, "software": slug,
           "steps": [{"kind": "apt", "packages": packages_out, "requested": requested}],
           "backup": BACKUP, "rollback": ROLLBACK, "expires_at": _expiry(now)}
    validated = validate_plan(raw, expected_owner=owner, expected_device=device, now=now)
    summary = ["Install %s from the Ubuntu archive (named by the assistant, checked by StyNpilot)." % ", ".join(requested)]
    summary += ["Package %s, exact version %s%s." % (p["name"], p["version"],
                "" if p["name"] in requested else " (needed by it)") for p in packages_out]
    if already:
        summary.append("Already installed, unchanged: %s." % ", ".join(already))
    summary += notes
    summary += ["Install scripts in Ubuntu packages run as root; a signed Ubuntu source proves where a package came from, not that it is harmless.",
                "A backup is taken before anything changes; rollback restores it.",
                "Expires %s UTC if not approved." % raw["expires_at"].replace("T", " ").rstrip("Z")]
    return validated, summary, {"software": slug, "requested": requested, "already_installed": already, "notes": notes}
