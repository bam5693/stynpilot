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

from datetime import datetime, timedelta, timezone
from types import MappingProxyType

from .plan import validate_plan

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
