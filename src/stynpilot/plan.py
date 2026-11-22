"""Fail-closed validation of an immutable software install plan. No execution, no approval.

A plan hash identifies one exact plan. It is NOT an owner approval. Trusted identity,
package resolution, backups, Docker isolation and privileged execution belong to
separate, independently reviewed components.

Origin: ChatGPT's GitLab prototype (commit 0e81d7b1). Changes after Claude's review:
* ValidatedPlan carries the validated content; callers must execute from it, never from
  the raw input, which they could still mutate after validation.
* a package may appear only once across the whole plan, not just once per step;
* owner, device and expiry have one strict shape, so one plan has one hash;
* plans live at most 24 hours and must be in the future.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping

SCHEMA = 1
MAX_STEPS = 20
MAX_PACKAGES = 32
MAX_HORIZON_SECONDS = 86400


class PlanError(ValueError):
    """The proposed plan is outside the narrow supported shape."""


@dataclass(frozen=True)
class ValidatedPlan:
    canonical_json: str
    plan_sha256: str
    step_count: int

    def content(self) -> dict:
        """A fresh copy of exactly what was validated and hashed."""
        return json.loads(self.canonical_json)


_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:|@-]{0,127}\Z")
_SLUG = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_PKG = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9:~.+-]{0,127}\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]{1,200}@sha256:[0-9a-f]{64}\Z")
_EXPIRY = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_LOCAL_NETS = tuple(ipaddress.ip_network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # home LAN
    "100.64.0.0/10",                                   # Tailscale
    "127.0.0.0/8", "::1/128", "fc00::/7",              # loopback, IPv6 private
))
_PLAN_FIELDS = {"schema", "owner", "device", "steps", "backup", "rollback", "expires_at", "software"}
# "software" (the catalog id) is optional for this validator, but the root executor
# requires it: it is hashed with the plan, so the recorded software name is the approved one.
_REQUIRED_PLAN_FIELDS = _PLAN_FIELDS - {"software"}
_STEP_FIELDS = {"kind", "packages", "app", "image", "bind_ip", "host_port", "container_port", "data_subdir"}
_CONTAINER_FIELDS = {"kind", "app", "image", "bind_ip", "host_port", "container_port", "data_subdir"}


def _only(obj: Any, fields: set[str], required: set[str], label: str) -> dict:
    if type(obj) is not dict or set(obj) - fields or required - set(obj):
        raise PlanError(f"{label}: missing or unrecognized fields")
    return obj


def _match(value: Any, regex: re.Pattern, label: str) -> str:
    if type(value) is not str or regex.fullmatch(value) is None:
        raise PlanError(f"{label}: invalid value")
    return value


def _port(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise PlanError(f"{label}: port must be an integer in 1..65535")
    return value


def _bind_address(value: Any) -> None:
    try:
        addr = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise PlanError("bind_ip must be a numeric LAN, Tailscale or loopback address") from None
    if addr.is_unspecified or addr.is_multicast or getattr(addr, "ipv4_mapped", None) is not None:
        raise PlanError("bind_ip cannot be a wildcard, multicast or mapped address")
    if not any(addr in net for net in _LOCAL_NETS):
        raise PlanError("bind_ip must be a LAN, Tailscale or loopback address")


def _check_step(step: Any, index: int, packages_seen: set[str], apps: set[str], binds: set) -> None:
    _only(step, _STEP_FIELDS, {"kind"}, f"step[{index}]")
    kind = step["kind"]
    if kind == "apt":
        _only(step, {"kind", "packages"}, {"kind", "packages"}, f"apt[{index}]")
        packages = step["packages"]
        if type(packages) is not list or not 1 <= len(packages) <= MAX_PACKAGES:
            raise PlanError(f"apt[{index}]: 1..{MAX_PACKAGES} packages required")
        for package in packages:
            _only(package, {"name", "version"}, {"name", "version"}, "apt package")
            name = _match(package["name"], _PKG, "apt name")
            _match(package["version"], _VERSION, "apt version")
            if name in packages_seen:
                raise PlanError("a package may appear only once in a plan")
            packages_seen.add(name)
    elif kind == "container":
        _only(step, _CONTAINER_FIELDS, _CONTAINER_FIELDS, f"container[{index}]")
        app = _match(step["app"], _SLUG, "container app")
        _match(step["image"], _IMAGE, "container image (must be pinned by sha256 digest)")
        _bind_address(step["bind_ip"])
        _port(step["host_port"], "host_port")
        _port(step["container_port"], "container_port")
        if step["data_subdir"] != app:
            raise PlanError("data_subdir must equal the app name; host paths are not accepted")
        if app in apps:
            raise PlanError("duplicate app name")
        bind = (str(ipaddress.ip_address(step["bind_ip"])), step["host_port"])
        if bind in binds:
            raise PlanError("duplicate address and port")
        apps.add(app)
        binds.add(bind)
    else:
        raise PlanError("unsupported step kind; raw shell and arbitrary installers are refused")


def validate_plan(raw: Mapping[str, Any], *, expected_owner: str, expected_device: str,
                  now: datetime | None = None) -> ValidatedPlan:
    """Validate a deliberately narrow plan without performing any action.

    expected_owner and expected_device MUST come from a trusted verifier (the owner's
    verified token and the enrolled device record), never from AI-supplied fields.
    """
    plan = _only(raw, _PLAN_FIELDS, _REQUIRED_PLAN_FIELDS, "plan")
    if "software" in plan:
        _match(plan["software"], _SLUG, "software (catalog id)")
    if type(plan["schema"]) is not int or plan["schema"] != SCHEMA:
        raise PlanError("unsupported plan schema")
    for trusted in (expected_owner, expected_device):
        _match(trusted, _IDENT, "trusted owner/device")
    if plan["owner"] != expected_owner or plan["device"] != expected_device:
        raise PlanError("plan owner or device does not match the trusted context")
    if plan["backup"] != "required-before-mutation" or plan["rollback"] != "restore-verified-snapshot":
        raise PlanError("verified backup and rollback declarations are required")
    expiry_text = _match(plan["expires_at"], _EXPIRY, "expires_at (YYYY-MM-DDTHH:MM:SSZ)")
    try:
        expiry = datetime.strptime(expiry_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise PlanError("invalid expiration") from None
    now = datetime.now(timezone.utc) if now is None else now
    if now.tzinfo is None:
        raise PlanError("trusted clock must be timezone aware")
    remaining = (expiry - now).total_seconds()
    if not 0 < remaining <= MAX_HORIZON_SECONDS:
        raise PlanError("plan is expired or exceeds the 24-hour horizon")
    steps = plan["steps"]
    if type(steps) is not list or not 1 <= len(steps) <= MAX_STEPS:
        raise PlanError(f"steps must contain 1..{MAX_STEPS} items")
    packages_seen: set[str] = set()
    apps: set[str] = set()
    binds: set = set()
    for index, step in enumerate(steps):
        _check_step(step, index, packages_seen, apps, binds)
    canonical = json.dumps(plan, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return ValidatedPlan(canonical, hashlib.sha256(canonical.encode("ascii")).hexdigest(), len(steps))
