"""Authorization for the read-only (GREEN) MCP tools: health and software status.

Standard library only. Every read passes two checks, before AND after reading:
1. the bearer token verifies and carries ``health.read``;
2. the verified account owns the requested, unrevoked, unexpired device.

Ported from the GitLab prototype (mcp_read_router.py and the _LocalOwnership part of
src/commander_health_connection.py, MR !29). Diagnostics are reason labels and
booleans only; no IDs, claims or tokens are ever logged.
"""
from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Mapping

from ..health import METRIC_BOUNDS
from ..identity import TokenDenied

DEVICE_ID = re.compile(r"dtdev_[A-Za-z0-9_-]{8,64}\Z")
READ_SCOPE = "health.read"
_LOG = logging.getLogger("stynpilot.auth")


class AccessDenied(Exception):
    pass


class LocalOwnership:
    """The one owner/device pair this computer is paired with, checked against its grant.

    ``grants.get(owner_id=..., device_id=...)`` returns an object with owner_id, device_id,
    revoked (bool), scopes (set) and expires_at (epoch seconds), or None.
    """

    def __init__(self, *, grants, owner_id, device_id, clock=time.time):
        if type(owner_id) is not str or not owner_id or type(device_id) is not str or not device_id:
            raise ValueError("Exact owner and paired device required")
        self.grants, self.owner_id, self.device_id, self.clock = grants, owner_id, device_id, clock

    def devices_for(self, account):
        try:
            grant = self.grants.get(owner_id=self.owner_id, device_id=self.device_id)
        except Exception as error:
            _LOG.warning("denied: grant_store_error type=%s", type(error).__name__)
            return []
        expires = getattr(grant, "expires_at", None)
        finite = type(expires) in (int, float) and math.isfinite(expires)
        checks = (
            ("owner_mismatch", account == self.owner_id),
            ("grant_missing", grant is not None),
            ("grant_owner_mismatch", getattr(grant, "owner_id", None) == self.owner_id),
            ("grant_device_mismatch", getattr(grant, "device_id", None) == self.device_id),
            ("grant_revoked", getattr(grant, "revoked", None) is False),
            ("grant_scope_missing", isinstance(getattr(grant, "scopes", None), (set, frozenset))
             and READ_SCOPE in grant.scopes),
            ("grant_expired", finite and self.clock() < expires),
        )
        for reason, ok in checks:
            if not ok:
                _LOG.warning("denied: %s", reason)
                return []
        return [{"device_id": self.device_id, "revoked": False, "expires": expires}]


class ReadRouter:
    def __init__(self, *, tokens, ownership, read_health, read_service_status=None, read_inventory=None, clock=time.time):
        if tokens is None or ownership is None or not callable(read_health):
            raise ValueError("Token verifier, ownership and health reader required")
        if read_service_status is not None and not callable(read_service_status):
            raise ValueError("Service status reader must be callable")
        self.tokens, self.ownership, self.clock = tokens, ownership, clock
        if read_inventory is not None and not callable(read_inventory):
            raise ValueError("Inventory reader must be callable")
        self.read_health, self.read_service_status, self.read_inventory = read_health, read_service_status, read_inventory

    def _authorize(self, header, device_id):
        if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
            _LOG.warning("denied: invalid_device_id")
            raise AccessDenied("Access denied")
        try:
            identity = self.tokens.authorize(header, required_scope=READ_SCOPE)
        except TokenDenied as error:
            _LOG.warning("denied: token")
            raise AccessDenied("Access denied") from error
        self._require_device(identity.account, device_id)
        return identity

    def _recheck(self, header, identity, device_id):
        """A read can outlast a revocation; check again before anything leaves."""
        again = self._authorize(header, device_id)
        if again.account != identity.account:
            raise AccessDenied("Access denied")

    def _require_device(self, account, device_id):
        for row in self.ownership.devices_for(account):
            if isinstance(row, dict) and row.get("device_id") == device_id:
                expires = row.get("expires")
                if (row.get("revoked") in (False, 0) and type(expires) in (int, float)
                        and math.isfinite(expires) and self.clock() < expires):
                    return
                break
        _LOG.warning("denied: device_not_owned_or_expired")
        raise AccessDenied("Access denied")

    def health(self, *, authorization_header, device_id):
        identity = self._authorize(authorization_header, device_id)
        data = self.read_health()
        self._recheck(authorization_header, identity, device_id)
        if not isinstance(data, Mapping):
            raise AccessDenied("Telemetry unavailable")
        metrics = {key: float(data[key]) for key, (low, high) in METRIC_BOUNDS.items()
                   if type(data.get(key)) in (int, float) and low <= data[key] <= high}
        if not metrics:
            raise AccessDenied("Telemetry unavailable")
        return metrics

    def inventory(self, *, authorization_header, device_id):
        if self.read_inventory is None:
            raise AccessDenied("Inventory unavailable")
        identity = self._authorize(authorization_header, device_id)
        data = self.read_inventory()
        self._recheck(authorization_header, identity, device_id)
        if not isinstance(data, Mapping):
            raise AccessDenied("Inventory unavailable")
        return dict(data)

    def service_status(self, *, authorization_header, device_id, software):
        if self.read_service_status is None:
            raise AccessDenied("Service status unavailable")
        identity = self._authorize(authorization_header, device_id)
        data = self.read_service_status(software)
        self._recheck(authorization_header, identity, device_id)
        if not isinstance(data, Mapping):
            raise AccessDenied("Status unavailable")
        return dict(data)
