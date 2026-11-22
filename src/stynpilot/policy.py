"""The single GREEN / YELLOW / BLACK policy.

GREEN  - preauthorized operations on enrolled resources. They still need an
         owner-enrolled, device-bound grant at the point of execution.
YELLOW - exact operations that need fresh, independently authenticated owner approval.
BLACK  - never available to an AI.

Pure data and pure functions: no I/O, no environment, no runtime mutation.
BLACK always wins. Anything not listed fails closed to BLACK.

Migrated from the GitLab prototype (tools/commander_policy.py). Changes: one table
validator instead of two overlapping ones, and the owner's four "always ask me"
categories added as explicit YELLOW operations.
"""
from __future__ import annotations

import re
from types import MappingProxyType

GREEN_TIER, YELLOW_TIER, BLACK_TIER = "GREEN", "YELLOW", "BLACK"

_DEV = frozenset((
    "development.list", "development.read", "development.write", "development.create",
    "development.patch", "development.test", "development.commit",
    "development.publish_branch", "development.dependencies",
))

# resource -> operations that are preauthorized on it
GREEN = MappingProxyType({
    "stynpilot-dev": _DEV,
    "deckplay-dev": _DEV,
    "stynpilot-backup": frozenset(("backup.inspect", "backup.append_encrypted")),
    "deckplay-backup": frozenset(("backup.inspect",)),
    "pi": frozenset(("device.health", "service.inspect")),
    "ryzen": frozenset(("device.health", "service.inspect")),
})

# operation -> exact resources that may be proposed for fresh owner approval
YELLOW = MappingProxyType({
    "controller.update": frozenset(("pi-controller", "ryzen-controller")),
    "service.restart": frozenset(("deckplay-mcp", "forgejo", "stynpilot-agent", "ryzen-docker", "ryzen-ollama")),
    "service.start": frozenset(("ryzen-docker", "ryzen-ollama")),
    "service.stop": frozenset(("ryzen-docker", "ryzen-ollama")),
    "system.install": frozenset(("pi-dependencies", "ryzen-dependencies")),
    "software.install": frozenset(("ryzen-software", "pi-software")),
    "credential.rotate": frozenset(("development-push-key", "backup-recipient")),
    "backup.configure": frozenset(("stynpilot-backup", "deckplay-backup")),
    "backup.restore_isolated": frozenset(("stynpilot-restore-test", "deckplay-restore-test")),
    "workspace.enroll": frozenset(("stynpilot-dev", "deckplay-dev")),
    # The owner's standing rule: these four always come back to him.
    "owner.publish_as": frozenset(("public-post",)),
    "money.spend": frozenset(("purchase", "subscription")),
    "account.signup": frozenset(("external-service",)),
    "private_data.access": frozenset(("owner-private-files",)),
})

BLACK_OPERATIONS = frozenset((
    "shell.exec", "sudo.exec", "credential.read", "signing_key.access", "age_identity.access",
    "grant.modify", "policy.modify", "auth0.modify", "audit.modify", "backup.delete",
    "backup.retention_change", "archive.modify", "production.deploy", "supervisor.modify",
    "stepup.modify", "owner_identity.modify", "disk.erase", "bootloader.modify",
    "firmware.flash", "network_exposure.change", "secret.exfiltrate", "approval.self_grant",
))
BLACK_RESOURCES = frozenset((
    "deckplay-archives", "existing-backups", "production", "recovery-supervisor",
    "commander-policy", "commander-grants", "commander-audit", "auth0-tenant", "signing-key",
    "age-identity", "commander-stepup", "owner-identity", "boot-firmware",
))

_NAME = re.compile(r"[a-z0-9_.-]{1,64}\Z")


def validate_tables(green, yellow, black_operations, black_resources):
    """Refuse malformed or overlapping tables. Runs at import, so a bad edit cannot load."""
    green_ops = set().union(*green.values()) if green else set()
    yellow_resources = set().union(*yellow.values()) if yellow else set()
    names = set(green) | green_ops | set(yellow) | yellow_resources | set(black_operations) | set(black_resources)
    if any(type(n) is not str or _NAME.fullmatch(n) is None for n in names):
        raise ValueError("Policy names must be bounded lowercase identifiers")
    if green_ops & set(yellow):
        raise ValueError("An operation cannot be both GREEN and YELLOW")
    if (green_ops | set(yellow)) & set(black_operations):
        raise ValueError("A BLACK operation is listed as GREEN or YELLOW")
    if (set(green) | yellow_resources) & set(black_resources):
        raise ValueError("A BLACK resource is listed as GREEN or YELLOW")


validate_tables(GREEN, YELLOW, BLACK_OPERATIONS, BLACK_RESOURCES)


def explain(operation, resource):
    """Return {'tier', 'reason'}. Invalid and unlisted pairs fail closed to BLACK."""
    if type(operation) is not str or type(resource) is not str:
        return {"tier": BLACK_TIER, "reason": "invalid_type"}
    if operation in BLACK_OPERATIONS:
        return {"tier": BLACK_TIER, "reason": "black_operation"}
    if resource in BLACK_RESOURCES:
        return {"tier": BLACK_TIER, "reason": "black_resource"}
    if operation in GREEN.get(resource, ()):
        return {"tier": GREEN_TIER, "reason": "green_preauthorized"}
    if resource in YELLOW.get(operation, ()):
        return {"tier": YELLOW_TIER, "reason": "owner_approval_required"}
    return {"tier": BLACK_TIER, "reason": "default_deny"}


def classify(operation, resource):
    return explain(operation, resource)["tier"]


def tier_table():
    """Read-only view of the whole policy, for the owner's screens."""
    return {
        GREEN_TIER: [(r, sorted(GREEN[r])) for r in sorted(GREEN)],
        YELLOW_TIER: [(o, sorted(YELLOW[o])) for o in sorted(YELLOW)],
        BLACK_TIER: {"operations": sorted(BLACK_OPERATIONS), "resources": sorted(BLACK_RESOURCES),
                     "default": "deny"},
    }
