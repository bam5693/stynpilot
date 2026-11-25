"""Passkey steps that only happen at the computer's own console, as root (``sudo stynpilot service passkeys ...``).

Why this exists: activating a new passkey gives it the power to approve system changes. If that step went through the owner-side
service, a compromised service could register its own key and show the owner a friendly summary. At the console there is no such
relay: root opens the installer's own database, shows what is really stored, and the owner (who must be at the machine or on
its SSH login, and authenticated for sudo) types the key's fingerprint to confirm. It refuses to run without a terminal.
"""
from __future__ import annotations

import sys
import time

from .broker.passkeys import PasskeyError


def _when(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "never"


def describe(key, now=None):
    now = now or time.time()
    kind = "synced through your Google account" if key["synced"] else "stays on one device"
    state = "RESTORED, quarantined" if key.get("quarantined") else ("pending" if key["pending"] else "active")
    return ("  ID %s  name %r  %s  key fingerprint %s\n      created %s (%d min ago), last used %s, %s"
            % (key["kid"], key["label"], kind, key["pub"][:16], _when(key["created"]), max(0, int((now - key["created"]) // 60)),
               _when(key["last_used"]), state))


def show(store, out=print):
    out("Active passkeys:")
    for key in store.active() or [None]:
        out(describe(key) if key else "  (none)")
    out("Pending (created, cannot approve anything yet):")
    for key in store.pending() or [None]:
        out(describe(key) if key else "  (none)")
    quarantined = store.quarantined()
    if quarantined:
        out("Restored from a backup and QUARANTINED (they cannot approve anything until you confirm them here):")
        for key in quarantined:
            out(describe(dict(key, quarantined=True)))
    out("Audit chain intact: %s" % ("yes" if store.audit_ok() else "NO - the record was altered"))
    return 0


def _confirm(prompt_for, fingerprint, input_fn, out):
    out("To confirm, type the first 8 characters of the key fingerprint (%s) exactly, or press Enter to cancel." % fingerprint[:8])
    return input_fn("> ").strip().lower() == fingerprint[:8]


def activate(store, kid, *, input_fn=input, is_tty=None, out=print):
    """Activate one PENDING passkey after the owner reads its real details and types its fingerprint."""
    if not (sys.stdin.isatty() if is_tty is None else is_tty):
        out("Refusing: this needs a real terminal and a person typing. Nothing was changed.")
        return 2
    pending = store.pending()
    match = [k for k in pending if k["kid"] == kid]
    if not match:
        out("No pending passkey with that ID (it may have expired after 15 minutes). Nothing was changed.")
        return 1
    key = match[0]
    out("Activate this passkey? It will be able to approve StyNpilot changes whenever your phone confirms it is you.")
    out(describe(key))
    if len(pending) > 1:
        out("WARNING: %d passkeys are pending but you should have created only one. If you did not create the others, "
            "do NOT continue; ask an assistant to run passkey_status and have the extras removed." % len(pending))
    if not _confirm("activate", key["pub"], input_fn, out):
        out("Cancelled. Nothing was changed.")
        return 1
    try:
        left = store.activate(kid, key["label"], key["pub"], "console", "console")
    except PasskeyError as refused:
        out("Not activated: %s" % refused.code)
        return 1
    out("Activated. Active passkeys: %d." % left)
    return 0


def confirm_restored(store, kid, *, input_fn=input, is_tty=None, out=print):
    if not (sys.stdin.isatty() if is_tty is None else is_tty):
        out("Refusing: this needs a real terminal and a person typing. Nothing was changed.")
        return 2
    match = [k for k in store.quarantined() if k["kid"] == kid]
    if not match:
        out("No quarantined passkey with that ID. Nothing was changed.")
        return 1
    key = match[0]
    out("This passkey came back from a backup. It may have been removed after that backup was made.")
    out(describe(dict(key, quarantined=True)))
    if not _confirm("restore", key["pub"], input_fn, out):
        out("Cancelled. Nothing was changed.")
        return 1
    try:
        store.reconfirm(kid, "console")
    except PasskeyError as refused:
        out("Not restored: %s" % refused.code)
        return 1
    out("Confirmed. It can approve changes again.")
    return 0
