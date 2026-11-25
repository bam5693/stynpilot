"""Release-authority steps that only happen at the computer's own console, as root (``sudo stynpilot service release ...``).

Why console only: the release signing key and the GitHub access are what let this computer publish software. Provisioning them
through any service the owner's side (or an assistant) can reach would let a compromised one plant its own key or token. At the console
there is nobody to relay: root creates the key itself, shows the owner its fingerprint, and the token is typed in privately.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import release
from .broker.release_authority import Authority, AuthorityError


def _tty(is_tty):
    return sys.stdin.isatty() if is_tty is None else is_tty


def _write_addendum(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def init(authority, addendum, *, out=print):
    """Create the signing key here (if none) and make THIS computer trust its public half. Idempotent."""
    entry = authority.init_key()
    current = {"keys": [], "revoked": []}
    if os.path.lexists(addendum):
        try:
            _, current = release._read_keys(addendum)
        except (OSError, ValueError, KeyError, TypeError):
            out("The existing trusted-keys file is damaged. Nothing was changed.")
            return 1
        current.setdefault("revoked", [])
    if entry["key_id"] not in [k["key_id"] for k in current["keys"]]:
        current["keys"].append(entry)
    if entry["key_id"] in current["revoked"]:
        current["revoked"].remove(entry["key_id"])
    _write_addendum(addendum, current)
    out("Release signing key ready. Key ID: %s" % entry["key_id"])
    out("This computer now trusts releases signed by that key. The private half never leaves the installer's private folder.")
    return 0


def set_token(authority, *, getpass_fn=None, is_tty=None, out=print):
    if not _tty(is_tty):
        out("Refusing: this needs a real terminal and a person typing. Nothing was changed.")
        return 2
    if getpass_fn is None:
        import getpass
        getpass_fn = getpass.getpass
    out("Paste the GitHub token for the StyNpilot repository only (Contents: read and write). Nothing is shown as you type.")
    token = getpass_fn("token> ").strip()
    try:
        authority.set_token(token)
    except AuthorityError as refused:
        out("Not saved: %s" % refused.code)
        return 1
    try:
        checked = authority.check_token()
    except AuthorityError as failed:
        out("Saved, but could not check it with GitHub right now (%s). Run the status action later." % failed.code)
        return 0
    out("Saved. GitHub says this token %s write to the StyNpilot repository." % ("CAN" if checked["ok"] else "CANNOT"))
    return 0 if checked["ok"] else 1


def status(authority, addendum, *, keys_file=release.KEYS_FILE, out=print):
    ready = authority.ready()
    out("Signing key: %s" % ("present, ID %s" % authority.key_entry()["key_id"] if ready["key"] else "missing (run --action init)"))
    out("GitHub token: %s" % ("saved" if ready["token"] else "missing (run --action set-token)"))
    out("Build account: %s" % ("configured" if ready["builder"] else "not configured (see docs)"))
    try:
        trusted = release.load_trusted_keys(keys_file, addendum=addendum)
        mine = authority.key_entry()["key_id"] if ready["key"] else None
        out("This computer trusts the signing key: %s" % ("yes" if mine in trusted else "NO"))
    except release.ReleaseError as problem:
        out("Trusted keys problem: %s" % problem.code)
    return 0
