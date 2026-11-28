"""Root-side durable claim for mutually exclusive managed activities.

The caller MUST hold the existing exclusive restore admission lock during
claim, finish and recovery reservation. Claims are outside the restored
trees and are never cleared by a timeout or a client disconnect. An ambiguous
completion requires a separately authorized, verified quiescence procedure.
This module does not start or stop services.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

NAME = "managed-activity"
ID = re.compile(r"[a-f0-9]{32}\Z")
KINDS = ("inference", "dev_lab", "deckplay_checkout")


class ActivityError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def path(state):
    return Path(state) / NAME


def held(state):
    # A malformed file, directory or dangling symlink also blocks recovery.
    try:
        os.lstat(path(state))
    except FileNotFoundError:
        return False
    except OSError:
        raise ActivityError("activity_state_unreadable") from None
    return True


def _sync(state):
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _record(kind, job):
    if kind not in KINDS or type(job) is not str or not ID.fullmatch(job):
        raise ActivityError("activity_claim_invalid")
    return (kind + ":" + job + "\n").encode("ascii")


def claim(state, kind, job):
    """Reserve BEFORE starting work, under exclusive restore admission."""
    data = _record(kind, job)
    control = Path(state) / "restore-control"
    if any(os.path.lexists(control / name) for name in ("pending.json", "safe.json")):
        raise ActivityError("root_restore_in_progress")
    try:
        fd = os.open(path(state), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise ActivityError("managed_activity_busy") from None
    try:
        # On any failure, do not unlink a partial reservation. Fail closed.
        if os.write(fd, data) != len(data):
            raise ActivityError("activity_claim_incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync(state)


def current(state):
    """Return only validated claim identity, never caller-provided evidence."""
    try:
        fd = os.open(path(state), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        if held(state):
            raise ActivityError("activity_claim_unreadable") from None
        return None
    except OSError:
        raise ActivityError("activity_claim_unreadable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 64):
            raise ActivityError("activity_claim_mismatch")
        raw = os.read(fd, 65)
        try:
            kind, job = raw.decode("ascii").rstrip("\n").split(":")
        except (ValueError, UnicodeError):
            raise ActivityError("activity_claim_mismatch") from None
        if raw != _record(kind, job):
            raise ActivityError("activity_claim_mismatch")
        return {"kind": kind, "job_id": job}
    finally:
        os.close(fd)


def finish(state, kind, job):
    """Clear only the exact claim after the trusted controller proves completion."""
    expected = _record(kind, job)
    try:
        fd = os.open(path(state), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise ActivityError("activity_claim_unreadable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or info.st_size != len(expected) or os.read(fd, len(expected)+1) != expected):
            raise ActivityError("activity_claim_mismatch")
    finally:
        os.close(fd)
    os.unlink(path(state))
    _sync(state)


def require_idle(state):
    if held(state):
        raise ActivityError("restore_requires_idle_managed_activity")
