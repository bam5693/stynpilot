"""Two advisory file locks that make privileged backup/restore of the root installer's records SAFE, not just documented.

  installer.alive  held (shared) by a running installer for its whole life.  RESTORE needs it exclusively, so a restore
                   is refused while the installer is running.
  installer.lock   held (exclusive) by the installer for the duration of one install or rollback, and by a backup or
                   restore while it works.  A backup is refused while a change is running, and a change is refused
                   (never queued, never interleaved) while a backup is reading the records.

The kernel drops flock locks when the holder dies, so a crash can never leave a stale lock.
"""
from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path

OPERATION = "installer.lock"
ALIVE = "installer.alive"
LOCK_FILES = (OPERATION, ALIVE)


class Busy(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _open(state_dir, name):
    return os.open(Path(state_dir) / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


def _take(state_dir, name, mode, code):
    fd = _open(state_dir, name)
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise Busy(code) from None
    return fd


@contextmanager
def operation(state_dir, code="installer_is_busy_with_a_change_or_a_backup"):
    fd = _take(state_dir, OPERATION, fcntl.LOCK_EX, code)
    try:
        yield
    finally:
        os.close(fd)


def hold_alive(state_dir):
    """Returned fd stays open (shared lock) as long as the installer object lives."""
    return _take(state_dir, ALIVE, fcntl.LOCK_SH, "state_is_being_restored")


@contextmanager
def exclusive_for_restore(state_dir):
    """Installer must be stopped AND idle; nothing else may touch the records while we write them."""
    alive = _take(state_dir, ALIVE, fcntl.LOCK_EX, "installer_is_running_stop_it_first")
    try:
        with operation(state_dir):
            yield
    finally:
        os.close(alive)
