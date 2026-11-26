"""Persistent worker fence, separate from the private restore state.

Only the fixed packaged installer provisions this root-owned file. Never
replace it on restart. A missing or malformed fence fails closed. A worker
takes a shared lease BEFORE reserving activity; owner-approved settlement
must obtain the exclusive lease BEFORE spending proof. Kernel release on
process death is not evidence of Ollama quiescence; that is checked separately.
"""
from __future__ import annotations

import fcntl
import os
import pwd
import stat
from contextlib import contextmanager
from pathlib import Path

from .managed_activity import ActivityError

FOLDER = Path("/var/lib/stynpilot-inference")
NAME = "worker.lock"


def _directory(folder, authority):
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != authority or stat.S_IMODE(info.st_mode) != 0o755:
            raise ActivityError("inference_fence_untrusted")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _validate(fd, authority, gid):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != authority
            or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o640
            or info.st_nlink != 1 or info.st_size != 0):
        raise ActivityError("inference_fence_untrusted")


def _provision(folder, gid, authority, *, allow_create):
    # Production uses a fixed directory under root-owned /var/lib.
    if allow_create:
        try:
            os.mkdir(folder, 0o700)
        except FileExistsError:
            pass
        else:
            # Installer umask may be 077. Set the exact traversal mode only
            # on the newly created, authority-owned directory.
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if os.fstat(fd).st_uid != authority:
                    raise ActivityError("inference_fence_untrusted")
                os.fchmod(fd, 0o755)
                os.fsync(fd)
            finally:
                os.close(fd)
            parent = os.open(Path(folder).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    directory = _directory(folder, authority)
    try:
        if allow_create:
            try:
                fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            except FileExistsError:
                pass
            else:
                try:
                    info = os.fstat(fd)
                    if (info.st_uid, info.st_gid) != (authority, gid):
                        os.fchown(fd, authority, gid)
                    os.fchmod(fd, 0o640)
                    os.fsync(fd)
                    os.fsync(directory)
                finally:
                    os.close(fd)
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                     os.O_NONBLOCK, dir_fd=directory)
        try:
            _validate(fd, authority, gid)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def provision(uid, *, allow_create):
    if os.geteuid() != 0 or type(uid) is not int or uid <= 0:
        raise ActivityError("inference_fence_untrusted")
    _provision(FOLDER, pwd.getpwuid(uid).pw_gid, 0, allow_create=allow_create)


@contextmanager
def _lease(folder, gid, authority, *, exclusive):
    directory = None
    fd = None
    try:
        directory = _directory(folder, authority)
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                     os.O_NONBLOCK, dir_fd=directory)
        _validate(fd, authority, gid)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ActivityError("inference_worker_busy") from None
        # Compare held inode with its name after acquisition.
        named = os.stat(NAME, dir_fd=directory, follow_symlinks=False)
        actual = os.fstat(fd)
        if (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino):
            raise ActivityError("inference_fence_untrusted")
    except OSError:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        raise ActivityError("inference_fence_unavailable") from None
    except BaseException:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        raise
    try:
        yield
    finally:
        os.close(fd)
        os.close(directory)


def worker():
    if os.geteuid() == 0:
        raise ActivityError("inference_owner_invalid")
    return _lease(FOLDER, os.getegid(), 0, exclusive=False)


def settlement(uid):
    if os.geteuid() != 0 or type(uid) is not int or uid <= 0:
        raise ActivityError("inference_fence_untrusted")
    return _lease(FOLDER, pwd.getpwuid(uid).pw_gid, 0, exclusive=True)
