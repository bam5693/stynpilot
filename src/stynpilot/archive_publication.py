"""Serialize one archive publication with invalidation of its root permit."""

from contextlib import contextmanager
import fcntl
import os

from .repo_archive import ArchiveError


@contextmanager
def lock(path):
    # Both sides open the same directory inode. The receiver sees it through
    # a read-only bind, so it cannot replace the lock or its sibling permit.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ArchiveError("archive_publication_busy") from None
        yield fd
    finally:
        os.close(fd)
