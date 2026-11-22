"""Backup and restore of the owner service's state (and, when run as root, the installer's ledgers).

A backup is ONE tar file with a manifest of SHA-256 hashes, written 0600 next to nothing else. SQLite files are
copied with SQLite's own online-backup call (consistent even while the service runs). Restoring is the safe way to
recover lost state: it brings back the revocation lists exactly as they were, so a revoked AI client stays
revoked. Restore refuses to touch a folder that already holds state, and verifies every hash first.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path

OWNER_FILES = ("requests.sqlite3", "revoked-clients.json", "token-revocations.sqlite3", "provisioned.json")
INSTALLER_FILES = ("runs.sqlite3", "installs.sqlite3")
MANIFEST = "manifest.json"
_MAX = 512 * 1024 * 1024


class BackupError(Exception):
    pass


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _snapshot(path):
    """Bytes of a consistent copy of one state file."""
    if path.suffix == ".sqlite3":
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "copy.sqlite3"
            source = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
            dest = sqlite3.connect(target)
            try:
                source.backup(dest)
            finally:
                dest.close()
                source.close()
            return target.read_bytes()
    return path.read_bytes()


def _check_dir(path):
    info = os.lstat(path)
    if path.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise BackupError("folder_must_be_private_and_ours")


def make_backup(state_dir, out_file, *, names=OWNER_FILES, kind="owner", clock=time.time):
    state_dir, out_file = Path(state_dir), Path(out_file)
    _check_dir(state_dir)
    members, manifest = {}, {"kind": kind, "created": int(clock()), "files": {}}
    for name in names:
        path = state_dir / name
        if not path.exists():
            raise BackupError("state_file_missing_%s" % name)
        data = _snapshot(path)
        members[name] = data
        manifest["files"][name] = _sha(data)
    members[MANIFEST] = json.dumps(manifest, sort_keys=True).encode()
    out_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle, tarfile.open(fileobj=handle, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, int(clock())
            tar.addfile(info, io.BytesIO(data))
    return manifest


def read_backup(archive):
    """Verified {name: bytes}; any odd member, size or hash mismatch refuses the whole archive."""
    try:
        with tarfile.open(archive, mode="r:") as tar:
            files = {}
            for member in tar.getmembers():
                if not member.isreg() or "/" in member.name or member.name.startswith(".") or member.size > _MAX:
                    raise BackupError("archive_member_not_allowed")
                files[member.name] = tar.extractfile(member).read()
    except (tarfile.TarError, OSError):
        raise BackupError("archive_unreadable") from None
    try:
        manifest = json.loads(files.pop(MANIFEST).decode())
    except (KeyError, ValueError):
        raise BackupError("archive_has_no_valid_manifest") from None
    if set(manifest.get("files", {})) != set(files) or any(_sha(files[n]) != h for n, h in manifest["files"].items()):
        raise BackupError("archive_failed_its_hash_check")
    allowed = set(OWNER_FILES) | set(INSTALLER_FILES)
    if not set(files) <= allowed:
        raise BackupError("archive_member_not_allowed")
    return manifest, files


def restore_backup(archive, state_dir):
    """Into an EMPTY private folder only. Verified first; written 0600; nothing existing is overwritten."""
    manifest, files = read_backup(archive)
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _check_dir(state_dir)
    if any(state_dir.iterdir()):
        raise BackupError("destination_not_empty_refusing_to_overwrite")
    for name, data in files.items():
        fd = os.open(state_dir / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    return manifest
