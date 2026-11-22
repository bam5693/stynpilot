"""Backups, in THREE clearly separate recovery kinds. Do not mix them up:

1. OWNER STATE (this module, kind "owner", no special rights): the request queue, the list of revoked AI
   connectors and the token revocations. Restoring it keeps revoked connectors revoked. Needed after losing your
   own files.
2. SOFTWARE-INSTALL ROLLBACK RECORDS (kind "root", needs the owner's password through polkit): the root installer's
   ledgers and the per-install package snapshots that let an installed program be rolled back later. This is NOT a
   system snapshot and NOT owner state.
3. PRESERVE26 ROLLBACK: nothing here touches it. It is a separate package that G8 keeps in place.

A backup is one tar of regular files plus a manifest with an exact schema, a kind and a SHA-256 for every file.
The hashes detect damage or partial files; they are NOT a signature, so someone who can rewrite the whole archive
can forge it. Restore verifies the complete file set first and only writes into an EMPTY private folder.
SQLite files are copied with SQLite's own online-backup call (consistent while the service runs).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import sqlite3
import stat
import tarfile
import tempfile
import time
from pathlib import Path

SCHEMA = 1
OWNER_FILES = ("requests.sqlite3", "revoked-clients.json", "token-revocations.sqlite3", "provisioned.json")
ROOT_DBS = ("runs.sqlite3", "installs.sqlite3")
ROOT_TREES = ("snapshots", "attention")
MANIFEST = "manifest.json"
_MAX_FILE = 1024 * 1024 * 1024
_MAX_FILES = 20000


class BackupError(Exception):
    pass


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _snapshot(path):
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


def _safe_rel(name):
    parts = posixpath.normpath(name).split("/")
    if (name != posixpath.normpath(name) or name.startswith("/") or ".." in parts or "" in parts
            or any(p.startswith(".") for p in parts) or "\\" in name or "\0" in name):
        raise BackupError("archive_member_not_allowed")
    return name


def _gather(state_dir, kind):
    state_dir = Path(state_dir)
    _check_dir(state_dir)
    members = {}
    names = OWNER_FILES if kind == "owner" else ROOT_DBS
    for name in names:
        path = state_dir / name
        if not path.exists() or path.is_symlink():
            raise BackupError("state_file_missing_%s" % name)
        members[name] = _snapshot(path)
    if kind == "root":
        for tree in ROOT_TREES:
            base = state_dir / tree
            if not base.is_dir() or base.is_symlink():
                raise BackupError("state_folder_missing_%s" % tree)
            for path in sorted(base.rglob("*")):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise BackupError("unexpected_entry_in_%s" % tree)
                if path.is_file():
                    members[path.relative_to(state_dir).as_posix()] = path.read_bytes()
        if len(members) > _MAX_FILES:
            raise BackupError("too_many_files")
    return members


def make_backup(state_dir, out_file, *, kind="owner", clock=time.time, chown_to=None):
    if kind not in ("owner", "root"):
        raise BackupError("unknown_kind")
    out_file = Path(out_file)
    members = _gather(state_dir, kind)
    manifest = {"schema": SCHEMA, "kind": kind, "created": int(clock()),
                "files": {name: _sha(data) for name, data in members.items()}}
    out_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        with tarfile.open(fileobj=handle, mode="w") as tar:
            for name, data in {**members, MANIFEST: json.dumps(manifest, sort_keys=True).encode()}.items():
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o600, int(clock())
                tar.addfile(info, io.BytesIO(data))
        handle.flush()
        os.fsync(handle.fileno())
    if chown_to is not None:
        os.chown(out_file, chown_to, -1)
    return manifest


def _validate_complete(kind, files):
    """Exact, complete file set for the kind; anything missing, extra or malformed is refused."""
    if kind == "owner":
        if set(files) != set(OWNER_FILES):
            raise BackupError("owner_backup_file_set_is_not_exactly_the_expected_one")
        return
    if not set(ROOT_DBS) <= set(files):
        raise BackupError("root_backup_missing_its_databases")
    snapshots = {}
    for name in files:
        parts = name.split("/")
        if name in ROOT_DBS:
            continue
        if parts[0] == "attention" and len(parts) == 2 and parts[1].endswith(".json"):
            continue
        if parts[0] == "snapshots" and len(parts) >= 3:
            snapshots.setdefault(parts[1], []).append("/".join(parts[2:]))
            continue
        raise BackupError("root_backup_has_an_unexpected_member")
    for sid, inside in snapshots.items():
        if "manifest.json" not in inside:
            raise BackupError("snapshot_without_its_manifest")
        try:
            man = json.loads(files["snapshots/%s/manifest.json" % sid].decode())
        except (ValueError, UnicodeError):
            raise BackupError("snapshot_manifest_unreadable") from None
        for entry in (man.get("debs") or {}).values():
            member = "snapshots/%s/debs/%s" % (sid, entry.get("file"))
            if member not in files or _sha(files[member]) != entry.get("sha256"):
                raise BackupError("snapshot_package_file_missing_or_changed")
        for entry in (man.get("files") or {}).values():
            member = "snapshots/%s/files/%s" % (sid, entry.get("copy"))
            if member not in files or _sha(files[member]) != entry.get("sha256"):
                raise BackupError("snapshot_settings_file_missing_or_changed")


def read_backup(archive, *, expected_kind=None):
    """Verified (manifest, {name: bytes}); refuses anything incomplete, mixed, odd or altered."""
    try:
        with tarfile.open(archive, mode="r:") as tar:
            files, count = {}, 0
            for member in tar.getmembers():
                count += 1
                if not member.isreg() or member.size > _MAX_FILE or count > _MAX_FILES + 1:
                    raise BackupError("archive_member_not_allowed")
                files[_safe_rel(member.name)] = tar.extractfile(member).read()
    except (tarfile.TarError, OSError):
        raise BackupError("archive_unreadable") from None
    try:
        manifest = json.loads(files.pop(MANIFEST).decode())
    except (KeyError, ValueError, UnicodeError):
        raise BackupError("archive_has_no_valid_manifest") from None
    if (type(manifest) is not dict or set(manifest) != {"schema", "kind", "created", "files"}
            or manifest["schema"] != SCHEMA or manifest["kind"] not in ("owner", "root")
            or type(manifest["files"]) is not dict):
        raise BackupError("archive_manifest_has_the_wrong_shape")
    if expected_kind is not None and manifest["kind"] != expected_kind:
        raise BackupError("this_is_a_%s_backup_not_a_%s_one" % (manifest["kind"], expected_kind))
    if set(manifest["files"]) != set(files) or any(_sha(files[n]) != h for n, h in manifest["files"].items()):
        raise BackupError("archive_failed_its_hash_check")
    _validate_complete(manifest["kind"], files)
    return manifest, files


def restore_backup(archive, state_dir, *, kind="owner"):
    """Into an EMPTY private folder only. Everything is verified first; nothing existing is overwritten."""
    manifest, files = read_backup(archive, expected_kind=kind)
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    _check_dir(state_dir)
    if any(state_dir.iterdir()):
        raise BackupError("destination_not_empty_refusing_to_overwrite")
    for name, data in sorted(files.items()):
        target = state_dir / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    if kind == "root":
        for sub in ("downloads",):
            (state_dir / sub).mkdir(mode=0o700, exist_ok=True)
    return manifest
