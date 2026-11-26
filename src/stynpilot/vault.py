"""Dev22: encrypted, verified, automatic backups (the "vault"), one per side.

Two sides, kept apart exactly like the existing backups (backup.py): the OWNER side is run by the owner service as the owner and holds
the owner's state (request queue, revocations, provisioned marker, project roots), the owner settings file and the pairing database;
the ROOT side is run by the installer as root and holds the installer's ledgers, rollback snapshots, attention records, passkey
database, settings in /etc/stynpilot, the trusted-release-key addendum and release-transaction records. Neither side can read the other's
vault. Never included: the release signing key and the GitHub token (the release/ folder), and any file that looks like it carries a
secret (it is left out and reported, never copied).

Format of one backup file (``<side>-<YYYYmmdd-HHMMSS>-<8 hex>.stynvault``, mode 0600):
    b"STYNVLT1" | 2-byte header length | header JSON | AES-256-GCM ciphertext (tag included)
The header (format, side, created, version, key_id, nonce, size) is authenticated as associated data, so any change to it or to the
ciphertext fails decryption. Nonces are 96 random bits, checked against every nonce this vault ever used. The plaintext is a bundle:
the existing backup.py archive of the side's state (validated by backup.read_backup exactly as before) plus the extra files, each with
its SHA-256.

The key (``backup-key``, 0600, 48 bytes: b"STYNKEY1" + 8-byte id + 32-byte key) is created once. If it is missing while backups or the
vault index say a key existed, nothing is created: the vault reports ``backup_key_missing`` (a new key would silently orphan them).

Every backup is verified right after it is written (decrypt, bundle hashes, backup.read_backup, SQLite integrity_check); retention
never deletes the newest VERIFIED backup, never deletes anything to make space, and never touches files it did not create (legacy
backups and upgrade rollback records live elsewhere and are left alone). Recovery drills restore the newest verified backup into a fresh
private folder inside the vault, check it, and delete it; they never write to live state and open no network connections.
Nothing here raises into the service that runs it: every failure is recorded in the index and shown by the status.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import struct
import tempfile
import threading
import time
from pathlib import Path

from . import backup

MAGIC = b"STYNVLT1"
KEY_MAGIC = b"STYNKEY1"
BUNDLE_MAGIC = b"STYNBND1"
FORMAT = 1
SUFFIX = ".stynvault"
NAME = re.compile(r"(owner|root)-\d{8}-\d{6}-[0-9a-f]{8}\.stynvault\Z")
DAY = 86400
DUE_AFTER = DAY                        # a new backup is due when the newest verified one is older than this
DRILL_EVERY = 7 * DAY
FULL_CHECK_EVERY = 30 * DAY             # every retained backup is re-verified monthly
MANUAL_BACKUP_EVERY = 600              # rate limits for requests from assistants
MANUAL_DRILL_EVERY = 3600
OVERDUE_AFTER = 2 * DAY
DEFAULT_RETENTION = {"daily": 7, "weekly": 4}
RETENTION_LIMITS = {"daily": (1, 30), "weekly": (0, 12)}      # changing it is YELLOW (owner approval); these bounds always hold
SETTINGS = "settings.json"


def valid_retention(daily, weekly):
    for name, value in (("daily", daily), ("weekly", weekly)):
        low, high = RETENTION_LIMITS[name]
        if type(value) is not int or isinstance(value, bool) or not low <= value <= high:
            return False
    return True
# Conservative limits, checked from file sizes BEFORE anything is read (the real state is a few MB).
MAX_GATHER = 256 * 1024 * 1024          # everything one backup may read
MAX_ONE_FILE = 128 * 1024 * 1024        # any single state or extra file
MAX_BACKUP = MAX_GATHER + (16 << 20)     # a stored backup file (bundle + overhead)
MAX_EXTRA = 16 * 1024 * 1024            # one settings/extra file
SPACE_MARGIN = 64 * 1024 * 1024
CHILD_MEMORY = 1280 * 1024 * 1024       # address-space limit of the separate process that does the heavy work
CHILD_TIMEOUT = 1800
NONCE_LOG = "nonces.log"
_SECRET_BYTES = (b"BEGIN PRIVATE KEY", b"BEGIN OPENSSH PRIVATE KEY", b"BEGIN RSA PRIVATE KEY", b"BEGIN EC PRIVATE KEY",
                 b"ghp_", b"github_pat_", b"gho_", b"ghs_")
_SECRET_KEY = re.compile(r"(token|secret|password|passphrase|private|api[_-]?key|credential)", re.I)


class VaultError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# -- small safe-file helpers ---------------------------------------------------------------------------------------------------
def _fsync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(folder, name, data, mode=0o600):
    """Write ``folder/name`` all-or-nothing: exclusive temp file, fsync, rename, fsync the folder. Never through a link."""
    tmp = ".tmp-%s-%s" % (name, secrets.token_hex(4))
    fd = os.open(str(folder / tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(str(folder / tmp))
        raise
    os.close(fd)
    os.replace(str(folder / tmp), str(folder / name))
    _fsync_dir(folder)


def _read_private(path, limit, *, uid=None):
    """A regular file we own, not readable by others, opened without following links, read with a size limit."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != (os.geteuid() if uid is None else uid) or info.st_mode & 0o077:
            raise VaultError("file_not_private_or_not_ours")
        chunks, total = [], 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise VaultError("file_too_large")
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _private_folder(path):
    """Create (0700) or check a folder: a real folder, ours, nobody else may enter (directory-mode verification)."""
    path = Path(path)
    try:
        path.mkdir(mode=0o700)
        os.chmod(str(path), 0o700)
    except FileExistsError:
        pass
    info = os.lstat(str(path))
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise VaultError("vault_folder_not_private_or_not_ours")
    return path


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _secret_free(name, data, allowed_keys=None):
    """Why a file may NOT be backed up, or None. No private-key or GitHub-token markers anywhere. A settings file with a known schema
    must be a JSON object whose top-level keys are within that schema (so a legitimate field such as token_endpoint is fine, and an
    unexpected field is refused); a file without a schema must have no secret-named key at any depth."""
    if any(marker in data for marker in _SECRET_BYTES):
        return "looks_like_a_secret"
    if allowed_keys is not None:
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            return "unreadable_json"
        if type(doc) is not dict or set(doc) - set(allowed_keys):
            return "unexpected_fields"
        return None
    if name.endswith(".json"):
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            return "unreadable_json"
        stack = [doc]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for key, value in item.items():
                    if _SECRET_KEY.search(str(key)):
                        return "looks_like_a_secret"
                    stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)
    return None


def _state_sizes(state_dir, side):
    """(total bytes, largest file) of what backup.make_backup will read, from sizes alone (nothing is opened)."""
    state_dir = Path(state_dir)
    names = list(backup.OWNER_FILES) if side == "owner" else list(backup.ROOT_DBS) + list(backup.ROOT_OPTIONAL_DBS)
    total = largest = 0
    for name in names:
        try:
            size = os.lstat(str(state_dir / name)).st_size
        except FileNotFoundError:
            continue
        total, largest = total + size, max(largest, size)
    if side == "root":
        for tree in backup.ROOT_TREES:
            for path in (state_dir / tree).rglob("*") if (state_dir / tree).is_dir() else ():
                if path.is_file() and not path.is_symlink():
                    size = path.lstat().st_size
                    total, largest = total + size, max(largest, size)
    return total, largest


def _passkeys_all_quarantined(data):
    """True only if the database opens and EVERY activated, non-revoked passkey is quarantined (as quarantine_after_restore makes
    them). Any SQLite error is a failure (fail closed)."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "p.sqlite3"
        copy.write_bytes(data)
        try:
            db = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
            try:
                live = db.execute("SELECT COUNT(*) FROM passkeys WHERE revoked IS NULL AND activated IS NOT NULL "
                                  "AND quarantined != 1").fetchone()[0]
                return live == 0
            finally:
                db.close()
        except sqlite3.Error:
            return False


def _sqlite_ok(data):
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "c.sqlite3"
        copy.write_bytes(data)
        try:
            db = sqlite3.connect("file:%s?mode=ro" % copy, uri=True)
            try:
                return db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            finally:
                db.close()
        except sqlite3.Error:
            return False


def _snapshot_sqlite(path):
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "copy.sqlite3"
        source = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=10)
        dest = sqlite3.connect(str(target))
        try:
            source.backup(dest)
        finally:
            dest.close()
            source.close()
        return target.read_bytes()


# -- bundle (the plaintext) ----------------------------------------------------------------------------------------------------
def pack_bundle(meta, blobs):
    """meta: dict; blobs: {name: bytes}. Length-prefixed, every blob hashed in the index."""
    index = dict(meta, entries=[{"name": n, "size": len(b), "sha256": _sha(b)} for n, b in sorted(blobs.items())])
    head = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    return BUNDLE_MAGIC + struct.pack(">I", len(head)) + head + b"".join(blobs[n] for n in sorted(blobs))


def unpack_bundle(data):
    if not data.startswith(BUNDLE_MAGIC) or len(data) < 12:
        raise VaultError("bundle_damaged")
    (size,) = struct.unpack(">I", data[8:12])
    if size > 1 << 20 or 12 + size > len(data):
        raise VaultError("bundle_damaged")
    try:
        index = json.loads(data[12:12 + size].decode())
    except (ValueError, UnicodeError):
        raise VaultError("bundle_damaged") from None
    entries = index.get("entries") if isinstance(index, dict) else None
    if not isinstance(entries, list):
        raise VaultError("bundle_damaged")
    at, blobs = 12 + size, {}
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != {"name", "size", "sha256"} or type(entry["size"]) is not int
                or entry["size"] < 0 or not isinstance(entry["name"], str) or entry["name"] in blobs):
            raise VaultError("bundle_damaged")
        blob = data[at:at + entry["size"]]
        if len(blob) != entry["size"] or _sha(blob) != entry["sha256"]:
            raise VaultError("bundle_failed_its_hash_check")
        blobs[entry["name"]] = blob
        at += entry["size"]
    if at != len(data):
        raise VaultError("bundle_damaged")
    return index, blobs


# -- the vault -----------------------------------------------------------------------------------------------------------------
class Vault:
    """One side's vault. The heavy work (reading, encrypting, decrypting, restoring) runs in a SEPARATE short-lived process with
    its own memory limit, so running out of memory or a crash there can never take the owner service or the installer down."""

    def __init__(self, *, side, state_dir, folder, extras=(), version="", clock=time.time, retention=None, aesgcm=None,
                 space=shutil.disk_usage, isolate=False, limits=None, retention_source=None):
        if side not in ("owner", "root"):
            raise ValueError("side")
        self.side, self.state_dir, self.folder = side, Path(state_dir), Path(folder)
        self.extras, self.version, self.clock, self.space = extras, version, clock, space
        self.retention = dict(DEFAULT_RETENTION, **(retention or {}))
        self.limits = dict({"gather": MAX_GATHER, "file": MAX_ONE_FILE, "extra": MAX_EXTRA, "memory": CHILD_MEMORY}, **(limits or {}))
        self.isolate = isolate
        self.retention_source = retention_source              # owner side: the installer's approved setting is the authority
        self.policy_confirmed = retention_source is None       # owner side: only after the installer's policy was confirmed
        self._aesgcm = aesgcm
        self._mutex = threading.Lock()
        self.key_file = self.folder / "backup-key"
        self.index_file = "index.json"

    def _extra_list(self):
        """[(name, path, kind, required, allowed_keys)]; older 3-item entries mean optional with no schema."""
        out = []
        for item in self.extras:
            item = tuple(item)
            name, path, kind = item[:3]
            required = bool(item[3]) if len(item) > 3 else False
            allowed = (sorted(item[4]) if item[4] is not None else None) if len(item) > 4 else None
            out.append((name, str(path), kind, required, allowed))
        return out

    # .. retention settings (changed only through an owner-approved request) .....................................................
    def effective_retention(self):
        """The approved setting in the vault (settings.json, private, ours), else the built-in default (self.retention).
        ``trusted`` is False when a settings file EXISTS but cannot be trusted (damaged, loose, out of range): then nothing is pruned
        (the owner approved a policy we cannot read; falling back to the default could delete backups it would keep)."""
        path = self.folder / SETTINGS
        if not os.path.lexists(str(path)):
            return dict(self.retention, approved=None, at=None, trusted=True)
        try:
            data = json.loads(_read_private(path, 4096).decode())
            if (type(data) is dict and data.get("schema") == 1 and valid_retention(data.get("daily"), data.get("weekly"))
                    and type(data.get("request_id")) is str):
                return {"daily": data["daily"], "weekly": data["weekly"], "approved": data["request_id"], "at": data.get("at"),
                        "trusted": True}
        except (OSError, VaultError, ValueError, UnicodeError):
            pass
        return dict(self.retention, approved=None, at=None, trusted=False)

    def set_retention(self, daily, weekly, request_id):
        """Store an approved retention setting atomically. Bounds are enforced here too, whatever the caller checked."""
        if not valid_retention(daily, weekly) or type(request_id) is not str or not re.fullmatch(r"[0-9a-f]{64}", request_id):
            raise VaultError("retention_invalid")
        def write():
            _write_atomic(self.folder, SETTINGS, json.dumps({"schema": 1, "daily": daily, "weekly": weekly, "request_id": request_id,
                                                              "at": int(self.clock())}, sort_keys=True).encode())
            return {"ok": True, "daily": daily, "weekly": weekly}
        with self._mutex:
            _private_folder(self.folder)
            lock = os.open(str(self.folder / ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)              # waits for a running backup; never changes the rule under it
                return write()
            finally:
                os.close(lock)

    # .. index ..................................................................................................................
    def _valid_index(self, index):
        if type(index) is not dict or index.get("schema") != 1 or index.get("side") != self.side or type(index.get("backups")) is not dict:
            return False
        for name, info in index["backups"].items():
            if (not NAME.fullmatch(name) or not name.startswith(self.side + "-") or type(info) is not dict
                    or type(info.get("created")) is not int or type(info.get("size")) is not int
                    or info.get("verified_at") is not None and type(info["verified_at"]) is not int):
                return False
        return True

    def _index(self):
        try:
            data = _read_private(self.folder / self.index_file, 8 << 20)
            index = json.loads(data.decode())
            if self._valid_index(index):
                index.setdefault("manual", {})
                return index
        except FileNotFoundError:
            return self._empty()
        except (VaultError, ValueError, UnicodeError, OSError):
            pass
        return dict(self._empty(), damaged=True)

    def _empty(self):
        return {"schema": 1, "side": self.side, "key_id": None, "backups": {}, "last_attempt": None, "last_success": None,
                "last_error": None, "last_drill": None, "manual": {}}

    def _save(self, index):
        if index.pop("damaged", None):                       # never silently discard a damaged index: keep it aside, then rebuild
            try:
                os.replace(str(self.folder / self.index_file),
                           str(self.folder / ("index.damaged-%d.json" % int(self.clock()))))
            except FileNotFoundError:
                pass
        _write_atomic(self.folder, self.index_file, json.dumps(index, sort_keys=True).encode())

    def _rebuild(self, index):
        """After index damage: re-learn every backup file present from its own (authenticated) contents. Nothing is deleted."""
        for path in self._files():
            if path.name in index["backups"]:
                continue
            try:
                header, _, _ = self._verify(path.name, index)
                _, meta, _ = self.open_backup(path.name, index)          # completeness comes from the authenticated bundle itself
                excluded, incomplete = meta.get("excluded"), meta.get("incomplete")
                if not isinstance(excluded, list) or not isinstance(incomplete, list):
                    raise VaultError("bundle_metadata_missing")
                index["backups"][path.name] = {"created": int(header["created"]), "size": path.lstat().st_size,
                                               "verified_at": int(self.clock()), "checked_at": int(self.clock()),
                                               "excluded": [str(x)[:120] for x in excluded][:50],
                                               "incomplete": [str(x)[:60] for x in incomplete][:50]}
            except Exception:
                index["backups"][path.name] = {"created": int(path.lstat().st_mtime), "size": path.lstat().st_size,
                                               "verified_at": None, "failed": True, "excluded": [], "incomplete": ["unknown"]}
        index["rebuilt_at"] = int(self.clock())
        self._skip_retention = True                            # no retention in the same run as a rebuild

    # .. nonces: an append-only log, fsynced before a nonce is used, independent of the index ..................................
    def _nonces(self, index=None):
        used = set()
        try:
            data = _read_private(self.folder / NONCE_LOG, 64 << 20)
            used |= {line for line in data.decode("ascii", "replace").split() if re.fullmatch(r"[0-9a-f]{24}", line)}
        except FileNotFoundError:
            # The log holds nonces of backups that retention already deleted; the surviving files cannot stand in for it. With a key
            # already in use, a missing log stops new backups (a new key, owner-approved, is the way out: tracked for Dev23).
            if self.key_file.exists() or self._files() or (index or {}).get("key_id") or (index or {}).get("backups"):
                raise VaultError("nonce_log_missing") from None
        for path in self._files():                           # and every backup still present, in case the log was lost
            try:
                with open(str(path), "rb") as handle:
                    head = handle.read(4096)
                (size,) = struct.unpack(">H", head[8:10])
                nonce = json.loads(head[10:10 + size].decode()).get("nonce")
                if isinstance(nonce, str):
                    used.add(nonce)
            except Exception:
                continue
        return used

    def _record_nonce(self, nonce):
        fd = os.open(str(self.folder / NONCE_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            if os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_mode & 0o077:
                raise VaultError("file_not_private_or_not_ours")
            os.write(fd, (nonce + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_dir(self.folder)

    # .. key ....................................................................................................................
    def _files(self):
        return sorted(p for p in self.folder.iterdir() if NAME.fullmatch(p.name) and p.name.startswith(self.side + "-")
                      and p.is_file() and not p.is_symlink())

    def _key(self, index, *, create):
        try:
            raw = _read_private(self.key_file, 64)
        except FileNotFoundError:
            log = self.folder / NONCE_LOG
            used_log = log.exists() and (log.is_symlink() or log.stat().st_size > 0)
            if index.get("key_id") or self._files() or index.get("damaged") or used_log:
                raise VaultError("backup_key_missing")          # never silently replace a key that existing backups need
            if log.exists():
                os.unlink(str(log))                             # an EMPTY log left by an interrupted first start: nothing depended on it
            if not create:
                raise VaultError("backup_key_missing")
            raw = KEY_MAGIC + secrets.token_bytes(8) + secrets.token_bytes(32)
            # the nonce log is born with the key, so from now on a missing log always means a LOST log
            log = os.open(str(self.folder / NONCE_LOG), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            os.fsync(log)
            os.close(log)
            fd = os.open(str(self.key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, raw)
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_dir(self.folder)
        if len(raw) != 48 or not raw.startswith(KEY_MAGIC):
            raise VaultError("backup_key_damaged")
        key_id = raw[8:16].hex()
        if index.get("key_id") not in (None, key_id):
            raise VaultError("backup_key_does_not_match_the_vault")
        return key_id, raw[16:]

    def _cipher(self, key):
        if self._aesgcm:
            return self._aesgcm(key)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key)

    # .. gather .................................................................................................................
    def _gather(self):
        """(bundle bytes, excluded, incomplete). Sizes are checked BEFORE anything is read."""
        total, largest = _state_sizes(self.state_dir, self.side)
        extras = self._extra_list()
        sizes = {}
        for name, path, kind, required, allowed in extras:
            try:
                info = os.lstat(path)
                sizes[name] = info.st_size if stat.S_ISREG(info.st_mode) else 0
            except FileNotFoundError:
                sizes[name] = 0
        total += sum(sizes.values())
        if total > self.limits["gather"] or largest > self.limits["file"]:
            raise VaultError("backup_too_large_for_the_limits")
        if self.space(str(self.folder)).free < 3 * total + SPACE_MARGIN:   # room for the temporary copies AND the backup, checked first
            raise VaultError("insufficient_storage")
        with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
            archive = Path(tmp) / "state.tar"
            backup.make_backup(self.state_dir, archive, kind=self.side, clock=self.clock)
            blobs = {"state.tar": archive.read_bytes()}
        excluded, incomplete = [], []
        for name, path, kind, required, allowed in extras:
            path = Path(path)
            why = None
            try:
                if path.is_symlink():
                    why = "link"
                elif not path.is_file():
                    why = "missing"
                elif sizes[name] > self.limits["extra"]:
                    why = "too_large"
                else:
                    data = _snapshot_sqlite(path) if kind == "sqlite" else path.read_bytes()
                    if kind == "sqlite":
                        why = None if _sqlite_ok(data) else "database_damaged"
                    else:
                        why = _secret_free(name, data, allowed)
            except (OSError, sqlite3.Error):
                why = "unreadable"
            if why is None:
                blobs["extra/" + name] = data
            elif why != "missing" or required:
                excluded.append("%s:%s" % (name, why))
            if why is not None and required:
                incomplete.append(name)
        meta = {"format": FORMAT, "side": self.side, "created": int(self.clock()), "version": self.version, "excluded": excluded,
                "incomplete": incomplete, "extras": {n: {"kind": k} for n, _, k, _, _ in extras if "extra/" + n in blobs}}
        return pack_bundle(meta, blobs), excluded, incomplete

    @property
    def work(self):
        return _private_folder(self.folder / ".work")

    # .. create / verify ........................................................................................................
    def _new_nonce(self, used):
        for _ in range(8):
            nonce = secrets.token_bytes(12).hex()
            if nonce not in used:
                return nonce
        raise VaultError("nonce_generation_failed")

    def _create(self, index):
        used = self._nonces(index)                              # BEFORE a key exists: a missing log is only fine for the very first backup
        key_id, key = self._key(index, create=True)
        index["key_id"] = key_id
        bundle, excluded, incomplete = self._gather()
        free = self.space(str(self.folder)).free
        if free < 2 * len(bundle) + SPACE_MARGIN:
            raise VaultError("insufficient_storage")            # nothing is deleted to make room
        nonce = self._new_nonce(used)
        now = int(self.clock())
        header = json.dumps({"format": FORMAT, "side": self.side, "created": now, "version": self.version, "key_id": key_id,
                             "nonce": nonce, "size": len(bundle)}, sort_keys=True, separators=(",", ":")).encode()
        aad = MAGIC + struct.pack(">H", len(header)) + header
        blob = aad + self._cipher(key).encrypt(bytes.fromhex(nonce), bundle, aad)
        del bundle
        name = "%s-%s-%s%s" % (self.side, time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)), secrets.token_hex(4), SUFFIX)
        self._record_nonce(nonce)                               # recorded BEFORE the backup can exist
        self._save(index)
        _write_atomic(self.folder, name, blob)
        index["backups"][name] = {"created": now, "size": len(blob), "verified_at": None, "excluded": excluded,
                                  "incomplete": incomplete}
        return name

    def open_backup(self, name, index=None):
        """(header, bundle meta, blobs) of one backup, fully checked. Raises VaultError."""
        index = index or self._index()
        if not NAME.fullmatch(name) or not name.startswith(self.side + "-"):
            raise VaultError("not_a_vault_backup")
        blob = _read_private(self.folder / name, MAX_BACKUP)
        if not blob.startswith(MAGIC) or len(blob) < 10:
            raise VaultError("backup_damaged")
        (size,) = struct.unpack(">H", blob[8:10])
        aad = blob[:10 + size]
        try:
            header = json.loads(blob[10:10 + size].decode())
        except (ValueError, UnicodeError):
            raise VaultError("backup_damaged") from None
        if (type(header) is not dict or set(header) != {"format", "side", "created", "version", "key_id", "nonce", "size"}
                or header["format"] != FORMAT or header["side"] != self.side or not re.fullmatch(r"[0-9a-f]{24}", str(header["nonce"]))
                or type(header["size"]) is not int or header["size"] > MAX_BACKUP):
            raise VaultError("backup_damaged")
        key_id, key = self._key(index, create=False)
        if header["key_id"] != key_id:
            raise VaultError("backup_made_with_another_key")
        try:
            bundle = self._cipher(key).decrypt(bytes.fromhex(header["nonce"]), blob[10 + size:], aad)
        except Exception:
            raise VaultError("backup_failed_authentication_damaged_or_altered") from None
        del blob
        meta, blobs = unpack_bundle(bundle)
        if meta.get("side") != self.side or meta.get("format") != FORMAT or len(bundle) != header["size"] or "state.tar" not in blobs:
            raise VaultError("backup_damaged")
        return header, meta, blobs

    def _verify(self, name, index):
        header, meta, blobs = self.open_backup(name, index)
        with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
            archive = Path(tmp) / "state.tar"
            archive.write_bytes(blobs["state.tar"])
            try:
                _, files = backup.read_backup(str(archive), expected_kind=self.side)
            except backup.BackupError as error:
                raise VaultError("state_archive_invalid_" + str(error)[:60]) from None
        for member, data in list(files.items()) + [(n, b) for n, b in blobs.items() if n.startswith("extra/")]:
            if member.endswith(".sqlite3") and not _sqlite_ok(data):
                raise VaultError("database_failed_integrity_check")
        return header, files, blobs

    # .. retention ..............................................................................................................
    def _retain(self, index, protect=None):
        skip, self._skip_retention = getattr(self, "_skip_retention", False), False
        if skip or index.get("damaged") or not self._valid_index(index):
            return []                                           # never delete anything on the strength of a doubtful index
        retention = self.effective_retention()
        if not retention["trusted"] or not self.policy_confirmed:
            index["prune_held"] = "retention_settings_untrusted" if not retention["trusted"] else "retention_policy_unconfirmed"
            return []                                           # back up and verify, but delete nothing under a doubtful policy
        index.pop("prune_held", None)
        verified = sorted((info["created"], name) for name, info in index["backups"].items()
                          if info.get("verified_at") and (self.folder / name).is_file())
        if not verified:
            return []
        complete = [(c, n) for c, n in verified if not index["backups"][n].get("incomplete")]
        if complete:
            newest_complete = index["backups"][complete[-1][1]]
            if int(self.clock()) - (newest_complete.get("checked_at") or newest_complete["verified_at"]) > DAY:
                try:                                            # prune only on the strength of a FRESH check of the last good point
                    self._verify(complete[-1][1], index)
                    newest_complete["checked_at"] = int(self.clock())
                except Exception as error:
                    newest_complete["verified_at"], newest_complete["check_failed"] = None, True
                    newest_complete["check_error"] = str(getattr(error, "code", type(error).__name__))[:80]
                    index["prune_held"] = "newest_complete_backup_failed_its_check"
                    return []
        keep = {verified[-1][1], protect}                       # the newest VERIFIED backup (and the one just made) are never deleted
        if complete:
            keep.add(complete[-1][1])                           # ... nor the newest COMPLETE verified one, however many partial follow
        days, weeks = {}, {}
        for created, name in (complete or verified):            # the daily/weekly windows are filled with complete backups only
            days[time.strftime("%Y%m%d", time.gmtime(created))] = name
            weeks[time.strftime("%G%V", time.gmtime(created))] = name
        for groups, count in ((days, retention["daily"]), (weeks, retention["weekly"])):
            if count > 0:
                keep |= {name for _, name in sorted(groups.items())[-count:]}
        removed = []
        for name in list(index["backups"]):
            info = index["backups"][name]
            if name in keep or not NAME.fullmatch(name) or not name.startswith(self.side + "-") or info.get("check_failed"):
                continue                                        # a backup that failed a re-check is kept for inspection, never pruned
            if not info.get("verified_at") and not info.get("failed") and info["created"] >= verified[-1][0]:
                continue                                        # a newer, not-yet-verified backup is kept
            path = self.folder / name
            if path.is_symlink() or (path.exists() and not path.is_file()):
                continue
            try:
                os.unlink(str(path))
            except FileNotFoundError:
                pass
            del index["backups"][name]
            removed.append(name)
        if removed:
            _fsync_dir(self.folder)
        return removed

    # .. the operations (run inside the separate process when isolate=True) ......................................................
    def _locked(self, fn):
        with self._mutex:
            _private_folder(self.folder)
            lock = os.open(str(self.folder / ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise VaultError("another_backup_operation_is_running") from None
                return fn()
            finally:
                os.close(lock)

    def _load(self):
        index = self._index()
        if index.get("damaged"):
            self._rebuild(index)
        return index

    def _op_backup(self, manual):
        index = self._load()
        now = int(self.clock())
        if manual and now - index["manual"].get("backup", 0) < MANUAL_BACKUP_EVERY:
            return {"ok": False, "error": "rate_limited", "retry_after": MANUAL_BACKUP_EVERY - (now - index["manual"]["backup"])}
        if manual:
            index["manual"]["backup"] = now
        index["last_attempt"] = now
        try:
            name = self._create(index)
            self._verify(name, index)
            entry = index["backups"][name]
            entry["verified_at"] = entry["checked_at"] = int(self.clock())
            index["last_success"], index["last_error"] = int(self.clock()), None
            index.setdefault("full_check_at", int(self.clock()))   # durable start of the monthly schedule, independent of retention
            removed = self._retain(index, protect=name)
            self._save(index)
            return {"ok": True, "backup": name, "removed": len(removed), "excluded": entry["excluded"],
                    "complete": not entry["incomplete"]}
        except Exception as error:                              # recorded here, so even an unexpected failure is visible
            return self._failed(index, now, error)

    def _failed(self, index, now, error):
        code = getattr(error, "code", None) or (str(error) if isinstance(error, backup.BackupError) else type(error).__name__)
        index["last_error"] = {"at": now, "code": str(code)[:120]}
        try:
            self._save(index)
        except OSError:
            pass
        return {"ok": False, "error": str(code)[:120]}

    def _op_recheck(self, scope="daily"):
        """Re-verify backups that count. daily: the newest verified AND the newest COMPLETE verified one (independently of any newer
        incomplete backup); all: every retained backup (monthly). A backup that fails stops counting and is KEPT and reported
        (check_failed): a failed check never leads to cleanup. If the newest complete one failed, a new backup is due at once."""
        index = self._load()
        now = int(self.clock())
        verified = sorted((info["created"], name) for name, info in index["backups"].items() if info.get("verified_at"))
        if scope == "all":
            names = [n for _, n in verified]
        else:
            complete = [n for _, n in verified if not index["backups"][n].get("incomplete")]
            names = sorted({n for n in ([verified[-1][1]] if verified else []) + complete[-1:]})
        checked, failed = [], []
        for name in names:
            entry = index["backups"][name]
            try:
                if not (self.folder / name).is_file():
                    raise VaultError("verified_backup_file_missing")
                self._verify(name, index)
                entry["checked_at"] = now
                checked.append(name)
            except Exception as error:
                entry["verified_at"], entry["check_failed"] = None, True
                entry["check_error"] = str(getattr(error, "code", type(error).__name__))[:80]
                failed.append(name)
        if scope == "all":
            index["full_check_at"] = now
        if failed:
            index["last_error"] = {"at": now, "code": "newest_backup_failed_recheck_" + index["backups"][failed[-1]]["check_error"]}
        self._save(index)
        return {"ok": not failed, "checked": checked, "failed": failed} if not failed else \
            {"ok": False, "error": index["last_error"]["code"], "checked": checked, "failed": failed}

    def _op_drill(self, manual):
        index = self._load()
        now = int(self.clock())
        if manual and now - index["manual"].get("drill", 0) < MANUAL_DRILL_EVERY:
            return {"ok": False, "error": "rate_limited", "retry_after": MANUAL_DRILL_EVERY - (now - index["manual"]["drill"])}
        if manual:
            index["manual"]["drill"] = now
        verified = sorted((info["created"], name) for name, info in index["backups"].items() if info.get("verified_at"))
        result = {"at": now, "ok": False, "backup": verified[-1][1] if verified else None}
        try:
            if not verified:
                raise VaultError("no_verified_backup_to_drill")
            header, files, blobs = self._verify(verified[-1][1], index)
            with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
                target = Path(tmp) / "restored"
                work = (self.folder / ".work").resolve()
                if target.resolve() == self.state_dir.resolve() or work not in target.resolve().parents or target.exists():
                    raise VaultError("drill_target_is_live_state")       # only ever a NEW folder inside the vault's scratch area
                archive = Path(tmp) / "state.tar"
                archive.write_bytes(blobs["state.tar"])
                manifest = backup.restore_backup(str(archive), target, kind=self.side)
                for name, data in files.items():                      # every restored state file equals the backup
                    restored = (target / name).read_bytes()
                    if name == "passkeys.sqlite3":
                        if not _passkeys_all_quarantined(restored):    # intentionally changed: must be quarantined, fail closed
                            raise VaultError("drill_passkeys_were_not_quarantined")
                    elif _sha(restored) != _sha(data):
                        raise VaultError("drill_restored_file_differs_" + name.split("/")[-1][:40])
                    if name.endswith(".sqlite3") and not _sqlite_ok(restored):
                        raise VaultError("drill_database_failed_integrity_check")
                extras = _private_folder(Path(tmp) / "extras")       # every extra recovered too, then checked
                count = 0
                for name, data in blobs.items():
                    if not name.startswith("extra/"):
                        continue
                    flat = name[len("extra/"):].replace("/", "__")
                    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", flat) or flat.startswith("."):
                        raise VaultError("drill_extra_name_unsafe")
                    _write_atomic(extras, flat, data)
                    back = _read_private(extras / flat, self.limits["extra"] + 1)
                    if _sha(back) != _sha(data):
                        raise VaultError("drill_extra_differs")
                    if name.endswith(".sqlite3") and not _sqlite_ok(back):
                        raise VaultError("drill_extra_database_damaged")
                    if name.endswith(".json"):
                        json.loads(back.decode("utf-8"))
                    count += 1
                result.update(ok=True, files=len(manifest["files"]), extras=count)
        except Exception as error:
            code = getattr(error, "code", None) or (str(error) if isinstance(error, (backup.BackupError, ValueError)) else "") \
                or type(error).__name__
            result["error"] = str(code)[:120]
        index["last_drill"] = result
        self._save(index)
        return result

    def _op(self, op, manual=False):
        return {"backup": lambda: self._op_backup(manual), "drill": lambda: self._op_drill(manual),
                "recheck": lambda: self._op_recheck("daily"), "recheck_all": lambda: self._op_recheck("all")}[op]()

    # .. public ...................................................................................................................
    def _spec(self, op, manual):
        return {"side": self.side, "state_dir": str(self.state_dir), "folder": str(self.folder), "extras": self._extra_list(),
                "version": self.version, "retention": self.retention, "limits": self.limits, "op": op, "manual": manual,
                "policy_confirmed": self.policy_confirmed}

    def _sync_retention(self):
        """Owner side: fetch the installer's policy. Pruning is allowed only when this run confirmed it (the installer answered
        with a valid policy: an approved one, or 'none approved' = the default)."""
        if self.retention_source is None:
            return
        self.policy_confirmed = False
        try:
            theirs = self.retention_source()
        except Exception:
            return                                             # unreachable installer: back up and verify, prune nothing
        if not isinstance(theirs, dict) or not valid_retention(theirs.get("daily"), theirs.get("weekly")) or theirs.get("trusted") is False:
            return
        try:
            mine = self.effective_retention()
            if theirs.get("approved"):
                if (theirs["daily"], theirs["weekly"], theirs["approved"]) != (mine["daily"], mine["weekly"], mine["approved"]):
                    self.set_retention(theirs["daily"], theirs["weekly"], theirs["approved"])
            elif os.path.lexists(str(self.folder / SETTINGS)):
                return                                         # we hold an approved setting the installer no longer reports: hold
            self.policy_confirmed = True
        except Exception:
            return

    def _run(self, op, manual=False):
        self._sync_retention()
        if not self.isolate:
            return self._guard(lambda: self._op(op, manual))
        with self._mutex:
            import subprocess
            import sys
            paths = [p for p in sys.path if p and os.path.isdir(p)]
            code = ("import sys,json;sys.path[:0]=json.loads(sys.argv[1]);from stynpilot.vault import _child;_child()")
            error = "backup_process_unavailable"
            try:
                done = subprocess.run([sys.executable, "-I", "-c", code, json.dumps(paths)], input=json.dumps(self._spec(op, manual)).encode(),
                                      capture_output=True, timeout=CHILD_TIMEOUT, close_fds=True)
                lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
                result = json.loads(lines[-1][-65536:]) if done.returncode == 0 and lines else None
                if isinstance(result, dict) and result.get("error") != "backup_worker_memory_limit_unavailable":
                    return result
                error = result["error"] if isinstance(result, dict) else "backup_process_failed_exit_%d" % done.returncode
            except subprocess.TimeoutExpired:
                error = "backup_process_timed_out"
            except (OSError, ValueError):
                pass
        # the child died (memory limit, crash, timeout): record it from here; the service itself is unaffected
        self._guard(lambda: self._record_worker_failure(op, error))
        return {"ok": False, "error": error}

    def _record_worker_failure(self, op, error):
        index = self._index()
        if index.get("damaged"):
            return None                                       # never overwrite a damaged index from here; the next run rebuilds it
        now = int(self.clock())
        if op == "drill":
            index["last_drill"] = {"at": now, "ok": False, "backup": None, "error": error}
        else:
            index["last_error"] = {"at": now, "code": ("recheck_" if op == "recheck" else "") + error}
            if op == "backup":
                index["last_attempt"] = now
        self._save(index)
        return None

    def backup_now(self, *, manual=False):
        return self._run("backup", manual)

    def drill(self, *, manual=False):
        return self._run("drill", manual)

    def recheck(self):
        return self._run("recheck")

    def recheck_all(self):
        return self._run("recheck_all")

    def tick(self):
        """What is due: re-check what counts (presence hourly; full daily check of the newest verified AND the newest complete
        verified backup; every retained backup monthly), the first backup at once, a missed or replacement one, a weekly drill."""
        index = self._index()
        now = int(self.clock())
        done = {}
        verified = sorted((i["created"], n, i) for n, i in index["backups"].items() if i.get("verified_at"))
        complete = [v for v in verified if not v[2].get("incomplete")]
        watched = {v[1]: v[2] for v in verified[-1:] + complete[-1:]}
        if any(not (self.folder / n).is_file() or now - (i.get("checked_at") or i["verified_at"]) >= DAY for n, i in watched.items()):
            done["recheck"] = self.recheck()
            index = self._index()
        if verified and now - (index.get("full_check_at") or now) >= FULL_CHECK_EVERY:
            done["recheck_all"] = self.recheck_all()
            index = self._index()
        newest = max((i["verified_at"] or 0 for i in index["backups"].values()), default=0)
        if now - newest >= DUE_AFTER or str((index.get("last_error") or {}).get("code", "")).startswith("newest_backup_failed_recheck"):
            last = index.get("last_attempt") or 0
            failed_recheck = str((index.get("last_error") or {}).get("code", "")).startswith("newest_backup_failed_recheck")
            if not index.get("last_error") or (failed_recheck and now - last >= 600) or now - last >= 3600:
                done["backup"] = self.backup_now()
        last_drill = (index.get("last_drill") or {}).get("at") or 0
        if now - last_drill >= DRILL_EVERY and (newest or done.get("backup", {}).get("ok")):
            done["drill"] = self.drill()
        return done

    def _guard(self, fn):
        try:
            return self._locked(fn)
        except VaultError as error:
            return {"ok": False, "error": error.code}
        except Exception as error:                                # never into the service that runs us
            return {"ok": False, "error": "internal_" + type(error).__name__}

    def status(self):
        """Read-only health: metadata only (names, times, sizes, results). Never contents, keys or file paths outside the vault."""
        try:
            index = self._index()
            now = int(self.clock())
            present = {p.name for p in self._files()} if self.folder.is_dir() else set()
            backups = sorted(({"name": n, "created": i["created"], "size": i["size"], "verified": bool(i.get("verified_at")),
                               "present": n in present, "complete": not i.get("incomplete")} for n, i in index["backups"].items()),
                             key=lambda b: b["created"])
            verified = [b for b in backups if b["verified"] and b["present"]]
            problems = []
            if index.get("damaged"):
                problems.append("vault_index_damaged")
            if (present or index.get("key_id")) and not self.key_file.exists():
                problems.append("backup_key_missing")
            if (present or index.get("key_id")) and not (self.folder / NONCE_LOG).exists():
                problems.append("nonce_log_missing")
            if not verified:
                problems.append("no_verified_backup")
            elif now - verified[-1]["created"] > OVERDUE_AFTER:
                problems.append("backup_overdue")
            if any(b["verified"] and not b["present"] for b in backups):
                problems.append("verified_backup_file_missing")
            complete = [b for b in verified if b["complete"]]
            if verified and not verified[-1]["complete"]:
                problems.append("incomplete_backup:" + ",".join(index["backups"][verified[-1]["name"]].get("incomplete", [])))
            if not complete:
                problems.append("no_complete_verified_backup")
            elif now - complete[-1]["created"] > OVERDUE_AFTER:
                problems.append("complete_backup_overdue")
            retention = self.effective_retention()
            if not retention["trusted"]:
                problems.append("retention_settings_untrusted")
            if index.get("prune_held"):
                problems.append("pruning_on_hold:" + str(index["prune_held"]))
            bad = [n for n, i in index["backups"].items() if i.get("check_failed")]
            if bad:
                problems.append("backups_failed_a_recheck:%d" % len(bad))
            if index.get("last_error"):
                problems.append("last_backup_failed:" + index["last_error"]["code"])
            drill = index.get("last_drill")
            if drill and not drill.get("ok"):
                problems.append("last_recovery_drill_failed:" + str(drill.get("error")))
            try:
                free = self.space(str(self.folder)).free
                if verified and free < 2 * verified[-1]["size"] + SPACE_MARGIN:
                    problems.append("insufficient_storage")
            except OSError:
                free = None
            return {"side": self.side, "healthy": not problems, "problems": problems, "count": len(backups),
                    "newest_verified": verified[-1] if verified else None,
                    "newest_complete_verified": complete[-1] if complete else None,
                    "last_full_check": index.get("full_check_at"), "last_success": index.get("last_success"),
                    "last_error": index.get("last_error"), "last_drill": drill, "retention": self.effective_retention(),
                    "excluded_last_time": (index["backups"].get(verified[-1]["name"], {}).get("excluded") if verified else None),
                    "free_bytes": free, "encrypted": "AES-256-GCM"}
        except Exception as error:
            return {"side": self.side, "healthy": False, "problems": ["status_unreadable_" + type(error).__name__]}


def _child():
    """The separate process: memory-limited, does ONE operation, prints one JSON line. Its death cannot harm the service."""
    import resource
    import sys
    spec = json.loads(sys.stdin.read(1 << 20))
    try:
        limit = int(spec["limits"]["memory"])
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        if resource.getrlimit(resource.RLIMIT_AS)[0] != limit:
            raise OSError("limit not in force")
    except (ValueError, OSError, KeyError, TypeError):
        sys.stdout.write(json.dumps({"ok": False, "error": "backup_worker_memory_limit_unavailable"}) + "\n")
        return                                                # fail closed: no heavy work without the limit
    v = Vault(side=spec["side"], state_dir=spec["state_dir"], folder=spec["folder"], extras=[tuple(e) for e in spec["extras"]],
              version=spec["version"], retention=spec["retention"], limits=spec["limits"])
    v.policy_confirmed = spec.get("policy_confirmed") is True
    result = v._guard(lambda: v._op(spec["op"], spec["manual"]))
    sys.stdout.write(json.dumps(result) + "\n")
def start_scheduler(vault, *, interval=3600, first_delay=30, stop=None):
    """Background thread: tick at start (after a short delay) and then every ``interval`` seconds. Never raises."""
    stop = stop or threading.Event()

    def loop():
        if stop.wait(first_delay):
            return
        while True:
            try:
                vault.tick()
            except Exception:
                pass
            if stop.wait(interval):
                return
    thread = threading.Thread(target=loop, name="stynpilot-vault-%s" % vault.side, daemon=True)
    thread.start()
    return stop, thread
