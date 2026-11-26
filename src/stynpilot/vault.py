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
MANUAL_BACKUP_EVERY = 600              # rate limits for requests from assistants
MANUAL_DRILL_EVERY = 3600
OVERDUE_AFTER = 2 * DAY
DEFAULT_RETENTION = {"daily": 7, "weekly": 4}
MAX_BACKUP = 2 * 1024 * 1024 * 1024
MAX_EXTRA = 64 * 1024 * 1024
MAX_NONCES = 50000
SPACE_MARGIN = 64 * 1024 * 1024
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


def _secret_free(name, data):
    """True when a file may be backed up: no private-key or GitHub-token markers, and (for JSON) no secret-named key."""
    if any(marker in data for marker in _SECRET_BYTES):
        return False
    if name.endswith(".json"):
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            return False
        stack = [doc]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                for key, value in item.items():
                    if _SECRET_KEY.search(str(key)) and key not in ("approval_client_id",):
                        return False
                    stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)
    return True


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
    def __init__(self, *, side, state_dir, folder, extras=(), version="", clock=time.time, retention=None, aesgcm=None,
                 space=shutil.disk_usage):
        if side not in ("owner", "root"):
            raise ValueError("side")
        self.side, self.state_dir, self.folder = side, Path(state_dir), Path(folder)
        self.extras, self.version, self.clock, self.space = list(extras), version, clock, space
        self.retention = dict(DEFAULT_RETENTION, **(retention or {}))
        self._aesgcm = aesgcm
        self._mutex = threading.Lock()
        self.key_file = self.folder / "backup-key"
        self.index_file = "index.json"

    # .. index ..................................................................................................................
    def _index(self):
        try:
            data = _read_private(self.folder / self.index_file, 8 << 20)
            index = json.loads(data.decode())
            if type(index) is dict and index.get("schema") == 1:
                return index
            return dict(self._empty(), damaged=True)
        except FileNotFoundError:
            return self._empty()
        except (VaultError, ValueError, UnicodeError, OSError):
            return dict(self._empty(), damaged=True)

    def _empty(self):
        return {"schema": 1, "side": self.side, "key_id": None, "backups": {}, "nonces": [], "last_attempt": None,
                "last_success": None, "last_error": None, "last_drill": None, "manual": {}}

    def _save(self, index):
        index.pop("damaged", None)
        index["nonces"] = index["nonces"][-MAX_NONCES:]
        _write_atomic(self.folder, self.index_file, json.dumps(index, sort_keys=True).encode())

    # .. key ....................................................................................................................
    def _files(self):
        return sorted(p for p in self.folder.iterdir() if NAME.fullmatch(p.name) and p.name.startswith(self.side + "-"))

    def _key(self, index, *, create):
        try:
            raw = _read_private(self.key_file, 64)
        except FileNotFoundError:
            if index.get("key_id") or self._files() or index.get("damaged"):
                raise VaultError("backup_key_missing")          # never silently replace a key that existing backups need
            if not create:
                raise VaultError("backup_key_missing")
            raw = KEY_MAGIC + secrets.token_bytes(8) + secrets.token_bytes(32)
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
        """(bundle bytes, excluded names). The state archive is backup.py's own, verified format."""
        with tempfile.TemporaryDirectory(dir=str(self.work)) as tmp:
            archive = Path(tmp) / "state.tar"
            backup.make_backup(self.state_dir, archive, kind=self.side, clock=self.clock)
            blobs = {"state.tar": archive.read_bytes()}
        excluded = []
        for name, path, kind in self.extras:
            path = Path(path)
            try:
                if path.is_symlink():
                    excluded.append(name + ":link")
                    continue
                if not path.is_file():
                    continue                                    # optional settings that do not exist are simply absent
                if path.stat().st_size > MAX_EXTRA:
                    excluded.append(name + ":too_large")
                    continue
                data = _snapshot_sqlite(path) if kind == "sqlite" else path.read_bytes()
            except (OSError, sqlite3.Error):
                excluded.append(name + ":unreadable")
                continue
            if kind != "sqlite" and not _secret_free(name, data):
                excluded.append(name + ":looks_like_a_secret")
                continue
            blobs["extra/" + name] = data
        meta = {"format": FORMAT, "side": self.side, "created": int(self.clock()), "version": self.version, "excluded": excluded}
        return pack_bundle(meta, blobs), excluded

    @property
    def work(self):
        return _private_folder(self.folder / ".work")

    # .. create / verify ........................................................................................................
    def _new_nonce(self, index):
        used = set(index["nonces"])
        for _ in range(8):
            nonce = secrets.token_bytes(12).hex()
            if nonce not in used:
                return nonce
        raise VaultError("nonce_generation_failed")

    def _create(self, index):
        key_id, key = self._key(index, create=True)
        index["key_id"] = key_id
        bundle, excluded = self._gather()
        free = self.space(str(self.folder)).free
        if free < 2 * len(bundle) + SPACE_MARGIN:
            raise VaultError("insufficient_storage")            # nothing is deleted to make room
        nonce = self._new_nonce(index)
        now = int(self.clock())
        header = json.dumps({"format": FORMAT, "side": self.side, "created": now, "version": self.version, "key_id": key_id,
                             "nonce": nonce, "size": len(bundle)}, sort_keys=True, separators=(",", ":")).encode()
        aad = MAGIC + struct.pack(">H", len(header)) + header
        blob = aad + self._cipher(key).encrypt(bytes.fromhex(nonce), bundle, aad)
        name = "%s-%s-%s%s" % (self.side, time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)), secrets.token_hex(4), SUFFIX)
        index["nonces"].append(nonce)
        self._save(index)                                       # the nonce is recorded BEFORE the backup can exist
        _write_atomic(self.folder, name, blob)
        index["backups"][name] = {"created": now, "size": len(blob), "verified_at": None, "excluded": excluded}
        return name

    def open_backup(self, name, index=None):
        """(header, bundle index, blobs) of one backup, fully checked. Raises VaultError."""
        index = index or self._index()
        if not NAME.fullmatch(name):
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
                or header["format"] != FORMAT or header["side"] != self.side or not re.fullmatch(r"[0-9a-f]{24}", str(header["nonce"]))):
            raise VaultError("backup_damaged")
        key_id, key = self._key(index, create=False)
        if header["key_id"] != key_id:
            raise VaultError("backup_made_with_another_key")
        try:
            bundle = self._cipher(key).decrypt(bytes.fromhex(header["nonce"]), blob[10 + size:], aad)
        except Exception:
            raise VaultError("backup_failed_authentication_damaged_or_altered") from None
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
        verified = sorted((info["created"], name) for name, info in index["backups"].items()
                          if info.get("verified_at") and (self.folder / name).exists())
        if not verified:
            return []
        keep = {verified[-1][1], protect}                       # the newest VERIFIED backup (and the one just made) are never deleted
        days, weeks = {}, {}
        for created, name in verified:
            days[time.strftime("%Y%m%d", time.gmtime(created))] = name
            weeks[time.strftime("%G%V", time.gmtime(created))] = name
        for groups, count in ((days, self.retention["daily"]), (weeks, self.retention["weekly"])):
            if count > 0:
                keep |= {name for _, name in sorted(groups.items())[-count:]}
        removed = []
        for name in list(index["backups"]):
            info = index["backups"][name]
            if name in keep:
                continue
            if not info.get("verified_at") and info["created"] >= verified[-1][0]:
                continue                                        # a newer, unverified backup is kept for inspection
            try:
                os.unlink(str(self.folder / name))
            except FileNotFoundError:
                pass
            del index["backups"][name]
            removed.append(name)
        if removed:
            _fsync_dir(self.folder)
        return removed

    # .. public operations ......................................................................................................
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

    def backup_now(self, *, manual=False):
        """Create, verify, then apply retention. Returns a short result; failures are recorded, never raised to the caller."""
        def run():
            index = self._index()
            now = int(self.clock())
            if manual and now - index["manual"].get("backup", 0) < MANUAL_BACKUP_EVERY:
                return {"ok": False, "error": "rate_limited", "retry_after": MANUAL_BACKUP_EVERY - (now - index["manual"]["backup"])}
            if manual:
                index["manual"]["backup"] = now
            index["last_attempt"] = now
            try:
                name = self._create(index)
                self._verify(name, index)
                index["backups"][name]["verified_at"] = int(self.clock())
                index["last_success"], index["last_error"] = int(self.clock()), None
                removed = self._retain(index, protect=name)
                self._save(index)
                return {"ok": True, "backup": name, "removed": len(removed), "excluded": index["backups"][name]["excluded"]}
            except (VaultError, backup.BackupError, OSError) as error:
                code = getattr(error, "code", None) or (str(error) if isinstance(error, backup.BackupError) else type(error).__name__)
                index["last_error"] = {"at": now, "code": str(code)[:120]}
                try:
                    self._save(index)
                except OSError:
                    pass
                return {"ok": False, "error": str(code)[:120]}
        return self._guard(run)

    def drill(self, *, manual=False):
        """Restore the newest verified backup into a fresh private folder, check it, delete it. Live state is never touched."""
        def run():
            index = self._index()
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
                    restored = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
                    missing = set(manifest["files"]) - restored
                    if missing:
                        raise VaultError("drill_restore_incomplete")
                    for name in manifest["files"]:
                        if name.endswith(".sqlite3") and not _sqlite_ok((target / name).read_bytes()):
                            raise VaultError("drill_database_failed_integrity_check")
                    if self.side == "root" and "passkeys.sqlite3" in manifest["files"]:
                        db = sqlite3.connect("file:%s?mode=ro" % (target / "passkeys.sqlite3"), uri=True)
                        try:
                            live = db.execute("SELECT COUNT(*) FROM passkeys WHERE quarantined = 0 AND revoked IS NULL").fetchone()[0]
                        except sqlite3.Error:
                            live = None
                        finally:
                            db.close()
                        if live not in (0, None):
                            raise VaultError("drill_passkeys_were_not_quarantined")
                    result.update(ok=True, files=len(manifest["files"]), extras=sum(1 for n in blobs if n.startswith("extra/")))
            except (VaultError, backup.BackupError, OSError) as error:
                code = getattr(error, "code", None) or str(error) or type(error).__name__
                result["error"] = str(code)[:120]
            index["last_drill"] = result
            self._save(index)
            return result
        return self._guard(run)

    def tick(self):
        """Run what is due: the first backup at once, a missed one after any downtime, a weekly drill. Called hourly and at start."""
        index = self._index()
        now = int(self.clock())
        newest = max((i["verified_at"] or 0 for i in index["backups"].values()), default=0)
        done = {}
        if now - newest >= DUE_AFTER:
            last = index.get("last_attempt") or 0
            if not index.get("last_error") or now - last >= 3600:   # a failing backup is retried hourly, not in a tight loop
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
                               "present": n in present} for n, i in index["backups"].items()), key=lambda b: b["created"])
            verified = [b for b in backups if b["verified"] and b["present"]]
            problems = []
            if index.get("damaged"):
                problems.append("vault_index_damaged")
            if (present or index.get("key_id")) and not self.key_file.exists():
                problems.append("backup_key_missing")
            if not verified:
                problems.append("no_verified_backup")
            elif now - verified[-1]["created"] > OVERDUE_AFTER:
                problems.append("backup_overdue")
            if any(b["verified"] and not b["present"] for b in backups):
                problems.append("verified_backup_file_missing")
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
                    "newest_verified": verified[-1] if verified else None, "last_success": index.get("last_success"),
                    "last_error": index.get("last_error"), "last_drill": drill, "retention": self.retention,
                    "excluded_last_time": (index["backups"].get(verified[-1]["name"], {}).get("excluded") if verified else None),
                    "free_bytes": free, "encrypted": "AES-256-GCM"}
        except Exception as error:
            return {"side": self.side, "healthy": False, "problems": ["status_unreadable_" + type(error).__name__]}


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
