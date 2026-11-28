"""Owner-side, read-only archive access for approved AI clients."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading

from . import repo_archive as git, redact, safefs, vault

MAX_RETAINED = 4 << 30
MAX_ARCHIVES = 32
MAX_ENTRIES = 16384
MAX_PAGE = 100
MAX_FILE = 64 << 10
# Bundle, frozen bundle, and generated pack and index each have Git's per-file
# limit. Commit refs and receipts are bounded separately.
ADOPTION_RESERVATION = 5 * git.MAX_BUNDLE + 4 * git.MAX_MANIFEST
_ARCHIVE = re.compile(r"[a-f0-9]{32}\Z")
_REPOSITORY = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_PENDING = re.compile(r"\.pending-[a-z0-9_]{8}\Z")
_PROTECTED_LOCATIONS = tuple(tuple(path.lower().split("/")) for path in safefs.HOME_DENY) + ((".git",),)
_DECKPLAY_SOURCE = {"provider": "github", "url": "https://github.com/bam5693/Deckplay-hq.git"}


def _check_repository_access(value):
    if (type(value) is not dict or set(value) != {"repository", "authorization_profile"}
            or type(value["repository"]) is not str or not _REPOSITORY.fullmatch(value["repository"])
            or type(value["authorization_profile"]) is not str or not git.DIGEST.fullmatch(value["authorization_profile"])):
        raise git.ArchiveError("archive_binding_invalid")


def _private_dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise git.ArchiveError("archive_store_untrusted")


def _receipt(path):
    try:
        return _receipt_data(vault._read_private(path, git.MAX_MANIFEST))
    except (OSError, vault.VaultError):
        raise git.ArchiveError("archive_receipt_invalid") from None


def _receipt_data(raw):
    try:
        row = json.loads(raw)
        if type(row) is not dict or set(row) != {"format", "source", "refs", "bundle_sha256", "bundle_size", "default_head"}:
            raise ValueError
        src = row["source"]
        if (type(src) is not dict or set(src) != {"provider", "url"}
                or git.source_origin(src["provider"], src["url"]) != src or row["format"] != 2
                or type(row["bundle_sha256"]) is not str or not git.DIGEST.fullmatch(row["bundle_sha256"])
                or type(row["bundle_size"]) is not int or not 0 < row["bundle_size"] <= git.MAX_BUNDLE):
            raise ValueError
        refs = git._expected_map(row["refs"])
        if not git._default_head(refs, row["default_head"]):
            raise ValueError
        return row
    except (OSError, ValueError, vault.VaultError, git.ArchiveError):
        raise git.ArchiveError("archive_receipt_invalid") from None


def _size(root, remaining):
    def refused(error):
        raise git.ArchiveError("archive_store_untrusted") from error

    total, count = 0, 0
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=refused):
        for name in dirs + files:
            info = (Path(folder) / name).lstat()
            count += 1
            if ((not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode))
                    or info.st_uid != os.geteuid() or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
                raise git.ArchiveError("archive_store_untrusted")
            total += max(info.st_size, info.st_blocks * 512)
            if count > MAX_ENTRIES or total > remaining:
                raise git.ArchiveError("archive_store_capacity")
    return total


def _page(items, offset, limit):
    if type(offset) is not int or not 0 <= offset <= MAX_ENTRIES or type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise git.ArchiveError("archive_page_invalid")
    end = offset + limit
    return {"items": items[offset:end], "total": len(items), "next_offset": end if end < len(items) else None}


class Store:
    """The only writer is the owner adoption command. MCP can inspect grants only."""

    def __init__(self, path, *, private_read=None):
        self.private_read = private_read
        self.path = Path(path).absolute()
        self._slots = threading.BoundedSemaphore(2)
        self._private_checks = threading.local()

    @contextmanager
    def _locked(self, write=False):
        if not self.path.exists() and not write:
            yield False
            return
        _private_dir(self.path.parent)
        if write:
            self.path.mkdir(mode=0o700, exist_ok=True)
        _private_dir(self.path)
        flags = (os.O_RDWR if write else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(self.path / "store.lock", flags | (os.O_CREAT if write else 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077):
                raise git.ArchiveError("archive_store_untrusted")
            try:
                fcntl.flock(fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            except BlockingIOError:
                raise git.ArchiveError("archive_store_busy") from None
            if not write:
                self._inventory()
                _size(self.path, MAX_RETAINED)
            yield True
        finally:
            os.close(fd)

    def _recover(self):
        # Only one writer holds this lock. A fresh name prevents an old child
        # from opening paths in a replacement transaction after a crash.
        for path in self.path.iterdir():
            if _PENDING.fullmatch(path.name):
                _private_dir(path)
                shutil.rmtree(path)
                vault._fsync_dir(self.path)

    def reconcile(self):
        # Provision the empty owner-private mount before a first broker capture.
        with self._locked(write=True):
            self._recover()
            self._inventory()
            _size(self.path, MAX_RETAINED)

    def _inventory(self):
        rows = []
        for entry in self.path.iterdir():
            if entry.name == "store.lock":
                continue
            if _PENDING.fullmatch(entry.name):
                raise git.ArchiveError("archive_recovery_required")
            if not _ARCHIVE.fullmatch(entry.name) or len(rows) >= MAX_ARCHIVES:
                raise git.ArchiveError("archive_store_capacity")
            _private_dir(entry)
            rows.append(entry)
        return sorted(rows)

    def adopt(self, source, *, manifest_sha256, bundle_sha256, clients):
        source = Path(source)
        _private_dir(source)
        raw = vault._read_private(source / "manifest.json", git.MAX_MANIFEST)
        return self._adopt(raw, manifest_sha256, bundle_sha256, clients,
                           lambda output, size: git._bundle_digest(source / "source.bundle", copy_to=output))

    def adopt_stream(self, stream, *, manifest_sha256, bundle_sha256, client, before_publish=None, repository_access=None):
        """Adopt a verified capture from the broker without passing paths or credentials."""
        header = stream.read(4)
        length = int.from_bytes(header, "big")
        if len(header) != 4 or not 0 < length <= git.MAX_MANIFEST:
            raise git.ArchiveError("archive_manifest_limit")
        raw = stream.read(length)
        if len(raw) != length:
            raise git.ArchiveError("archive_manifest_invalid")
        return self._adopt(raw, manifest_sha256, bundle_sha256, [client],
                           lambda output, size: git._hash_bundle_stream(stream, copy_to=output, limit=size),
                           before_publish=before_publish, repository_access=repository_access)

    def _adopt(self, raw, manifest_sha256, bundle_sha256, clients, receive_bundle, *, before_publish=None, repository_access=None):
        if (type(clients) is not list or not 1 <= len(clients) <= 8
                or any(type(c) is not str or not _CLIENT.fullmatch(c) for c in clients)
                or len(set(clients)) != len(clients)):
            raise git.ArchiveError("archive_client_grant_invalid")
        if repository_access is not None:
            _check_repository_access(repository_access)
        for digest in (manifest_sha256, bundle_sha256):
            if type(digest) is not str or not git.DIGEST.fullmatch(digest):
                raise git.ArchiveError("archive_binding_invalid")
        if hashlib.sha256(raw).hexdigest() != manifest_sha256:
            raise git.ArchiveError("archive_binding_invalid")
        archive_id = manifest_sha256[:32]
        with self._locked(write=True):
            self._recover()
            inventory = self._inventory()
            dest = self.path / archive_id
            if os.path.lexists(dest):
                raise git.ArchiveError("archive_already_adopted")
            retained = _size(self.path, MAX_RETAINED)
            if len(inventory) >= MAX_ARCHIVES or retained + ADOPTION_RESERVATION > MAX_RETAINED:
                raise git.ArchiveError("archive_store_capacity")
            pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.path))
            try:
                archive = pending / "archive"
                archive.mkdir(mode=0o700)
                vault._write_atomic(archive, "manifest.json", raw)
                receipt = _receipt(archive / "manifest.json")
                bundle = archive / "source.bundle"
                fd = os.open(bundle, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    digest, size = receive_bundle(stream, receipt["bundle_size"])
                    stream.flush()
                    os.fsync(stream.fileno())
                if digest != bundle_sha256 or (digest, size) != (receipt["bundle_sha256"], receipt["bundle_size"]):
                    raise git.ArchiveError("archive_bundle_digest_mismatch")
                _restore(pending, receipt)
                grant = {"manifest_sha256": manifest_sha256}
                if repository_access is not None:
                    # Older builds ignore unknown fields and rely on clients.
                    # Omit that key so private archives stay hidden on rollback.
                    grant.update(private_client=clients[0], repository_access=repository_access)
                else:
                    grant["clients"] = sorted(clients)
                vault._write_atomic(pending, "grant.json", json.dumps(grant).encode())
                _size(self.path, MAX_RETAINED)
                _sync_tree(pending)
                if before_publish is not None:
                    before_publish()
                git._publish_directory(pending, dest)
            finally:
                if pending.exists():
                    self._recover()
            return {"archive_id": archive_id, **_public(receipt)}

    def inspect(self, method, client, *args):
        if not self._slots.acquire(blocking=False):
            raise git.ArchiveError("archive_store_busy")
        try:
            self._private_checks.scopes = []
            result = method(client, *args)
            if any(not self.private_read(client, access, source) for access, source in self._private_checks.scopes):
                raise git.ArchiveError("archive_read_authorization_changed")
            return result
        finally:
            del self._private_checks.scopes
            self._slots.release()

    def _visible(self, entry, client):
        row = json.loads(vault._read_private(entry / "grant.json", 4096))
        if type(row) is not dict:
            return None
        if "repository_access" in row:
            if set(row) != {"repository_access", "private_client", "manifest_sha256"} or row["private_client"] != client:
                return None
        elif type(row.get("clients")) is not list or client not in row["clients"]:
            return None
        manifest = entry / "archive" / "manifest.json"
        raw = vault._read_private(manifest, git.MAX_MANIFEST)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row.get("manifest_sha256") or digest[:32] != entry.name:
            raise git.ArchiveError("archive_binding_invalid")
        receipt = _receipt_data(raw)
        if "repository_access" in row:
            access = row["repository_access"]
            _check_repository_access(access)
            if self.private_read is None or not self.private_read(client, access, receipt["source"]):
                return None
            if hasattr(self._private_checks, "scopes"):
                self._private_checks.scopes.append((access, receipt["source"]))
        return receipt

    def list(self, client):
        with self._locked() as ready:
            if not ready:
                return {"archives": []}
            return {"archives": [{"archive_id": entry.name, **_public(row)} for entry in self._inventory()
                                 if (row := self._visible(entry, client)) is not None]}

    def _lookup(self, archive_id, client):
        if type(archive_id) is not str or not _ARCHIVE.fullmatch(archive_id):
            raise git.ArchiveError("archive_not_found")
        entry = self.path / archive_id
        try:
            _private_dir(entry)
            receipt = self._visible(entry, client)
        except FileNotFoundError:
            receipt = None
        if receipt is None:
            raise git.ArchiveError("archive_not_found")
        bare = entry / "comparison.git"
        _private_dir(bare)
        if os.path.lexists(bare / "objects/info/alternates") or os.path.lexists(bare / "shallow"):
            raise git.ArchiveError("archive_store_untrusted")
        return bare, receipt

    def _deckplay_checkout_binding(self, client, archive_id, ref, commit):
        # Caller holds the store lock. Never accept a path or origin from MCP.
        bare, receipt = self._lookup(archive_id, client)
        if receipt["source"] != _DECKPLAY_SOURCE:
            raise git.ArchiveError("archive_checkout_source_mismatch")
        if (type(ref) is not str or not ref.startswith("refs/heads/")
                or type(commit) is not str or not git.OID.fullmatch(commit)
                or receipt["refs"].get(ref) != commit):
            raise git.ArchiveError("archive_checkout_ref_mismatch")
        bundle = self.path / archive_id / "archive" / "source.bundle"
        if git._bundle_digest(bundle) != (receipt["bundle_sha256"], receipt["bundle_size"]):
            raise git.ArchiveError("archive_bundle_digest_mismatch")
        if git._git(bare, "show-ref", "--verify", "--hash", ref, timeout=8).strip() != commit.encode("ascii"):
            raise git.ArchiveError("archive_checkout_ref_mismatch")
        return bare, receipt

    def deckplay_checkout_preview(self, client, archive_id, ref, commit):
        """Metadata-only preflight for a future separately authorized checkout.

        This does not grant checkout permission, expose historical objects, or
        write to a workspace. A full import must additionally enforce workspace
        enrollment, owner approval and content/history isolation.
        """
        with self._locked():
            bare, receipt = self._deckplay_checkout_binding(client, archive_id, ref, commit)
            tree = _tree(bare, commit)
            return {"archive_id": archive_id, "source": dict(receipt["source"]),
                    "workspace": "deckplay-hq", "ref": ref, "commit": commit,
                    "bundle_sha256": receipt["bundle_sha256"],
                    "bundle_size": receipt["bundle_size"], "entry_count": len(tree),
                    "protected_path_count": sum(not _safe_path(name) for name in tree),
                    "nonregular_entry_count": sum(row["mode"] not in ("100644", "100755")
                                                  or row["type"] != "blob" for row in tree.values()),
                    "checkout_authorized": False, "requires_content_review": True}

    @contextmanager
    def _deckplay_transfer_bundle(self, client, archive_id, ref, commit):
        """Stage a self-contained single-tip bundle, internally, without networking.

        Not an MCP operation. A future approval-bound consumer must separately
        authorize materialization and historical-content access. Never return
        this path or bytes in an assistant-visible response.
        """
        with self._locked():
            bare, receipt = self._deckplay_checkout_binding(client, archive_id, ref, commit)
            with tempfile.TemporaryDirectory(prefix="stynpilot-deckplay-transfer-") as scratch:
                bundle = Path(scratch) / "checkout.bundle"
                git._git(bare, "bundle", "create", str(bundle), ref)
                digest, size = git._bundle_digest(bundle)
                # Verify without consulting the original object store.
                git._verify_bundle(bundle, {ref: commit})
                yield bundle, {"archive_id": archive_id, "source": dict(receipt["source"]),
                               "ref": ref, "commit": commit, "bundle_sha256": digest,
                               "bundle_size": size, "source_bundle_sha256": receipt["bundle_sha256"]}

    def refs(self, client, archive_id, offset=0, limit=50):
        with self._locked():
            _, receipt = self._lookup(archive_id, client)
            return _page([{"ref": name, "object": oid} for name, oid in sorted(receipt["refs"].items())], offset, limit)

    def tree(self, client, archive_id, commit, offset=0, limit=50):
        with self._locked():
            bare, _ = self._lookup(archive_id, client)
            return _page([{"path": path, **item} for path, item in _tree(bare, commit).items() if _safe_path(path)],
                         offset, limit)

    def history(self, client, archive_id, commit, offset=0, limit=50):
        _page([], offset, limit)
        with self._locked():
            bare, _ = self._lookup(archive_id, client)
            _commit(bare, commit)
            raw = git._git(bare, "rev-list", "--topo-order", "--parents", f"--skip={offset}",
                           f"--max-count={limit + 1}", commit, timeout=8)
            rows = [line.split() for line in raw.decode("ascii").splitlines()]
            return {"items": [{"commit": row[0], "parents": row[1:]} for row in rows[:limit]],
                    "next_offset": offset + limit if len(rows) > limit and offset + limit <= MAX_ENTRIES else None}

    def file(self, client, archive_id, commit, path):
        with self._locked():
            _path(path)
            bare, _ = self._lookup(archive_id, client)
            if not _safe_path(path):
                raise git.ArchiveError("archive_protected_path")
            _commit(bare, commit)
            spec = commit + ":" + path
            if git._git(bare, "cat-file", "-t", spec, timeout=8).strip() != b"blob":
                raise git.ArchiveError("archive_blob_required")
            size = int(git._git(bare, "cat-file", "-s", spec, timeout=8))
            if size > MAX_FILE:
                raise git.ArchiveError("archive_file_too_large")
            try:
                text = git._git(bare, "cat-file", "blob", spec, timeout=8).decode("utf-8")
            except UnicodeDecodeError:
                raise git.ArchiveError("archive_file_not_text") from None
            if "\0" in text:
                raise git.ArchiveError("archive_file_not_text")
            clean, found = redact.redact(text)
            if redact.mostly_secret(len(text), clean, found):
                raise git.ArchiveError("archive_file_is_mostly_secret")
            if len(clean.encode("utf-8")) > MAX_FILE:
                raise git.ArchiveError("archive_file_too_large")
            return {"path": path, "size": size, "text": clean, "redacted": found}

    def compare(self, client, left_id, left_commit, right_id, right_commit, offset=0, limit=50):
        with self._locked():
            left, _ = self._lookup(left_id, client)
            right, _ = self._lookup(right_id, client)
            before, after = _tree(left, left_commit), _tree(right, right_commit)
            return _page([{"path": name, "before": before.get(name), "after": after.get(name)}
                          for name in sorted(before.keys() | after.keys())
                          if before.get(name) != after.get(name) and _safe_path(name)],
                         offset, limit)


def _sync_tree(path):
    for folder, _, names in os.walk(path, topdown=False):
        for name in names:
            vault._fsync_file(Path(folder) / name)
        vault._fsync_dir(folder)


def _restore(pending, receipt):
    source = receipt["source"]
    git.restore_comparison(pending / "archive", pending / "comparison.git", source["provider"], source["url"],
                           receipt["refs"], receipt["bundle_sha256"], default_head=receipt["default_head"])


def _public(row):
    return {"source": row["source"], "default_head": row["default_head"], "ref_count": len(row["refs"]),
            "bundle_sha256": row["bundle_sha256"], "bundle_size": row["bundle_size"]}


def _commit(bare, commit):
    if type(commit) is not str or not git.OID.fullmatch(commit) or git._git(bare, "cat-file", "-t", commit, timeout=8).strip() != b"commit":
        raise git.ArchiveError("archive_commit_invalid")


def _path(path):
    if (type(path) is not str or not 0 < len(path) <= 1024 or any(ord(c) < 32 for c in path)
            or any(p in {"", ".", ".."} for p in path.split("/"))):
        raise git.ArchiveError("archive_path_invalid")


def _unprotected_path(path):
    try:
        _path(path)
        parts = tuple(path.lower().split("/"))
        for part in parts:
            safefs.Policy.name_ok(part)
    except (git.ArchiveError, safefs.FileDenied):
        return False
    if any(parts[start:start + len(location)] == location
           for start in range(len(parts)) for location in _PROTECTED_LOCATIONS):
        return False
    return True


def _safe_path(path):
    return _unprotected_path(path) and not redact.redact(path)[1]


def _tree(bare, commit):
    _commit(bare, commit)
    rows = git._git(bare, "ls-tree", "-rz", "--full-tree", commit, timeout=8).removesuffix(b"\0")
    tree = {}
    for line in rows.split(b"\0") if rows else ():
        ident, path = line.split(b"\t", 1)
        mode, kind, oid = ident.decode("ascii").split()
        name = path.decode("utf-8", "strict")
        tree[name] = {"mode": mode, "type": kind, "object": oid}
        if len(tree) > MAX_ENTRIES:
            raise git.ArchiveError("archive_tree_limit")
    return tree
