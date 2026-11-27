"""Preserve and verify full branch and tag bundles in isolated bare repositories."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

from . import repo_git, vault

MAX_BUNDLE = 512 << 20
MAX_MANIFEST = 4 << 20
MAX_REFS = 10000
PROVIDERS = {"github": "github.com", "gitlab": "gitlab.com", "forgejo": None}
OID = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_REPOSITORY_PATH = re.compile(r"/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*/)+[A-Za-z0-9_-][A-Za-z0-9_.-]*\.git\Z")
_ENV = dict(repo_git._ENV, GIT_PROTOCOL_FROM_USER="0", GIT_CONFIG_COUNT="0")
_RENAME_NOREPLACE = 1  # Linux renameat2 flag


class ArchiveError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def source_origin(provider, origin):
    """Validate a provenance value; origin is never used for networking here."""
    if type(provider) is not str or provider not in PROVIDERS or type(origin) is not str or len(origin) > 512:
        raise ArchiveError("archive_origin_invalid")
    try:
        parsed = urlsplit(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ArchiveError("archive_origin_invalid") from None
    if (parsed.scheme != "https" or not hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", hostname)
            or parsed.netloc != hostname + (f":{port}" if port is not None else "")
            or origin != "https://" + parsed.netloc + parsed.path
            or not _REPOSITORY_PATH.fullmatch(parsed.path)
            or (PROVIDERS[provider] and (hostname != PROVIDERS[provider] or port is not None))):
        raise ArchiveError("archive_origin_invalid")
    return {"provider": provider, "url": origin}


def _git(repository, *argv, timeout=120):
    command = [
        "/usr/bin/prlimit", f"--fsize={MAX_BUNDLE}:{MAX_BUNDLE}", "--as=1610612736:1610612736",
        "--", "/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
        "-c", "protocol.allow=never", "-c", "submodule.recurse=false", "-c", "pack.threads=2",
    ]
    if repository is not None:
        command.append("--git-dir=" + str(repository))
    try:
        with tempfile.TemporaryFile() as output:
            subprocess.run(command + list(argv), env=_ENV, stdin=subprocess.DEVNULL,
                           stdout=output, stderr=subprocess.DEVNULL, cwd='/', timeout=timeout, check=True)
            output.seek(0)
            result = output.read(MAX_MANIFEST + 1)
    except (OSError, subprocess.SubprocessError):
        raise ArchiveError("archive_git_refused") from None
    if len(result) > MAX_MANIFEST:
        raise ArchiveError("archive_manifest_limit")
    return result


def _ref_name(name):
    # Git ref rules for full branch and tag names, including Unicode refs.
    if not (name.startswith("refs/heads/") or name.startswith("refs/tags/")) or len(name) > 1024:
        return False
    if any(ord(c) < 33 or ord(c) in (92, 127) or c in "~^:?*[" for c in name):
        return False
    if ".." in name or "@{" in name or name.endswith("."):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in name.split("/"))


def _ref_map(rows, *, name_first=False):
    refs = {}
    try:
        lines = rows.decode("utf-8").removesuffix("\n").split("\n") if rows else []
    except UnicodeDecodeError:
        raise ArchiveError("archive_refs_invalid") from None
    for line in lines:
        first, sep, second = line.partition(" ")
        name, oid = (first, second) if name_first else (second, first)
        if (not sep or not _ref_name(name)
                or not OID.fullmatch(oid) or oid == "0" * 40 or name in refs or len(refs) >= MAX_REFS):
            raise ArchiveError("archive_refs_invalid")
        refs[name] = oid
    if not refs:
        raise ArchiveError("archive_refs_empty")
    return refs


def _expected_map(value):
    if type(value) is not dict or not 0 < len(value) <= MAX_REFS:
        raise ArchiveError("archive_refs_invalid")
    if any(type(k) is not str or type(v) is not str or len(k) > 1024 for k, v in value.items()):
        raise ArchiveError("archive_refs_invalid")
    encoded = "\n".join(f"{name} {oid}" for name, oid in value.items()).encode("utf-8")
    if len(encoded) > MAX_MANIFEST:
        raise ArchiveError("archive_manifest_limit")
    if _ref_map(encoded, name_first=True) != value:
        raise ArchiveError("archive_refs_invalid")
    return dict(sorted(value.items()))


def _bundle_digest(path, *, copy_to=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BUNDLE:
            raise ArchiveError("archive_bundle_limit")
        digest, total = hashlib.sha256(), 0
        while chunk := source.read(1 << 20):
            total += len(chunk)
            if total > MAX_BUNDLE:
                raise ArchiveError("archive_bundle_limit")
            digest.update(chunk)
            if copy_to is not None:
                copy_to.write(chunk)
        if total != info.st_size:
            raise ArchiveError("archive_bundle_changed")
        return digest.hexdigest(), total


def _restore_bundle(bundle, bare, refs, default_head=None):
    if _ref_map(_git(None, "bundle", "list-heads", str(bundle))) != refs:
        raise ArchiveError("archive_refs_changed")
    # An empty verifier has no objects to satisfy a thin/incremental bundle.
    # Unbundle and walk the full object graph without creating a working tree.
    _git(None, "init", "--quiet", "--bare", "--template=", str(bare))
    _git(bare, "bundle", "verify", str(bundle))
    _git(bare, "bundle", "unbundle", str(bundle))
    with (bare / "packed-refs").open("x", encoding="utf-8") as packed:
        for name, oid in refs.items():
            packed.write(f"{oid} {name}\n")
    if default_head is not None:
        (bare / "HEAD").write_text(f"ref: {default_head}\n", encoding="utf-8")
    _git(bare, "fsck", "--full", "--strict", "--no-dangling")


def _verify_bundle(bundle, refs):
    with tempfile.TemporaryDirectory(prefix="stynpilot-archive-verify-", dir=bundle.parent) as scratch:
        _restore_bundle(bundle, Path(scratch) / "verify.git", refs)


def _publish_directory(staging, destination):
    """Atomically commit a complete archive and fail if the destination exists."""
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = os.open(destination.parent, flags)
    try:
        if rename(parent_fd, os.fsencode(staging.name), parent_fd, os.fsencode(destination.name), _RENAME_NOREPLACE):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), destination)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _default_head(refs, value):
    if value is not None and (type(value) is not str or value not in refs or not value.startswith("refs/heads/")):
        raise ArchiveError("archive_default_head_invalid")
    return {"default_head": value} if value is not None else {}


def restore_comparison(archive, destination, provider, origin, expected_refs, expected_digest, *, default_head=None):
    """Restore a separate bare comparison repository, with no checkout or merge.

    The expected identity, digest and branch/tag tips are trusted inputs from
    the archive receipt. The manifest beside the bundle cannot authorize itself.
    """
    source, refs = source_origin(provider, origin), _expected_map(expected_refs)
    head = _default_head(refs, default_head)
    if type(expected_digest) is not str or not DIGEST.fullmatch(expected_digest):
        raise ArchiveError("archive_binding_invalid")
    archive, destination = Path(archive), Path(destination).absolute()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        with os.fdopen(os.open(archive / "manifest.json", flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ArchiveError("archive_manifest_invalid")
            raw = stream.read(MAX_MANIFEST + 1)
    except OSError:
        raise ArchiveError("archive_manifest_invalid") from None
    try:
        manifest = json.loads(raw) if len(raw) <= MAX_MANIFEST else None
    except (ValueError, UnicodeError):
        raise ArchiveError("archive_manifest_invalid") from None
    fields = {"format", "source", "refs", "bundle_sha256", "bundle_size"} | head.keys()
    if (type(manifest) is not dict or set(manifest) != fields
            or manifest["format"] != (2 if head else 1) or manifest["source"] != source or manifest["refs"] != refs
            or manifest.get("default_head") != default_head
            or manifest["bundle_sha256"] != expected_digest
            or type(manifest["bundle_size"]) is not int or not 0 < manifest["bundle_size"] <= MAX_BUNDLE):
        raise ArchiveError("archive_binding_invalid")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        with tempfile.TemporaryDirectory(prefix="stynpilot-archive-import-", dir=destination.parent) as scratch:
            frozen = Path(scratch) / "frozen.bundle"
            with frozen.open("xb") as copy:
                digest, size = _bundle_digest(archive / "source.bundle", copy_to=copy)
            if (digest, size) != (expected_digest, manifest["bundle_size"]):
                raise ArchiveError("archive_bundle_digest_mismatch")
            _restore_bundle(frozen, destination, refs, default_head)
        return manifest
    except Exception:
        shutil.rmtree(destination)
        raise


def capture_prepared(bare, destination, provider, origin, expected_refs, *, default_head=None):
    """Archive a clean, private bare intake repository against pinned source refs.

    The caller owns preparation and network authorization. It must give this
    function exclusive access to the prepared repository and archive directory.
    """
    source, refs = source_origin(provider, origin), _expected_map(expected_refs)
    head = _default_head(refs, default_head)
    bare, destination = Path(bare).resolve(strict=True), Path(destination).absolute()
    if _git(bare, "rev-parse", "--is-bare-repository", "--is-shallow-repository").splitlines() != [b"true", b"false"]:
        raise ArchiveError("archive_full_bare_repo_required")
    if _git(bare, "for-each-ref", "--format=%(symref)", "refs/heads", "refs/tags").strip():
        raise ArchiveError("archive_symbolic_ref")
    advertised = _ref_map(_git(bare, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags"))
    if advertised != refs:
        raise ArchiveError("archive_refs_changed")

    if os.path.lexists(destination):
        raise FileExistsError(destination)
    staging = Path(tempfile.mkdtemp(prefix=".stynpilot-archive-", dir=destination.parent))
    try:
        bundle = staging / "source.bundle"
        _git(bare, "bundle", "create", str(bundle), "--branches", "--tags")
        bundle.chmod(0o600)
        digest, size = _bundle_digest(bundle)
        _verify_bundle(bundle, refs)
        manifest = {"format": 2 if head else 1, "source": source, "refs": refs,
                    "bundle_sha256": digest, "bundle_size": size, **head}
        raw = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if len(raw) > MAX_MANIFEST:
            raise ArchiveError("archive_manifest_limit")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        with os.fdopen(os.open(staging / "manifest.json", flags, 0o600), "wb") as metadata:
            metadata.write(raw)
            metadata.flush()
            os.fsync(metadata.fileno())
        vault._fsync_file(bundle)
        vault._fsync_dir(staging)
        _publish_directory(staging, destination)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)
