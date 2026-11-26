"""Materialize one passkey-bindable source artifact in private executor scratch."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tarfile
from pathlib import Path

from .dev_lab_policy import LabError, SHA

MAX_ARCHIVE = 64 << 20
MAX_FILE = 16 << 20
MAX_ENTRIES = 8192
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def stage(archive, scratch, commit, digest):
    """Copy, verify, then unpack a Git tar into a new private job directory.

    The broker must supply the commit and digest from a trusted enrollment. The
    tar comment alone carries no authority. The candidate is data in this step.
    """
    if type(commit) is not str or not SHA.fullmatch(commit):
        raise LabError("lab_exact_commit_required")
    if type(digest) is not str or not SHA256.fullmatch(digest):
        raise LabError("lab_source_digest_required")
    scratch = Path(scratch)
    info = scratch.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise LabError("lab_scratch_not_private")
    with os.fdopen(os.open(archive, _OPEN), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE:
            raise LabError("lab_source_archive_invalid")
        # Freeze the bytes during the digest check. Reopening the input would
        # admit a different archive if it changed between verification and use.
        frozen = scratch / "source.tar"
        with frozen.open("xb") as copy:
            checksum = hashlib.sha256()
            total = 0
            while block := source.read(65536):
                total += len(block)
                if total > MAX_ARCHIVE:
                    raise LabError("lab_source_archive_invalid")
                checksum.update(block)
                copy.write(block)
        if total != info.st_size or checksum.hexdigest() != digest:
            raise LabError("lab_source_digest_mismatch")

    output = scratch / "src"
    output.mkdir(mode=0o700)
    files = set()
    with tarfile.open(frozen, "r:") as contents:
        for index, member in enumerate(contents):
            if index >= MAX_ENTRIES:
                raise LabError("lab_source_member_limit")
            if contents.pax_headers.get("comment") != commit:
                raise LabError("lab_source_commit_mismatch")
            name = member.name.split("/")
            if (any(part in ("", ".", "..", ".git") for part in name)
                    or len(member.name) > 1024 or len(name) > 24 or member.name in files
                    or member.type not in (tarfile.DIRTYPE, tarfile.REGTYPE)
                    or member.issparse() or not 0 <= member.size <= MAX_FILE
                    or (member.isdir() and member.size != 0)):
                raise LabError("lab_source_member_invalid")
            files.add(member.name)
            target = output.joinpath(*name)
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with contents.extractfile(member) as data, target.open("xb") as stream:
                shutil.copyfileobj(data, stream, length=65536)
            target.chmod(0o555 if member.mode & 0o111 else 0o444)
    if not files:
        raise LabError("lab_source_archive_invalid")
    frozen.unlink()
    return output
