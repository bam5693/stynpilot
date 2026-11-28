"""Read-only transport for a broker-admitted full-history snapshot.

The broker supplies the exact admitted source, audited refs, and a dedicated
read credential. Run this worker in a private, size-limited transient unit.
"""
from __future__ import annotations

import base64
import ctypes
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import tempfile
import time

from . import repo_archive as archive

NETWORK_SECONDS = 120
MAX_REQUEST = 256 << 10
_USERNAME = {"github": "x-access-token", "gitlab": "oauth2"}
_REFSPECS = ("refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*")


def _git(repository, credential_fd, deadline, *args):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise archive.ArchiveError("archive_intake_timeout")
    command = [
        "/usr/bin/prlimit", f"--fsize={archive.MAX_BUNDLE}:{archive.MAX_BUNDLE}",
        "--core=0:0", "--as=1610612736:1610612736", "--", "/usr/bin/git",
        "--git-dir=" + str(repository), "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
        "-c", "http.followRedirects=false", "-c", "http.sslVerify=true", "-c", "credential.helper=",
        "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "-c", "pack.threads=2",
    ]
    fds = () if credential_fd is None else (credential_fd,)
    if fds:
        command.extend(("-c", f"include.path=/proc/self/fd/{credential_fd}"))
    try:
        with tempfile.TemporaryFile(dir=repository.parent) as output, subprocess.Popen(
            command + list(args), cwd=repository.parent, env=dict(archive._ENV, HOME=str(repository.parent)),
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, start_new_session=True, pass_fds=fds,
        ) as proc:
            try:
                status = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                raise archive.ArchiveError("archive_intake_timeout") from None
            if status:
                raise archive.ArchiveError("archive_intake_refused")
            output.seek(0)
            rows = output.read(archive.MAX_MANIFEST + 1)
    except OSError:
        raise archive.ArchiveError("archive_intake_refused") from None
    if len(rows) > archive.MAX_MANIFEST:
        raise archive.ArchiveError("archive_manifest_limit")
    return rows


@contextmanager
def _credential_config(provider, origin, credential):
    if credential is None:
        yield None
        return
    if type(credential) is not tuple or len(credential) != 2:
        raise archive.ArchiveError("archive_intake_credential_invalid")
    username, token = credential
    if (((provider in _USERNAME and username != _USERNAME[provider])
         or type(username) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", username))
            or type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_.~+\-/=]{16,1024}", token)):
        raise archive.ArchiveError("archive_intake_credential_invalid")
    header = base64.b64encode(f"{username}:{token}".encode("ascii")).decode("ascii")
    content = f'[http "{origin}"]\n\textraHeader = Authorization: Basic {header}\n'.encode("ascii")
    try:
        fd = os.memfd_create("stynpilot-repository-authorization", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except OSError:
        raise archive.ArchiveError("archive_intake_credentials_unavailable") from None
    try:
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(content)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW)
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError:
            raise archive.ArchiveError("archive_intake_credentials_unavailable") from None
        yield fd
    finally:
        os.close(fd)


def _check_head(rows, refs, expected):
    ref, oid = None, None
    for line in rows.splitlines():
        value, sep, name = line.partition(b"\t")
        if not sep or name != b"HEAD":
            raise archive.ArchiveError("archive_default_head_invalid")
        if value.startswith(b"ref: ") and ref is None:
            ref = value[5:]
        elif not value.startswith(b"ref: ") and oid is None:
            oid = value
        else:
            raise archive.ArchiveError("archive_default_head_invalid")
    if ref != expected.encode("utf-8") or oid != refs[expected].encode("ascii"):
        raise archive.ArchiveError("archive_default_head_changed")


def intake_snapshot(destination, admitted_source, requested_source, expected_refs, *, default_head, scratch,
                    credential=None):
    """Capture the exact admitted HTTPS source; request data cannot choose the origin."""
    source = archive.source_origin(*admitted_source)
    if archive.source_origin(*requested_source) != source:
        raise archive.ArchiveError("archive_intake_scope_mismatch")
    refs = archive._expected_map(expected_refs)
    if not archive._default_head(refs, default_head):
        raise archive.ArchiveError("archive_default_head_invalid")
    origin = source["url"]
    deadline = time.monotonic() + NETWORK_SECONDS
    with tempfile.TemporaryDirectory(prefix="stynpilot-intake-", dir=scratch) as tmp:
        folder = Path(tmp)
        bare = folder / "intake.git"
        archive._git(None, "init", "--bare", "--quiet", "--template=", str(bare))
        with _credential_config(source["provider"], origin, credential) as fd:
            def confirm_remote_refs():
                rows = _git(bare, fd, deadline, "ls-remote", "--refs", "--heads", "--tags", "--", origin)
                if archive._ref_map(rows.replace(b"\t", b" ")) != refs:
                    raise archive.ArchiveError("archive_refs_changed")
                rows = _git(bare, fd, deadline, "ls-remote", "--symref", "--", origin, "HEAD")
                _check_head(rows, refs, default_head)

            confirm_remote_refs()
            _git(bare, fd, deadline, "fetch", "--atomic", "--no-tags", "--no-recurse-submodules",
                 "--no-write-fetch-head", "--no-auto-maintenance", "--", origin, *_REFSPECS)
            confirm_remote_refs()
        return archive.capture_prepared(bare, destination, *admitted_source, refs, default_head=default_head)



def _private_worker():
    # Confirm protection before the worker, or any Git HTTPS child, can read a token.
    if (os.geteuid() == 0 or resource.getrlimit(resource.RLIMIT_CORE) != (0, 0)
            or Path("/proc/self/coredump_filter").read_text().strip() != "00000000"):
        raise archive.ArchiveError("archive_intake_worker_unprotected")
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    if prctl(4, 0, 0, 0, 0) != 0 or prctl(3, 0, 0, 0, 0) != 0:
        raise archive.ArchiveError("archive_intake_worker_unprotected")


def _worker_request(raw):
    if len(raw) > MAX_REQUEST:
        raise archive.ArchiveError("archive_intake_request_invalid")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise archive.ArchiveError("archive_intake_request_invalid") from None
    if (type(value) is not dict or set(value) != {"origin", "refs", "head", "credential"}
            or type(value["credential"]) is not list or len(value["credential"]) != 2
            or any(type(part) is not str for part in value["credential"])):
        raise archive.ArchiveError("archive_intake_request_invalid")
    origin = archive.source_origin("gitlab", value["origin"])["url"]
    refs = archive._expected_map(value["refs"])
    if not archive._default_head(refs, value["head"]):
        raise archive.ArchiveError("archive_default_head_invalid")
    return ("gitlab", origin), refs, value["head"], tuple(value["credential"])


def _send_capture(folder, output, receipt):
    raw = (folder / "manifest.json").read_bytes()
    if not 0 < len(raw) <= archive.MAX_MANIFEST:
        raise archive.ArchiveError("archive_manifest_limit")
    output.write(len(raw).to_bytes(4, "big") + raw)
    if archive._bundle_digest(folder / "source.bundle", copy_to=output) != (receipt["bundle_sha256"], receipt["bundle_size"]):
        raise archive.ArchiveError("archive_bundle_changed")
    output.flush()


def installed():
    """Read the broker request on stdin and emit only a verified archive frame."""
    try:
        _private_worker()
        source, refs, head, credential = _worker_request(sys.stdin.buffer.read(MAX_REQUEST + 1))
        with tempfile.TemporaryDirectory(prefix="stynpilot-private-repository-", dir="/tmp") as scratch:
            folder = Path(scratch) / "capture"
            receipt = intake_snapshot(folder, source, source, refs, default_head=head, scratch=scratch,
                                      credential=credential)
            _send_capture(folder, sys.stdout.buffer, receipt)
    except (OSError, archive.ArchiveError):
        return 1
    return 0
