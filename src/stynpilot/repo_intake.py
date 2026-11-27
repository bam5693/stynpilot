"""Read-only transport for a broker-admitted full-history snapshot.

The broker supplies the exact admitted source, audited refs, and a dedicated
read credential. Run this worker in a private, size-limited transient unit.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from . import repo_archive as archive

NETWORK_SECONDS = 120
_USERNAME = {"github": "x-access-token", "gitlab": "oauth2"}
_REFSPECS = ("refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*")


def _git(repository, config, deadline, *args):
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
    if config is not None:
        command.extend(("-c", "include.path=" + str(config)))
    try:
        with tempfile.TemporaryFile(dir=repository.parent) as output, subprocess.Popen(
            command + list(args), cwd=repository.parent, env=dict(archive._ENV, HOME=str(repository.parent)),
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL, start_new_session=True,
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


def _credential_config(folder, provider, origin, credential):
    if credential is None:
        return None
    if type(credential) is not tuple or len(credential) != 2:
        raise archive.ArchiveError("archive_intake_credential_invalid")
    username, token = credential
    if (((provider in _USERNAME and username != _USERNAME[provider])
         or type(username) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", username))
            or type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_.~+\-/=]{16,512}", token)):
        raise archive.ArchiveError("archive_intake_credential_invalid")
    header = base64.b64encode(f"{username}:{token}".encode("ascii")).decode("ascii")
    config = folder / "auth.conf"
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(f'[http "{origin}"]\n\textraHeader = Authorization: Basic {header}\n')
    return config


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
        config = _credential_config(folder, source["provider"], origin, credential)

        def confirm_remote_refs():
            rows = _git(bare, config, deadline, "ls-remote", "--refs", "--heads", "--tags", "--", origin)
            if archive._ref_map(rows.replace(b"\t", b" ")) != refs:
                raise archive.ArchiveError("archive_refs_changed")
            rows = _git(bare, config, deadline, "ls-remote", "--symref", "--", origin, "HEAD")
            _check_head(rows, refs, default_head)

        confirm_remote_refs()
        _git(bare, config, deadline, "fetch", "--atomic", "--no-tags", "--no-recurse-submodules",
             "--no-write-fetch-head", "--no-auto-maintenance", "--", origin, *_REFSPECS)
        confirm_remote_refs()
        if config is not None:
            config.unlink()
        return archive.capture_prepared(bare, destination, *admitted_source, refs, default_head=default_head)
