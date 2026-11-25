"""The Release Authority: builds a release from an exact source commit, and - only after the owner's one approval - signs and
publishes it. Part of the root installer; the AI side can only ASK it to prepare a release and later ask the owner to approve it.

What it keeps, all under the installer's private folder (root, mode 0700, unreachable by the owner-side service or any assistant):
  release/signing-ed25519.pem   the release signing key, generated HERE at the computer's console, never exported
  release/github-token          a GitHub token limited to the StyNpilot repository (entered once at the console)
  release/builds/<commit>/      the verified build of that commit: the .deb, its hash, the test report

Order of events (nothing is signed or published before the approval):
  prepare(commit, version): fetch that exact commit, build the package TWICE (different umask, different folder) and require the
      same SHA-256, run the whole test suite as an unprivileged account and require zero failures. Everything the owner will be
      shown (hash, size, test counts, commit) comes from this record, never from the assistant.
  [owner approves ONE request on the phone: it names the commit, version, hash, size and test result]
  publish(...): build the manifest from the approved record, sign it, upload the package, manifest and signature to the project's
      GitHub release for that tag (created at that exact commit). The installer then downloads it back through the normal
      signed-release path and upgrades, with health checks and automatic rollback.
"""
from __future__ import annotations

import collections
import fcntl
import hashlib
import json
import os
import re
import shlex
import selectors
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .. import release
from ..release import ReleaseError

API_HOST, UPLOAD_HOST = "api.github.com", "uploads.github.com"
CLONE_URL = "https://github.com/%s.git" % release.REPOSITORY
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_]{20,255}\Z")
_REVIEW = re.compile(r"[ -~]{0,200}\Z")
BUILD_TIMEOUT, TEST_TIMEOUT, GIT_TIMEOUT = 600, 1500, 300
MAX_ASSET = release.MAX_SIZE
RETAIN_BUILDS = 3
_LOCK_LINE = re.compile(r"([A-Za-z0-9_.\-]{1,80})==([A-Za-z0-9_.!+\-]{1,40}) [0-9a-f]{64}")
_VERSION_SCRIPT = ("import re;m=re.search(r'^__version__ = \"([^\"]+)\"', open('src/src/stynpilot/__init__.py').read(), re.M);"
                   "print(m.group(1) if m else '')")
# The tests need the vendored packages (e.g. mcp, which Ubuntu does not ship) exactly as the package carries them: unpack the wheels the
# lock file named (already hash-checked by the build) beside the source and put them on the path. No network, no install.
TEST_SCRIPT = ("mkdir -p vendor && for w in cache/*.whl; do /usr/bin/python3 -m zipfile -e \"$w\" vendor || exit 97; done && "
               "cd src && PYTHONPATH=src:../vendor exec /usr/bin/python3 -m pytest -q -p no:cacheprovider tests")
_ASSET_HOSTS = (".githubusercontent.com",)
_TESTS_LINE = re.compile(r"(?:(\d+) failed, )?(?:(\d+) passed)(?:, (\d+) skipped)?(?:, (\d+) (?:error|errors))?")


class AuthorityError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# The installer service runs in its OWN mount namespace (PrivateTmp, ProtectHome). A mount it makes there is invisible to the sandbox
# units systemd starts in the host namespace: on Dev19 try #4 the builds wrote into the plain folder under the tmpfs, and root, looking
# at its empty tmpfs, found no package (package_missing). The work area is therefore mounted and unmounted in the HOST namespace
# (it propagates into the installer's namespace), and before any build step root proves both sides see the same file system.
HOST_NS = ["/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--"]


def default_run(argv, timeout, cwd=None, env=None, keep=20000):
    """(returncode, the LAST ``keep`` bytes of combined output). No shell. Output is bounded while it is read (a runaway build cannot
    fill this process's memory); when time runs out, the whole process group is killed (124)."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, env=env,
                                start_new_session=True)
    except OSError:
        return 127, ""
    tail, size, timed_out = collections.deque(), 0, False
    deadline = time.monotonic() + timeout
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            timed_out = True
            break
        if sel.select(min(left, 1.0)):
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            tail.append(chunk)
            size += len(chunk)
            while size > keep and len(tail) > 1:
                size -= len(tail.popleft())
    code = None
    if not timed_out:
        # EOF on the pipe means every writer closed it, not that the command has reported its exit status: let it finish (bounded) BEFORE
        # the group is killed, or a command that succeeded could be recorded as killed.
        try:
            code = proc.wait(max(0.1, deadline - time.monotonic()))          # the WHOLE remaining time: a quiet command is not cut short
        except subprocess.TimeoutExpired:
            code, timed_out = None, True                              # it really ran out of time: report 124, not a kill status
    try:
        os.killpg(proc.pid, signal.SIGKILL)                   # nothing the command started may outlive it
    except OSError:
        pass
    sel.close()
    proc.stdout.close()
    if code is None:
        try:
            code = proc.wait(10)
        except subprocess.TimeoutExpired:
            code = 124
    return (124 if timed_out else code), b"".join(tail)[-keep:].decode("utf-8", "replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def default_http(method, url, headers, body, max_bytes=2_000_000, timeout=120):
    """(status, response bytes) over HTTPS to GitHub's own API hosts only. Redirects are never followed (the token must not travel)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in (API_HOST, UPLOAD_HOST) or parts.username or parts.port:
        raise AuthorityError("publish_address_not_allowed")
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as reply:
            return reply.status, reply.read(max_bytes)
    except urllib.error.HTTPError as err:
        if err.code in (301, 302, 303, 307) and method == "GET":
            return err.code, (err.headers.get("Location") or "").encode("ascii", "replace")    # the caller decides where it may go
        return err.code, err.read(max_bytes)
    except (urllib.error.URLError, OSError):
        raise AuthorityError("github_unreachable") from None


def default_fetch(url, max_bytes):
    """The file a GitHub asset redirect points at: HTTPS to GitHub's own storage hosts only, no credentials, no further redirects."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https" or parts.username or parts.port or not host.endswith(_ASSET_HOSTS):
        raise AuthorityError("asset_address_not_allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "stynpilot-release-authority"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=120) as reply:
            return reply.read(max_bytes)
    except (urllib.error.URLError, OSError):
        raise AuthorityError("asset_unreadable") from None


def _write_private(path, data, *, replace=False):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if not replace and path.exists():
        tmp.unlink()
        raise AuthorityError("already_exists")
    os.replace(tmp, path)


class Authority:
    def __init__(self, state_dir, *, run=default_run, http=default_http, clock=time.time, build_prefix=None, build_uid=None,
                 clone_url=CLONE_URL, repository=release.REPOSITORY, work_root=None, sandbox=None, mount_work=False,
                 tmpfs_mb=2048, inspect=None, fetch=None, host_ns=None):
        self.host_ns = list(HOST_NS if host_ns is None else host_ns)
        self.mountinfo = "/proc/self/mountinfo"
        self.root = Path(state_dir) / "release"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        (self.root / "builds").mkdir(exist_ok=True, mode=0o700)
        self.run, self.http, self.clock = run, http, clock
        self.build_prefix, self.build_uid = list(build_prefix or []), build_uid
        self.clone_url, self.repository = clone_url, repository
        # Where the unprivileged builder works. It must be reachable by the build account, so it cannot sit inside the installer's
        # private (0700) folder; root only ever READS results back out of it and re-hashes them.
        self.work_root = Path(work_root) if work_root else None
        # sandbox(job_id, argv, workspace, seconds=, memory_mb=, tasks=, network=) -> the full command that runs ``argv`` as the build
        # account inside the S3 sandbox; inspect(path, version) raises unless the upgrade path would accept the package.
        self.sandbox, self.mount_work, self.tmpfs_mb, self.inspect = sandbox, mount_work, tmpfs_mb, inspect
        self.fetch = fetch or default_fetch
        self.last_phase = None
        self.keyfile, self.tokenfile = self.root / "signing-ed25519.pem", self.root / "github-token"

    # -- console-provisioned secrets ------------------------------------------------------------------------------------
    def init_key(self):
        """Create the signing key if there is none (console only). Returns the public entry; the private half never leaves."""
        if not self.keyfile.exists():
            private = release.new_private_key()
            _write_private(self.keyfile, release.private_pem(private))
        return self.key_entry()

    def _private(self):
        try:
            return release.load_private_key(self.keyfile)
        except (OSError, ValueError):
            raise AuthorityError("signing_key_missing") from None

    def key_entry(self):
        return release.public_entry(self._private())

    def set_token(self, token):
        if type(token) is not str or not _TOKEN.fullmatch(token):
            raise AuthorityError("token_shape_invalid")
        _write_private(self.tokenfile, token.encode("ascii"), replace=True)

    def _token(self):
        try:
            token = self.tokenfile.read_text("ascii").strip()
        except OSError:
            raise AuthorityError("github_token_missing") from None
        if not _TOKEN.fullmatch(token):
            raise AuthorityError("github_token_unreadable")
        return token

    def _api(self, method, url, body=None, content_type="application/json", max_bytes=2_000_000, accept="application/vnd.github+json"):
        headers = {"Authorization": "Bearer " + self._token(), "Accept": accept,
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "stynpilot-release-authority"}
        data = body
        if body is not None:
            headers["Content-Type"] = content_type
            if type(body) is dict:
                data = json.dumps(body).encode()
                headers["Content-Type"] = "application/json"
        return self.http(method, url, headers, data, max_bytes)

    def check_token(self):
        """Can this token write releases to the StyNpilot repository (and report that it is only that one)? Returns a dict."""
        status, body = self._api("GET", "https://%s/repos/%s" % (API_HOST, self.repository))
        if status != 200:
            return {"ok": False, "why": "github_status_%d" % status}
        info = json.loads(body.decode())
        return {"ok": bool((info.get("permissions") or {}).get("push")), "why": "push_permission"}

    def ready(self):
        return {"key": self.keyfile.exists(), "token": self.tokenfile.exists(), "builder": bool(self.build_prefix or self.sandbox)}

    # -- build + verify, from an exact commit ----------------------------------------------------------------------------
    def _dir(self, commit):
        return self.root / "builds" / commit

    def _state(self, commit):
        try:
            return json.loads((self._dir(commit) / "record.json").read_text())
        except (OSError, ValueError):
            return None

    def _save(self, commit, record):
        d = self._dir(commit)
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        _write_private(d / "record.json", json.dumps(record, sort_keys=True).encode(), replace=True)

    def status(self, commit):
        if type(commit) is not str or not _HEX40.fullmatch(commit):
            raise AuthorityError("commit_invalid")
        rec = self._state(commit)
        if rec is None:
            return {"state": "not_started"}
        return {k: rec[k] for k in ("state", "version", "why", "sha256", "size", "tests_passed", "tests_failed", "tests_skipped",
                                    "reproducible", "commit", "started", "finished", "detail") if k in rec}

    def prepare_check(self, commit, version):
        """Refuse an unusable request up front (before any background work)."""
        if type(commit) is not str or not _HEX40.fullmatch(commit):
            raise AuthorityError("commit_invalid")
        try:
            release.tag_for_version(version)
        except ReleaseError:
            raise AuthorityError("version_invalid") from None
        if not self.build_prefix and not self.sandbox:
            raise AuthorityError("builder_not_configured")
        if not self.keyfile.exists() or not self.tokenfile.exists():
            raise AuthorityError("release_authority_not_provisioned")
        lock = self._take_lock()                              # one build at a time, machine-wide
        os.close(lock)

    def _take_lock(self):
        fd = os.open(self.root / "build.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise AuthorityError("another_build_is_running") from None
        return fd

    def prepare(self, commit, version, installed_version):
        """Build and verify (synchronous; the installer runs it in the background). Records the outcome; raises nothing for a
        failed build - the record says why. Only one build runs at a time and only the most recent few are kept."""
        self.prepare_check(commit, version)
        lock = self._take_lock()
        try:
            return self._prepare_locked(commit, version)
        finally:
            os.close(lock)

    def _prepare_locked(self, commit, version):
        d = self._dir(commit)
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, mode=0o700)
        record = {"state": "building", "commit": commit, "version": version, "started": self.clock()}
        self._save(commit, record)
        self.last_phase = None
        try:
            record.update(self._build(commit, version, d))
            record["state"] = "ready"
        except AuthorityError as failed:
            record.update(state="failed", why=failed.code)
            if self.last_phase and self.last_phase.get("code") != 0:
                record["detail"] = self.last_phase                  # the step that failed, its exit code and output tail
        except Exception as error:                       # a bug must never look like a good build
            record.update(state="failed", why="unexpected_%s" % type(error).__name__)
        record["finished"] = self.clock()
        self._save(commit, record)
        self._prune(keep=commit)
        return self.status(commit)

    def _prune(self, keep, limit=RETAIN_BUILDS):
        """Keep the newest few build folders (always including the one just made, and never one still being built)."""
        found = []
        for d in (self.root / "builds").iterdir():
            rec = self._state(d.name) if _HEX40.fullmatch(d.name) else None
            found.append((rec.get("finished", rec.get("started", 0)) if rec else 0, d.name))
        found.sort(reverse=True)
        for _, name in found[limit:]:
            if name != keep:
                shutil.rmtree(self.root / "builds" / name, ignore_errors=True)

    # -- the sandboxed builder -----------------------------------------------------------------------------------------
    def _phase(self, commit, name, argv, work, *, seconds, network=False, memory_mb=2048, tasks=256, env=None):
        """Run one step as the unprivileged build account inside the sandbox. Returns (exit code, output). A step that runs out
        of time is stopped together with everything it started; nothing it spawned survives."""
        result = self._phase_run(commit, name, argv, work, seconds, network, memory_mb, tasks, env)
        # What the owner (and the assistants) need to find a failure on a real machine: which step, its exit code, the end of its output.
        # The builder's output is untrusted DATA: printable ASCII only, short, and no secrets exist in the sandbox to leak.
        tail = re.sub(r"[^ -~\n]", "?", result[1][-3000:])
        self.last_phase = {"phase": name, "code": result[0], "tail": tail}
        return result

    def _phase_run(self, commit, name, argv, work, seconds, network, memory_mb, tasks, env):
        if self.sandbox:
            job = hashlib.sha256(("%s|%s|%r" % (commit, name, self.clock())).encode()).hexdigest()[:24]
            cmd = self.sandbox(job, argv, str(work), seconds=seconds, memory_mb=memory_mb, tasks=tasks, network=network)
            try:
                return self.run(cmd, seconds + 30, cwd=None, env=None)
            finally:
                self._stop_unit("stynpilot-job-" + job + ".service")                           # nothing may outlive the step
        base = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8", "GIT_TERMINAL_PROMPT": "0", "HOME": str(work)}
        return self.run(self.build_prefix + argv, seconds, cwd=str(work), env=dict(base, **(env or {})))

    def _stop_unit(self, name):
        """Stop the unit and VERIFY it is gone; a unit that will not stop fails the build rather than being ignored."""
        for _ in range(2):
            self.run(["systemctl", "stop", name], 30)
            code, state = self.run(["systemctl", "is-active", name], 30)
            if state.strip() in ("inactive", "failed") and code in (0, 3, 4):     # only an explicit answer counts; anything else = still unknown
                return
        raise AuthorityError("sandbox_did_not_stop")

    def _mount_work(self, work):
        """A size-limited, memory-backed work area owned by the build account: whatever the build writes can never fill the disk."""
        if not self.mount_work:
            return False
        code, _ = self.run(self.host_ns + ["/usr/bin/mount", "-t", "tmpfs", "-o", "size=%dm,uid=%d,gid=%d,mode=0700,nosuid,nodev" % (
            self.tmpfs_mb, self.build_uid or 0, self.build_uid or 0), "tmpfs", str(work)], 30)
        if code != 0:
            raise AuthorityError("work_area_unavailable")
        return True

    def _build(self, commit, version, d):
        work = (self.work_root / commit) if self.work_root else d / "work"
        if self.mount_work:
            self.run(self.host_ns + ["/usr/bin/umount", "-l", str(work)], 30)   # a work area left by a crashed build is released first
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, mode=0o700)
        if self.build_uid is not None and os.stat(work).st_uid != self.build_uid:
            os.chown(work, self.build_uid, -1)                    # only when it changes something (a no-op chown is refused in a sandbox)
            os.chmod(work, 0o700)
        mounted = False
        try:
            mounted = self._mount_work(work)
            if mounted:
                os.chmod(work, 0o700)
                self._prove_shared_work(commit, work)
            return self._build_in(commit, version, d, work)
        finally:
            if mounted:
                self.run(self.host_ns + ["/usr/bin/umount", "-l", str(work)], 30)
            shutil.rmtree(work, ignore_errors=True)

    def _prove_shared_work(self, commit, work):
        """Fail closed unless root's view of the work area is the tmpfs AND the sandbox sees the very same one: root writes a fresh
        random token there (exclusive, never through a link) and a sandbox step must read it back."""
        mine = [line.split() for line in open(self.mountinfo, encoding="utf-8", errors="replace")]
        here = [m for m in mine if len(m) > 4 and m[4] == str(work)]
        kinds = [m[m.index("-") + 1] for m in here if "-" in m]
        if not kinds or kinds[-1] != "tmpfs":
            raise AuthorityError("work_area_not_visible_to_root")
        token = secrets.token_hex(16)
        name = ".shared-" + token[:8]
        top = os.open(str(work), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=top)
            try:
                os.write(fd, token.encode())
                os.fchmod(fd, 0o644)
            finally:
                os.close(fd)
        finally:
            os.close(top)
        code, out = self._phase(commit, "shared", ["/usr/bin/cat", name], work, seconds=60)
        if code != 0 or out.strip() != token:
            raise AuthorityError("work_area_not_shared_with_the_sandbox")

    def _build_in(self, commit, version, d, work):
        git = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never",
               "-c", "protocol.https.allow=always", "-c", "advice.detachedHead=false"]
        ph = lambda name, argv, **kw: self._phase(commit, name, argv, work, **kw)
        steps = ((["/usr/bin/git", "init", "-q", "src"], False), (git + ["-C", "src", "remote", "add", "origin", self.clone_url], False),
                 (git + ["-C", "src", "fetch", "-q", "--depth", "1", "origin", commit], True),
                 (git + ["-C", "src", "checkout", "-q", "--detach", "FETCH_HEAD"], False))
        for n, (argv, net) in enumerate(steps):
            code, _ = ph("git%d" % n, argv, seconds=GIT_TIMEOUT, network=net, memory_mb=1024, tasks=64)
            if code != 0:
                raise AuthorityError("could_not_fetch_that_exact_commit")
        code, out = ph("head", git + ["-C", "src", "rev-parse", "HEAD"], seconds=30, memory_mb=256, tasks=16)
        if code != 0 or out.strip().splitlines()[-1:] != [commit]:
            raise AuthorityError("could_not_fetch_that_exact_commit")
        code, out = ph("version", ["/usr/bin/python3", "-I", "-c", _VERSION_SCRIPT], seconds=30, memory_mb=256, tasks=16)
        if code != 0 or out.strip().replace(".dev", "~dev") != version:
            raise AuthorityError("source_version_differs_from_requested_version")
        # The only step with network besides the fetch: download exactly the vendored wheels the lock file names (never code from
        # the commit). The build itself re-checks every wheel's SHA-256 against the lock.
        code, out = ph("lock", ["/usr/bin/cat", "src/packaging/vendor.lock"], seconds=30, memory_mb=256, tasks=16)
        if code != 0:
            raise AuthorityError("vendor_lock_unreadable")
        for line in out.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            m = _LOCK_LINE.fullmatch(line.strip())
            if not m:
                raise AuthorityError("vendor_lock_line_not_understood")
            code, _ = ph("wheel", ["/usr/bin/python3", "-m", "pip", "download", "--no-deps", "--only-binary=:all:", "--no-input",
                                   "--no-cache-dir", "-d", "cache", "%s==%s" % (m.group(1), m.group(2))],
                         seconds=BUILD_TIMEOUT, network=True, memory_mb=1024, tasks=64)
            if code != 0:
                raise AuthorityError("dependency_download_failed")
        for n, mask in enumerate(("022", "077")):
            script = ("umask %s && cd src && mkdir -p ../out%d && /usr/bin/python3 -c \"import sys;sys.path.insert(0,'tools');"
                      "import build_deb;print(build_deb.build('../out%d','../cache'))\"" % (mask, n, n))
            code, _ = ph("build%d" % n, ["/usr/bin/sh", "-c", script], seconds=BUILD_TIMEOUT)
            if code != 0:
                raise AuthorityError("build_failed")
        # Run the tests directly (no pipe: the exit status must be pytest's own).
        code, out = ph("tests", ["/usr/bin/sh", "-c", TEST_SCRIPT],
                       seconds=TEST_TIMEOUT)
        counts = self._count_tests(out)
        if counts is None:
            raise AuthorityError("test_result_unreadable")
        passed, failed, skipped = counts
        if failed or not passed:
            raise AuthorityError("tests_failed_%d_passed_%d" % (failed, passed))
        if code != 0:
            raise AuthorityError("tests_exit_status_%d" % code)
        datas = [self._read_artifact(work, "out%d" % n) for n in (0, 1)]       # root reads and hashes BOTH, itself
        hashes = [hashlib.sha256(x).hexdigest() for x in datas]
        if hashes[0] != hashes[1]:
            raise AuthorityError("build_is_not_reproducible")
        target = d / ("stynpilot_%s_all.deb" % version)
        _write_private(target, datas[0])
        self._inspect(target, version)
        return {"sha256": hashes[0], "size": len(datas[0]), "reproducible": True, "tests_passed": passed, "tests_failed": failed,
                "tests_skipped": skipped, "deb": target.name}

    def _inspect(self, path, version):
        if self.inspect is None:
            raise AuthorityError("package_inspection_not_configured")
        try:
            self.inspect(path, version)
        except AuthorityError:
            raise
        except Exception as refused:
            raise AuthorityError("package_not_acceptable_%s" % str(getattr(refused, "code", type(refused).__name__))[:60]) from None

    @staticmethod
    def _read_artifact(work, name):
        """The package a build left in ``work/name``, read by root WITHOUT trusting the builder's folder: every step is relative
        to an open directory handle and refuses links, exactly one .deb is allowed, and the size limit applies while reading."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            top = os.open(work, flags)
        except OSError:
            raise AuthorityError("package_missing") from None
        try:
            try:
                folder = os.open(name, flags, dir_fd=top)
            except OSError:
                raise AuthorityError("package_missing") from None
            try:
                debs = [n for n in os.listdir(folder) if n.endswith(".deb")]
                if len(debs) != 1:
                    raise AuthorityError("package_missing" if not debs else "more_than_one_package_built")
                try:
                    fd = os.open(debs[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=folder)
                except OSError:
                    raise AuthorityError("package_not_where_the_builder_should_have_put_it") from None
                try:
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET:
                        raise AuthorityError("package_not_where_the_builder_should_have_put_it")
                    chunks, total = [], 0
                    while True:
                        block = os.read(fd, 1 << 20)
                        if not block:
                            break
                        total += len(block)
                        if total > MAX_ASSET:
                            raise AuthorityError("package_too_large")
                        chunks.append(block)
                finally:
                    os.close(fd)
            finally:
                os.close(folder)
        finally:
            os.close(top)
        return b"".join(chunks)

    @staticmethod
    def _count_tests(text):
        for line in reversed(text.strip().splitlines()):
            m = _TESTS_LINE.search(line)
            if m and ("passed" in line):
                return int(m.group(2)), int(m.group(1) or 0) + int(m.group(4) or 0), int(m.group(3) or 0)
        return None

    # -- what the owner is asked to approve (from the verified record only) --------------------------------------------------
    def intent(self, commit, version, review_note="", from_min=""):
        """The exact, installer-derived intent for a verified build. Raises unless the build is ready and still matches.
        ``review_note`` is the assistant's own words and is shown to the owner labelled as UNVERIFIED."""
        rec = self._state(commit) if type(commit) is str and _HEX40.fullmatch(commit) else None
        if not rec or rec.get("state") != "ready" or rec.get("version") != version:
            raise AuthorityError("build_not_ready")
        if type(review_note) is not str or not _REVIEW.fullmatch(review_note):
            raise AuthorityError("review_note_invalid")
        data = self.package_bytes(commit, rec)
        if hashlib.sha256(data).hexdigest() != rec["sha256"] or len(data) != rec["size"]:
            raise AuthorityError("verified_package_was_altered")
        return {"commit": commit, "version": version, "sha256": rec["sha256"], "size": rec["size"],
                "tests_passed": rec["tests_passed"], "tests_failed": rec["tests_failed"], "tests_skipped": rec["tests_skipped"],
                "reproducible": True, "key_id": self.key_entry()["key_id"], "from_min": from_min,
                "review_note": review_note}

    def package_bytes(self, commit, rec=None):
        rec = rec or self._state(commit)
        if not rec or "deb" not in rec:
            raise AuthorityError("build_not_ready")
        path = self._dir(commit) / rec["deb"]
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise AuthorityError("verified_package_was_altered") from None
        try:
            return os.read(fd, MAX_ASSET + 1) if os.fstat(fd).st_size <= MAX_ASSET else b"x" * (MAX_ASSET + 1)
        finally:
            os.close(fd)

    def preflight(self, intent):
        """Everything that can be checked BEFORE the owner's approval is used up, without any external effect: the token still
        works, the verified package is intact and still acceptable to the upgrade path."""
        check = self.check_token()
        if not check.get("ok"):
            raise AuthorityError("github_token_not_usable_%s" % check.get("why", "unknown"))
        tagged = self.tag_commit(release.tag_for_version(intent["version"]))
        if tagged is not None and tagged != intent["commit"]:
            raise AuthorityError("tag_exists_for_a_different_commit")
        path = self._dir(intent["commit"]) / ("stynpilot_%s_all.deb" % intent["version"])
        self.intent(intent["commit"], intent["version"], intent.get("review_note", ""), intent["from_min"])
        self._inspect(path, intent["version"])

    # -- after approval ---------------------------------------------------------------------------------------------------
    def manifest_for(self, intent, notes):
        tag = release.tag_for_version(intent["version"])
        manifest = {"schema": release.SCHEMA, "package": release.PACKAGE, "version": intent["version"], "tag": tag,
                    "asset": "stynpilot-%s.deb" % tag, "sha256": intent["sha256"], "size": intent["size"],
                    "git_commit": intent["commit"], "from_min": intent["from_min"],
                    "created": datetime.fromtimestamp(self.clock(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "notes": list(notes)}
        release.validate_manifest(manifest)
        return manifest

    def sign(self, manifest):
        return release.sign(manifest, self._private())

    # -- publication, in separately repeatable steps (the installer records which one it reached) --------------------------
    def _base(self):
        return "https://%s/repos/%s" % (API_HOST, self.repository)

    def _json(self, status, body, ok=(200,)):
        if status not in ok:
            raise AuthorityError("github_status_%d" % status)
        try:
            return json.loads(body.decode())
        except ValueError:
            raise AuthorityError("github_reply_unreadable") from None

    def tag_commit(self, tag):
        """The commit the Git tag really points at (None when the tag does not exist)."""
        status, body = self._api("GET", "%s/git/ref/tags/%s" % (self._base(), urllib.parse.quote(tag)))
        if status == 404:
            return None
        obj = self._json(status, body)["object"]
        for _ in range(3):                                    # an annotated tag points at a tag object, which points at the commit
            if obj.get("type") == "commit":
                return obj["sha"]
            if obj.get("type") != "tag":
                raise AuthorityError("tag_points_at_something_unexpected")
            status, body = self._api("GET", "%s/git/tags/%s" % (self._base(), obj["sha"]))
            obj = self._json(status, body)["object"]
        raise AuthorityError("tag_points_at_something_unexpected")

    def _releases(self, tag):
        status, body = self._api("GET", "%s/releases?per_page=100" % self._base())
        return [r for r in self._json(status, body) if r.get("tag_name") == tag]

    @staticmethod
    def _marker(rid):
        return "stynpilot-release-transaction:%s" % rid

    def _owned(self, info, manifest, commit, rid):
        """Is this GitHub release the one THIS approved transaction made (its marker, tag and exact target commit)?"""
        if (self._marker(rid) not in (info.get("body") or "") or info.get("tag_name") != manifest["tag"]
                or info.get("target_commitish") != commit):
            raise AuthorityError("existing_release_not_owned_by_this_transaction")

    def draft(self, manifest, commit, rid):
        """Make (or find again) THIS transaction's DRAFT release for the tag. An unrelated release or draft with the same tag is never
        adopted or changed. Returns the release id."""
        tag = manifest["tag"]
        existing = self.tag_commit(tag)
        if existing is not None and existing != commit:
            raise AuthorityError("tag_exists_for_a_different_commit")
        found = self._releases(tag)
        if len(found) > 1:
            raise AuthorityError("more_than_one_release_for_that_tag")
        if found:
            self._owned(found[0], manifest, commit, rid)
            if not found[0].get("draft"):
                raise AuthorityError("release_is_already_public")
            return found[0]["id"]
        if existing is not None:
            raise AuthorityError("tag_exists_but_no_release_to_resume")
        status, body = self._api("POST", self._base() + "/releases", {
            "tag_name": tag, "target_commitish": commit, "name": tag, "draft": True, "prerelease": True,
            "body": "Built from commit %s and signed after owner approval.\n%s" % (commit, self._marker(rid))})
        return self._json(status, body, ok=(201,))["id"]

    def _assets(self, release_id):
        status, body = self._api("GET", "%s/releases/%d" % (self._base(), release_id))
        info = self._json(status, body)
        return info, {a["name"]: a for a in info.get("assets", [])}

    def _asset_bytes(self, asset):
        status, body = self._api("GET", "%s/releases/assets/%d" % (self._base(), asset["id"]), accept="application/octet-stream",
                                 max_bytes=MAX_ASSET + 1)
        if status in (301, 302, 303, 307):                    # the real file is served from GitHub's own storage hosts
            return self.fetch(body.decode("ascii", "replace"), MAX_ASSET + 1)
        if status != 200:
            raise AuthorityError("asset_unreadable_status_%d" % status)
        return body

    def _expected_files(self, manifest, signature, data):
        return {manifest["asset"]: data, "release-manifest.json": release.canonical(manifest),
                "release-manifest.json.sig": signature.encode("ascii")}

    def _kinds(self, manifest):
        return {manifest["asset"]: "application/octet-stream", "release-manifest.json": "application/json",
                "release-manifest.json.sig": "text/plain"}

    def upload_and_verify(self, release_id, manifest, signature, data, commit, rid):
        """Put the three files on the DRAFT and read each one back: it must match byte for byte (a same-named but different file
        is deleted and uploaded again; nothing else is touched)."""
        if len(data) != manifest["size"] or hashlib.sha256(data).hexdigest() != manifest["sha256"]:
            raise AuthorityError("package_bytes_differ_from_the_approved_package")
        want, kinds = self._expected_files(manifest, signature, data), self._kinds(manifest)
        info, have = self._assets(release_id)
        self._owned(info, manifest, commit, rid)
        if not info.get("draft"):
            raise AuthorityError("release_is_already_public")
        for name, content in want.items():
            asset = have.get(name)
            if asset is not None and self._matches(asset, content):
                continue
            if asset is not None:
                status, _ = self._api("DELETE", "%s/releases/assets/%d" % (self._base(), asset["id"]))
                if status != 204:
                    raise AuthorityError("could_not_replace_a_wrong_asset")
            url = "https://%s/repos/%s/releases/%d/assets?name=%s" % (UPLOAD_HOST, self.repository, release_id, urllib.parse.quote(name))
            status, _ = self._api("POST", url, content, content_type=kinds[name], max_bytes=200_000)
            if status != 201:
                raise AuthorityError("upload_failed_%s_status_%d" % (name[:30], status))
        self.verify_assets(release_id, manifest, signature, data)

    def _matches(self, asset, content):
        if asset.get("size") != len(content):
            return False
        return hashlib.sha256(self._asset_bytes(asset)).digest() == hashlib.sha256(content).digest()

    def verify_assets(self, release_id, manifest, signature, data):
        """All three files exist exactly once, with exactly the approved content."""
        info, have = self._assets(release_id)
        want = self._expected_files(manifest, signature, data)
        if set(have) != set(want) or len(info.get("assets", [])) != len(want):
            raise AuthorityError("release_assets_are_not_exactly_the_approved_three")
        for name, content in want.items():
            if not self._matches(have[name], content):
                raise AuthorityError("asset_content_differs_%s" % name[:30])
        return info

    def make_public(self, release_id, manifest, signature, data, commit, rid):
        """Publish the verified draft, then confirm the real Git tag points at the approved commit and the public assets still
        match. Repeating it on an already published identical release succeeds."""
        info, _ = self._assets(release_id)
        self._owned(info, manifest, commit, rid)
        if info.get("draft"):
            self.verify_assets(release_id, manifest, signature, data)
            status, body = self._api("PATCH", "%s/releases/%d" % (self._base(), release_id), {"draft": False, "prerelease": True})
            self._json(status, body)
        if self.tag_commit(manifest["tag"]) != commit:
            raise AuthorityError("published_tag_does_not_point_at_the_approved_commit")
        info = self.verify_assets(release_id, manifest, signature, data)
        if info.get("draft") or info.get("tag_name") != manifest["tag"]:
            raise AuthorityError("release_not_public_as_expected")
        return {"tag": manifest["tag"], "release_id": release_id}
