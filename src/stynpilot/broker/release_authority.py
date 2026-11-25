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

import hashlib
import json
import os
import re
import shlex
import shutil
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
_TESTS_LINE = re.compile(r"(?:(\d+) failed, )?(?:(\d+) passed)(?:, (\d+) skipped)?(?:, (\d+) (?:error|errors))?")


class AuthorityError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def default_run(argv, timeout, cwd=None, env=None):
    """(returncode, combined output). No shell, bounded time and output."""
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd, env=env, check=False,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return done.returncode, (done.stdout + done.stderr)[-20000:].decode("utf-8", "replace")


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
        return err.code, err.read(max_bytes)
    except (urllib.error.URLError, OSError):
        raise AuthorityError("github_unreachable") from None


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
                 clone_url=CLONE_URL, repository=release.REPOSITORY, work_root=None):
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

    def _api(self, method, url, body=None, content_type="application/json", max_bytes=2_000_000):
        headers = {"Authorization": "Bearer " + self._token(), "Accept": "application/vnd.github+json",
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
        return {"key": self.keyfile.exists(), "token": self.tokenfile.exists(), "builder": bool(self.build_prefix)}

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
                                    "reproducible", "commit", "started", "finished") if k in rec}

    def _as_builder(self, argv):
        return self.build_prefix + argv

    def prepare_check(self, commit, version):
        """Refuse an unusable request up front (before any background work)."""
        if type(commit) is not str or not _HEX40.fullmatch(commit):
            raise AuthorityError("commit_invalid")
        try:
            release.tag_for_version(version)
        except ReleaseError:
            raise AuthorityError("version_invalid") from None
        if not self.build_prefix:
            raise AuthorityError("builder_not_configured")
        if not self.keyfile.exists() or not self.tokenfile.exists():
            raise AuthorityError("release_authority_not_provisioned")

    def prepare(self, commit, version, installed_version):
        """Build and verify (synchronous; the installer runs it in the background). Records the outcome; raises nothing for a
        failed build - the record says why."""
        self.prepare_check(commit, version)
        previous = self._state(commit)
        if previous and previous.get("state") == "building" and self.clock() - previous.get("started", 0) < BUILD_TIMEOUT + TEST_TIMEOUT:
            raise AuthorityError("already_building")
        d = self._dir(commit)
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, mode=0o700)
        record = {"state": "building", "commit": commit, "version": version, "started": self.clock()}
        self._save(commit, record)
        try:
            record.update(self._build(commit, version, d))
            record["state"] = "ready"
        except AuthorityError as failed:
            record.update(state="failed", why=failed.code)
        except Exception as error:                       # a bug must never look like a good build
            record.update(state="failed", why="unexpected_%s" % type(error).__name__)
        record["finished"] = self.clock()
        self._save(commit, record)
        return self.status(commit)

    def _sh(self, argv, timeout, cwd=None, env=None):
        return self.run(argv, timeout, cwd=cwd, env=env) if cwd is not None or env is not None else self.run(argv, timeout)

    def _build(self, commit, version, d):
        env_base = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C.UTF-8", "GIT_TERMINAL_PROMPT": "0"}
        work = (self.work_root / commit) if self.work_root else d / "work"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, mode=0o700)
        if self.build_uid is not None:
            os.chown(work, self.build_uid, -1)
            os.chmod(work, 0o700)
        src = work / "src"
        shell = lambda script, timeout, **kw: self.run(self._as_builder(["sh", "-c", script]), timeout, cwd=str(work),
                                                        env=dict(env_base, HOME=str(work), **kw))
        steps = ("git init -q src && cd src && git remote add origin %s && git fetch -q --depth 1 origin %s && "
                 "git checkout -q --detach FETCH_HEAD && git rev-parse HEAD" % (shlex.quote(self.clone_url), commit))
        code, out = shell(steps, GIT_TIMEOUT)
        if code != 0 or out.strip().splitlines()[-1:] != [commit]:
            raise AuthorityError("could_not_fetch_that_exact_commit")
        code, out = shell("cd src && sed -n 's/^__version__ = \"\\(.*\\)\"/\\1/p' src/stynpilot/__init__.py", 30)
        if code != 0 or out.strip().replace(".dev", "~dev") != version:
            raise AuthorityError("source_version_differs_from_requested_version")
        hashes = []
        for n, mask in enumerate(("022", "077")):
            code, out = shell("umask %s && cd src && mkdir -p ../out%d && python3 -c \"import sys;sys.path.insert(0,'tools');"
                              "import build_deb;print(build_deb.build('../out%d','../cache'))\"" % (mask, n, n), BUILD_TIMEOUT)
            if code != 0:
                raise AuthorityError("build_failed")
            code, out = shell("sha256sum out%d/*.deb | cut -d' ' -f1" % n, 60)
            if code != 0 or not re.fullmatch(r"[0-9a-f]{64}", out.strip()):
                raise AuthorityError("build_output_unreadable")
            hashes.append(out.strip())
        if hashes[0] != hashes[1]:
            raise AuthorityError("build_is_not_reproducible")
        code, out = shell("cd src && PYTHONPATH=src python3 -m pytest -q -p no:cacheprovider tests 2>&1 | tail -3", TEST_TIMEOUT)
        counts = self._count_tests(out)
        if counts is None:
            raise AuthorityError("test_result_unreadable")
        passed, failed, skipped = counts
        if failed or not passed:
            raise AuthorityError("tests_failed_%d_passed_%d" % (failed, passed))
        # Copy the verified package out of the builder's folder (root re-reads and re-hashes it: the builder is not trusted).
        deb = next((work / "out0").glob("*.deb"), None)
        if deb is None:
            raise AuthorityError("package_missing")
        real = os.path.realpath(deb)                          # the build account controls this folder: never follow it elsewhere
        info = os.lstat(real)
        if (not real.startswith(os.path.realpath(work) + os.sep) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET):
            raise AuthorityError("package_not_where_the_builder_should_have_put_it")
        data = Path(real).read_bytes()
        if hashlib.sha256(data).hexdigest() != hashes[0]:
            raise AuthorityError("package_changed_after_build")
        target = d / ("stynpilot_%s_all.deb" % version)
        _write_private(target, data)
        shutil.rmtree(work, ignore_errors=True)
        return {"sha256": hashes[0], "size": len(data), "reproducible": True, "tests_passed": passed, "tests_failed": failed,
                "tests_skipped": skipped, "deb": target.name}

    @staticmethod
    def _count_tests(text):
        for line in reversed(text.strip().splitlines()):
            m = _TESTS_LINE.search(line)
            if m and ("passed" in line):
                return int(m.group(2)), int(m.group(1) or 0) + int(m.group(4) or 0), int(m.group(3) or 0)
        return None

    # -- what the owner is asked to approve (from the verified record only) --------------------------------------------------
    def intent(self, commit, version, review_note="", from_min=""):
        """The exact, installer-derived intent for a verified build. Raises unless the build is ready and still matches."""
        rec = self._state(commit) if type(commit) is str and _HEX40.fullmatch(commit) else None
        if not rec or rec.get("state") != "ready" or rec.get("version") != version:
            raise AuthorityError("build_not_ready")
        if type(review_note) is not str or not _REVIEW.fullmatch(review_note):
            raise AuthorityError("review_note_invalid")
        deb = self._dir(commit) / rec["deb"]
        data = deb.read_bytes()
        if hashlib.sha256(data).hexdigest() != rec["sha256"] or len(data) != rec["size"]:
            raise AuthorityError("verified_package_was_altered")
        return {"commit": commit, "version": version, "sha256": rec["sha256"], "size": rec["size"],
                "tests_passed": rec["tests_passed"], "tests_failed": rec["tests_failed"], "tests_skipped": rec["tests_skipped"],
                "reproducible": True, "key_id": self.key_entry()["key_id"], "from_min": from_min, "review_note": review_note}

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

    def publish(self, manifest, signature, commit):
        """Create the GitHub release for the tag at the exact commit and upload the three files. Safe to repeat: an existing
        identical release is accepted; anything different is refused."""
        tag, repo = manifest["tag"], self.repository
        deb_path = self._dir(commit) / ("stynpilot_%s_all.deb" % manifest["version"])
        data = deb_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest["sha256"] or len(data) != manifest["size"]:
            raise AuthorityError("verified_package_was_altered")
        base = "https://%s/repos/%s" % (API_HOST, repo)
        status, body = self._api("GET", "%s/releases/tags/%s" % (base, tag))
        if status == 200:
            info = json.loads(body.decode())
            have = {a["name"] for a in info.get("assets", [])}
            if info.get("target_commitish") not in (commit, None) and len(info.get("target_commitish", "")) == 40:
                raise AuthorityError("tag_exists_for_a_different_commit")
        elif status == 404:
            status, body = self._api("POST", base + "/releases", {"tag_name": tag, "target_commitish": commit, "name": tag,
                                                                  "draft": False, "prerelease": True,
                                                                  "body": "Built from commit %s and signed after owner approval." % commit})
            if status != 201:
                raise AuthorityError("release_not_created_status_%d" % status)
            info, have = json.loads(body.decode()), set()
        else:
            raise AuthorityError("github_status_%d" % status)
        files = {manifest["asset"]: (data, "application/octet-stream"),
                 "release-manifest.json": (release.canonical(manifest), "application/json"),
                 "release-manifest.json.sig": (signature.encode("ascii"), "text/plain")}
        for name, (content, kind) in files.items():
            if name in have:
                continue
            url = "https://%s/repos/%s/releases/%d/assets?name=%s" % (UPLOAD_HOST, repo, info["id"], urllib.parse.quote(name))
            status, body = self._api("POST", url, content, content_type=kind, max_bytes=200_000)
            if status != 201:
                raise AuthorityError("upload_failed_%s_status_%d" % (name[:30], status))
        return {"tag": tag, "release_id": info["id"]}
