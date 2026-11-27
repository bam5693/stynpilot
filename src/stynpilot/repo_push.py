"""Single exact ref update from a clean, separate Git transport workspace."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from . import repo_git

ZERO = "0" * 40


def push_bundle(bundle, branch, commit, expected, token, *, remote=repo_git.ORIGIN):
    """Native Git validates ancestry and its receive-pack protocol checks old ref state."""
    repo_git.validate_push(branch, commit, expected)
    if not 0 < len(bundle) <= repo_git.BUNDLE_LIMIT:
        raise repo_git.WorkspaceError("git_push_bundle_invalid")
    if remote == repo_git.ORIGIN and not re.fullmatch(r"[A-Za-z0-9_]{20,255}", token):
        raise repo_git.WorkspaceError("git_push_credential_unavailable")
    ref = "refs/heads/" + branch
    with tempfile.TemporaryDirectory(prefix="stynpilot-push-") as scratch:
        folder = Path(scratch)
        archive = folder / "checkout.bundle"
        archive.write_bytes(bundle)
        hooks = folder / "hooks"
        hooks.mkdir()
        guard = hooks / "pre-push"
        guard.write_text(
            "#!/usr/bin/python3 -I\n"
            "import sys\n"
            "entry = sys.stdin.read(4097).split()\n"
            f"raise SystemExit(0 if entry == [{ref!r}, {commit!r}, {ref!r}, {expected!r}] else 1)\n",
            encoding="ascii",
        )
        guard.chmod(0o700)
        repository = folder / "transport.git"
        commands = [
            "/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
            "-c", "protocol.file.allow=always",
        ]

        def git(*args, env=None):
            return subprocess.run(commands + list(args), cwd=folder, env=env or repo_git._ENV,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=30, check=True).stdout

        git("init", "--bare", "--quiet", "--template=", str(repository))
        commands.extend(["--git-dir=" + str(repository)])
        if git("bundle", "list-heads", str(archive)).splitlines() != [f"{commit} {ref}".encode("ascii")]:
            raise repo_git.WorkspaceError("git_push_commit_mismatch")
        git("fetch", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance", "--",
            str(archive), ref + ":" + ref)
        # The transport always uses a full-history bundle and a fresh bare
        # repository. It has no workspace hooks, config, files or credentials.
        if git("rev-parse", "--verify", ref + "^{commit}").strip() != commit.encode("ascii"):
            raise repo_git.WorkspaceError("git_push_commit_mismatch")
        env = dict(repo_git._ENV)
        if remote == repo_git.ORIGIN:
            auth = base64.b64encode(("x-access-token:" + token).encode("ascii")).decode("ascii")
            env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http." + remote + ".extraHeader",
                       GIT_CONFIG_VALUE_0="Authorization: Basic " + auth)
            commands.extend(["-c", "protocol.https.allow=always", "-c", "protocol.file.allow=never",
                             "-c", "http.followRedirects=false", "-c", "credential.helper="])
        def remote_head():
            entries = git("ls-remote", "--refs", "--", remote, ref, env=env).splitlines()
            if not entries:
                return ZERO
            if len(entries) != 1:
                raise repo_git.WorkspaceError("git_push_remote_changed")
            object_id, sep, remote_ref = entries[0].partition(b"\t")
            if not sep or remote_ref != ref.encode("ascii") or not re.fullmatch(rb"[0-9a-f]{40}", object_id):
                raise repo_git.WorkspaceError("git_push_remote_changed")
            return object_id.decode("ascii")

        current = remote_head()
        if current == commit:
            return
        if current != expected:
            raise repo_git.WorkspaceError("git_push_remote_changed")
        # The pre-push hook checks the actual push advertisement. Native push
        # then enforces fast-forward and receive-pack performs old-OID CAS.
        git("-c", "core.hooksPath=" + str(hooks), "push", "--porcelain",
            "--no-follow-tags", "--recurse-submodules=no", "--", remote, ref + ":" + ref, env=env)
        if remote_head() != commit:
            raise repo_git.WorkspaceError("git_push_outcome_unverified")


def main():
    try:
        branch, commit, expected = sys.argv[1:]
        token = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / "github").read_text("ascii").strip()
        push_bundle(sys.stdin.buffer.read(repo_git.BUNDLE_LIMIT + 1), branch, commit, expected, token)
    except (KeyError, ValueError, OSError, subprocess.SubprocessError, repo_git.WorkspaceError):
        return 1
    return 0
