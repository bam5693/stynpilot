"""Native, offline Git writes for the enrolled StyNpilot checkout."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from .workspace import WorkspaceError, parts_of

WORKSPACE = "stynpilot"
ORIGIN = "https://github.com/bam5693/stynpilot.git"
BRANCH, COMMIT = "git-work-branch", "git-work-commit"
SWITCH, FAST_FORWARD = "git-work-switch", "git-work-fast-forward"
RECIPES = frozenset((BRANCH, COMMIT, SWITCH, FAST_FORWARD))
FETCH = "git-verified-fetch"
MUTATIONS = RECIPES | {FETCH}
BUNDLE_LIMIT = 32 << 20
BUNDLE_REF = "refs/heads/stynpilot-import"
VERIFIED_REF_PREFIX = "refs/stynpilot/verified/"
_REF = re.compile(r"(?:work|test)/[a-z0-9][a-z0-9_-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CONFIG = {
    "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
    "remote.origin.url", "remote.origin.fetch",
}
_IN_PROGRESS = ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-apply", "rebase-merge", "sequencer")
_ENV = {
    "PATH": "/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
}


def read_bundle(commit, digest, stream):
    if not _SHA.fullmatch(commit) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise WorkspaceError("checkout_binding_invalid")
    data = stream.read(BUNDLE_LIMIT + 1)
    if not 0 < len(data) <= BUNDLE_LIMIT or hashlib.sha256(data).hexdigest() != digest:
        raise WorkspaceError("checkout_bundle_digest_mismatch")
    return data


def validate(recipe, args, workspace):
    fixed_count = {BRANCH: 2, SWITCH: 3, FAST_FORWARD: 3}
    valid_count = len(args) == fixed_count[recipe] if recipe in fixed_count else recipe == COMMIT and 4 <= len(args) <= 11
    if Path(workspace).name != WORKSPACE:
        raise WorkspaceError("git_workspace_not_bound")
    if not valid_count or not _REF.fullmatch(args[0]) or not _SHA.fullmatch(args[1]):
        raise WorkspaceError("git_request_invalid")
    if recipe in (SWITCH, FAST_FORWARD) and not _SHA.fullmatch(args[2]):
        raise WorkspaceError("git_request_invalid")
    if recipe == COMMIT:
        message, *paths = args[2:]
        if not message.strip() or message.startswith("-") or len(set(paths)) != len(paths):
            raise WorkspaceError("git_request_invalid")
        for path in paths:
            if not (parts := parts_of(path)) or path != "/".join(parts):
                raise WorkspaceError("git_path_invalid")


def run(recipe, args, folder):
    if recipe == FETCH:
        if Path(folder).name != WORKSPACE or len(args) != 2:
            raise WorkspaceError("git_workspace_not_bound")
    else:
        validate(recipe, args, folder)
    branch, expected = args[:2]
    folder = Path(folder)
    metadata = folder / ".git"
    if not stat.S_ISDIR(metadata.lstat().st_mode):
        raise WorkspaceError("git_checkout_required")
    if not stat.S_ISREG((metadata / "config").lstat().st_mode):
        raise WorkspaceError("git_checkout_required")
    if any(os.path.lexists(metadata / name) for name in _IN_PROGRESS):
        raise WorkspaceError("git_operation_in_progress")

    command = [
        "/usr/bin/git", "--no-pager", "--literal-pathspecs",
        "-c", "safe.directory=" + str(folder), "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-c", "commit.gpgSign=false",
        "-c", "submodule.recurse=false",
        "-c", "user.name=StyNpilot workspace", "-c", "user.email=workspace@stynpilot.invalid",
        "--git-dir=.git", "--work-tree=.",
    ]

    def git(*argv, hooks=None, file_transport=False):
        config = ["-c", "core.hooksPath=" + str(hooks)] if hooks else []
        if file_transport:
            config += ["-c", "protocol.file.allow=always"]
        result = subprocess.run(command + config + list(argv), cwd=folder, env=_ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False)
        if result.returncode != 0:
            raise WorkspaceError("git_operation_refused")
        return result.stdout

    config = git("config", "--local", "--no-includes", "--null", "--list").split(b"\0")
    origins = []
    for entry in config[:-1]:
        key, _, value = entry.decode("utf-8").partition("\n")
        if key not in _CONFIG:
            raise WorkspaceError("git_checkout_config_not_supported")
        if key == "remote.origin.url":
            origins.append(value)
    if origins != [ORIGIN]:
        raise WorkspaceError("git_workspace_origin_mismatch")
    if recipe == FETCH:
        commit, digest = args
        data = read_bundle(commit, digest, sys.stdin.buffer)
        with tempfile.TemporaryDirectory(prefix="stynpilot-git-fetch-") as scratch:
            bundle = Path(scratch) / "checkout.bundle"
            bundle.write_bytes(data)
            if git("bundle", "list-heads", str(bundle)).splitlines() != [f"{commit} {BUNDLE_REF}".encode("ascii")]:
                raise WorkspaceError("checkout_commit_mismatch")
            git("fetch", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head",
                "--no-auto-maintenance", "--", str(bundle), BUNDLE_REF, file_transport=True)
        if git("rev-parse", "--verify", commit + "^{commit}").strip() != commit.encode("ascii"):
            raise WorkspaceError("checkout_commit_mismatch")
        ref = VERIFIED_REF_PREFIX + commit
        # Accept a retry of the same immutable ref, and refuse an altered
        # ref without forcing either a protected ref or the current branch.
        found = git("for-each-ref", "--format=%(objectname) %(refname)", ref).splitlines()
        if found != [f"{commit} {ref}".encode("ascii")]:
            git("update-ref", "--no-deref", ref, commit, "0" * 40)
        return commit

    if git("rev-parse", "--verify", "HEAD").strip().decode("ascii") != expected:
        raise WorkspaceError("git_head_changed")

    if recipe == BRANCH:
        git("switch", "--no-track", "--no-recurse-submodules", "--no-overwrite-ignore", "--create", branch, expected)
        return expected

    ref = "refs/heads/" + branch
    if recipe in (SWITCH, FAST_FORWARD):
        target = args[2]
        if git("status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=none"):
            raise WorkspaceError("git_workspace_dirty")
        if recipe == SWITCH:
            if git("show-ref", "--hash", "--verify", ref).strip().decode("ascii") != target:
                raise WorkspaceError("git_target_changed")
            git("switch", "--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--", branch)
            if git("rev-parse", "--verify", "HEAD").strip().decode("ascii") != target:
                raise WorkspaceError("git_target_changed")
            return target
        if git("symbolic-ref", "--quiet", "HEAD").strip().decode("ascii") != ref:
            raise WorkspaceError("git_work_branch_required")
        if git("rev-parse", "--verify", target + "^{commit}").strip().decode("ascii") != target:
            raise WorkspaceError("git_target_not_commit")
        git("merge-base", "--is-ancestor", expected, target)
        if target == expected:
            return expected
        operation = ("merge", "--ff-only", "--no-autostash", "--no-edit", "--no-overwrite-ignore", target)
    else:
        if git("symbolic-ref", "--quiet", "HEAD").strip().decode("ascii") != ref:
            raise WorkspaceError("git_work_branch_required")
        message, *paths = args[2:]
        added = []
        for path in paths:
            node = folder
            for part in parts_of(path):
                node /= part
                if node.is_symlink():
                    raise WorkspaceError("git_path_invalid")
            exists = node.exists()
            if exists:
                info = node.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise WorkspaceError("git_path_invalid")
            indexed = git("ls-files", "--cached", "-z", "--", path)
            if not indexed and exists:
                added.append(path)
            elif indexed != path.encode() + b"\0":
                raise WorkspaceError("git_path_invalid")
        if added:
            # Intent-to-add is Git's recoverable placeholder for an untracked
            # file. It doesn't stage contents or alter unrelated index entries.
            git("add", "--intent-to-add", "--", *added)
        operation = ("commit", "--only", "--no-gpg-sign", "-m", message, "--", *paths)
    # Git invokes this guard while the ref transaction is locked. It
    # stops a native caller's concurrent branch switch or head advance
    # from redirecting the commit after the worker's initial validation.
    with tempfile.TemporaryDirectory(prefix="stynpilot-git-hooks-") as hooks:
        guard = Path(hooks) / "reference-transaction"
        guard.write_text(
            "#!/usr/bin/python3 -I\n"
            "import sys\n"
            "if sys.argv[1] != 'prepared':\n"
            "    raise SystemExit(0)\n"
            "entry = sys.stdin.read(4097).split()\n"
            "if entry == ['0' * 40, '0' * 40, 'AUTO_MERGE']:\n"
            "    raise SystemExit(0)\n"
            f"if {recipe == FAST_FORWARD!r} and len(entry) == 3 and "
            f"entry[1:] == [{expected!r}, 'ORIG_HEAD']:\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit(0 if len(entry) == 3 and "
            f"entry[0] == {expected!r} and entry[2] == {ref!r} else 1)\n",
            encoding="ascii",
        )
        guard.chmod(0o700)
        git(*operation, hooks=hooks)
    return git("rev-parse", "--verify", "HEAD").strip().decode("ascii")


def main():
    try:
        print(run(sys.argv[1], sys.argv[2:], Path.cwd()))
    except WorkspaceError as error:
        print(error.code)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("git_checkout_unavailable")
        return 1
    return 0
