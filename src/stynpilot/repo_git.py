"""Native, offline Git writes for the enrolled StyNpilot checkout."""
from __future__ import annotations

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
RECIPES = frozenset((BRANCH, COMMIT))
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


def validate(recipe, args, workspace):
    valid_count = (len(args) == 2 if recipe == BRANCH else 4 <= len(args) <= 11)
    if Path(workspace).name != WORKSPACE:
        raise WorkspaceError("git_workspace_not_bound")
    if not valid_count or not _REF.fullmatch(args[0]) or not _SHA.fullmatch(args[1]):
        raise WorkspaceError("git_request_invalid")
    if recipe == COMMIT:
        message, *paths = args[2:]
        if not message.strip() or message.startswith("-") or len(set(paths)) != len(paths):
            raise WorkspaceError("git_request_invalid")
        for path in paths:
            if not (parts := parts_of(path)) or path != "/".join(parts):
                raise WorkspaceError("git_path_invalid")


def run(recipe, args, folder):
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
        "-c", "user.name=StyNpilot workspace", "-c", "user.email=workspace@stynpilot.invalid",
        "--git-dir=.git", "--work-tree=.",
    ]

    def git(*argv, hooks=None):
        config = ["-c", "core.hooksPath=" + str(hooks)] if hooks else []
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
    if git("rev-parse", "--verify", "HEAD").strip().decode("ascii") != expected:
        raise WorkspaceError("git_head_changed")

    if recipe == BRANCH:
        git("switch", "--no-track", "--no-recurse-submodules", "--create", branch, expected)
    else:
        if git("symbolic-ref", "--quiet", "HEAD").strip().decode("ascii") != "refs/heads/" + branch:
            raise WorkspaceError("git_work_branch_required")
        message, *paths = args[2:]
        for path in paths:
            node = folder
            for part in parts_of(path):
                node /= part
                if node.is_symlink():
                    raise WorkspaceError("git_path_invalid")
            if node.exists():
                info = node.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise WorkspaceError("git_path_invalid")
            if git("ls-files", "--cached", "-z", "--", path) != path.encode() + b"\0":
                raise WorkspaceError("git_tracked_file_required")
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
                "raise SystemExit(0 if len(entry) == 3 and "
                f"entry[0] == {expected!r} and entry[2] == {'refs/heads/' + branch!r} else 1)\n",
                encoding="ascii",
            )
            guard.chmod(0o700)
            git("commit", "--only", "--no-gpg-sign", "-m", message, "--", *paths, hooks=hooks)
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
