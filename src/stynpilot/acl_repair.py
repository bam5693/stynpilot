"""Run by the sandbox account, inside the sandbox, after a job: give the OWNER (and the sandbox accounts) working access to the
files and folders this account created.

Why it exists: a file created with mode 0600 under a default ACL gets an ACL mask of 0, which switches the owner's named entry off.
Only the file's own account can change that ACL, so the account repairs its own files.

What it will NOT do: touch anything it does not own, follow a link, enter or change a protected (credential-named) path, or keep any
ACL entry other than the three kinds it writes (``-b`` first), so it cannot widen an unrelated entry. Mode bits for "other" are kept.

``python3 -I -c 'import sys; sys.path.insert(0, LIB); from stynpilot import acl_repair; acl_repair.main()' '<json>'``
"""
import json
import os
import re
import stat
import subprocess
import sys

from stynpilot import safefs

MAX_ENTRIES = 50000
MAX_DEPTH = 64
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
TRASH = ".stynpilot-trash"


def _protected(name):
    if name == TRASH:
        return True
    try:
        safefs.Policy.name_ok(name)
    except safefs.FileDenied:
        return True
    return False


def _setfacl(args, fd):
    subprocess.run(["setfacl"] + args + ["--", "/proc/self/fd/%d" % fd], pass_fds=[fd], capture_output=True, env=_ENV, timeout=60, check=False)


def repair(root_fd, uid, owner, users):
    named = ",".join("u:%s:rwX" % u for u in [owner] + list(users))
    seen = [0]

    def visit(dirfd, dev, depth):
        if depth > MAX_DEPTH:
            return
        try:
            names = sorted(os.listdir(dirfd))
        except OSError:
            return
        for name in names:
            seen[0] += 1
            if seen[0] > MAX_ENTRIES or _protected(name):
                continue
            try:
                before = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                continue
            mode = before.st_mode
            if before.st_dev != dev or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                continue
            is_dir = stat.S_ISDIR(mode)
            try:
                fd = os.open(name, _DIR if is_dir else os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
            except OSError:
                continue
            try:
                after = os.fstat(fd)
                if (after.st_ino, after.st_dev) != (before.st_ino, before.st_dev) or stat.S_ISDIR(after.st_mode) != is_dir \
                        or (not is_dir and after.st_nlink > 1):
                    continue
                if after.st_uid == uid:
                    _setfacl(["-b"], fd)
                    _setfacl(["-m", named], fd)
                    if is_dir:
                        _setfacl(["-k"], fd)
                        _setfacl(["-d", "-m", "u:%s:rwX,g::---,o::---" % owner], fd)
                if is_dir:
                    visit(fd, dev, depth + 1)
            finally:
                os.close(fd)
    info = os.fstat(root_fd)
    visit(root_fd, info.st_dev, 0)
    return seen[0]


def main():
    request = json.loads(sys.argv[1])
    owner, users = request["owner"], request["users"]
    for u in [owner] + users:
        if type(u) is not str or not _USER.fullmatch(u):
            raise SystemExit(2)
    fd = os.open(".", _DIR)
    try:
        repair(fd, os.getuid(), owner, users)
    finally:
        os.close(fd)
