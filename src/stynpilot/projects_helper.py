"""The projects helper: everything that touches the owner's home folder on behalf of the root installer.

It runs AS THE OWNER (an unprivileged user, no capabilities: in production a transient systemd unit, in tests a real uid drop),
so the root installer never needs to see the home folder (its unit keeps ProtectHome=yes) and a path race can never give root
power over anything: the owner can only change what the owner already owns.

Even so every walk is race-safe: directories are opened with O_NOFOLLOW from the previous directory's descriptor, files are
opened with O_PATH|O_NOFOLLOW and re-checked on the descriptor itself (regular, one link, same device, same inode), and ACLs are
applied to ``/proc/self/fd/N`` (the inode we hold), never to a path name. A link swapped in mid-walk is skipped, not followed.

Usage: ``python3 -I projects_helper.py '<json request>'`` -> one JSON line. Standard library plus stynpilot.safefs only.
"""
import json
import os
import re
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stynpilot import safefs  # noqa: E402

MAX_ENTRIES = 50000
MAX_DEPTH = 40
BATCH = 100
MAX_PROTECTED = 64
TRASH = ".stynpilot-trash"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class Refuse(Exception):
    pass


def _no_links(path):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise Refuse("path_not_canonical")
    cur = "/"
    for part in [p for p in path.split("/") if p]:
        cur = os.path.join(cur, part)
        if stat.S_ISLNK(os.lstat(cur).st_mode):
            raise Refuse("path_contains_a_link")


def _projects(request):
    projects, home = request.get("projects"), request.get("home")
    if type(projects) is not str or type(home) is not str or os.path.dirname(projects) != home:
        raise Refuse("projects_folder_must_be_directly_in_the_home_folder")
    _no_links(home)
    _no_links(projects) if os.path.lexists(projects) else None
    return projects


def _own_folder(path):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise Refuse("folder_must_be_a_real_folder_owned_by_the_owner")
    if info.st_mode & 0o002:
        raise Refuse("folder_is_world_writable")
    return info


def _workspace(request, create=False):
    projects, name = _projects(request), request.get("name")
    if type(name) is not str or not _NAME.fullmatch(name):
        raise Refuse("workspace_name_invalid")
    try:
        safefs.Policy.name_ok(name)
    except safefs.FileDenied:
        raise Refuse("workspace_name_protected") from None
    _own_folder(projects)
    path = os.path.join(projects, name)
    if create and not os.path.lexists(path):
        os.mkdir(path, 0o700)
    _no_links(path)
    _own_folder(path)
    return path


def _setfacl(args, fds):
    done = subprocess.run(["setfacl"] + args + ["--"] + ["/proc/self/fd/%d" % fd for fd in fds], pass_fds=fds, capture_output=True,
                          env=_ENV, timeout=120, check=False)
    if done.returncode != 0:
        raise Refuse("could_not_set_permissions")


def _open_checked(dirfd, name, dev):
    """(fd, is_dir) for a plain file or folder on the same file system, verified on the descriptor itself; else None."""
    try:
        before = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except OSError:
        return None
    mode = before.st_mode
    if before.st_dev != dev or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return None
    try:
        fd = os.open(name, (_DIR if stat.S_ISDIR(mode) else os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC), dir_fd=dirfd)
    except OSError:
        return None
    after = os.fstat(fd)
    if (after.st_ino, after.st_dev) != (before.st_ino, before.st_dev) or stat.S_ISDIR(after.st_mode) != stat.S_ISDIR(mode) \
            or (stat.S_ISREG(after.st_mode) and after.st_nlink > 1):
        os.close(fd)
        return None
    return fd, stat.S_ISDIR(mode)


class Counter:
    def __init__(self):
        self.entries = 0
        self.skipped = 0


def _walk_acl(dirfd, dev, apply, count, depth=0):
    """Visit one folder: ``apply(files_fds, dir_fds)`` on batches, then recurse into sub folders."""
    if depth > MAX_DEPTH:
        count.skipped += 1
        return
    files, subdirs = [], []
    try:
        names = sorted(os.listdir(dirfd))
    except OSError:
        count.skipped += 1
        return
    try:
        for name in names:
            if name == TRASH:
                count.skipped += 1
                continue
            try:
                safefs.Policy.name_ok(name)
            except safefs.FileDenied:
                count.skipped += 1
                continue
            got = _open_checked(dirfd, name, dev)
            if got is None:
                count.skipped += 1
                continue
            count.entries += 1
            if count.entries > MAX_ENTRIES:
                os.close(got[0])
                raise Refuse("workspace_too_large")
            (subdirs if got[1] else files).append(got[0])
            if len(files) >= BATCH:
                apply(files, [])
                for fd in files:
                    os.close(fd)
                files = []
        apply(files, [])
        for fd in subdirs:
            apply([], [fd])
        for fd in subdirs:
            _walk_acl(fd, dev, apply, count, depth + 1)
    finally:
        for fd in files + subdirs:
            try:
                os.close(fd)
            except OSError:
                pass


def _grant(files, dirs, spec):
    if files:
        _setfacl(["-m", spec], files)
    if dirs:
        _setfacl(["-m", spec], dirs)
        _setfacl(["-d", "-m", spec], dirs)


def _revoke(files, dirs, who):
    if files:
        _setfacl(["-x", who], files)
    if dirs:
        _setfacl(["-x", who], dirs)
        _setfacl(["-d", "-x", who], dirs)


def _users(request):
    run_user, owner_user = request.get("run_user"), request.get("owner_user")
    for u in (run_user, owner_user):
        if type(u) is not str or not _USER.fullmatch(u):
            raise Refuse("user_name_invalid")
    return run_user, owner_user


def op_prepare(request):
    projects = request.get("projects")
    home = request.get("home")
    if type(projects) is not str or type(home) is not str or os.path.dirname(projects) != home:
        raise Refuse("projects_folder_must_be_directly_in_the_home_folder")
    _no_links(home)
    created = False
    if not os.path.lexists(projects):
        os.mkdir(projects, 0o700)
        created = True
    _no_links(projects)
    _own_folder(projects)
    return {"created": created}


def op_check(request):
    return {"path": _workspace(request)}


def op_home_names(request):
    home = request.get("home")
    _no_links(home)
    return {"names": sorted(os.listdir(home))[:200]}


def op_disk(request):
    path = request.get("path")
    _no_links(path)
    info = os.statvfs(path)
    return {"free": info.f_bavail * info.f_frsize, "total": info.f_blocks * info.f_frsize, "device": os.stat(path).st_dev}


def _open_root(path):
    fd = os.open(path, _DIR)
    return fd, os.fstat(fd)


def op_enroll(request):
    run_user, owner_user = _users(request)
    path = _workspace(request, create=True)
    spec = "u:%s:rwX,u:%s:rwX" % (run_user, owner_user)
    fd, info = _open_root(path)
    count = Counter()
    try:
        _grant([], [fd], spec)
        _walk_acl(fd, info.st_dev, lambda f, d: _grant(f, d, spec), count)
    finally:
        os.close(fd)
    return {"path": path, "entries": count.entries + 1, "skipped": count.skipped}


def op_unenroll(request):
    run_user, _ = _users({"run_user": request.get("run_user"), "owner_user": request.get("run_user")})
    path = _workspace(request)
    who = "u:%s" % run_user
    fd, info = _open_root(path)
    count = Counter()
    try:
        _revoke([], [fd], who)
        _walk_acl(fd, info.st_dev, lambda f, d: _revoke(f, d, who), count)
    finally:
        os.close(fd)
    return {"path": path}


def op_protected(request):
    """Credential-named files and folders (and the trash) that the sandbox must not see at all, found NOW (not at enrolment)."""
    path = _workspace(request)
    found, seen = [], [0]

    def scan(dirfd, rel, depth):
        if depth > MAX_DEPTH:
            return
        for name in sorted(os.listdir(dirfd)):
            seen[0] += 1
            if seen[0] > MAX_ENTRIES:
                raise Refuse("workspace_too_large")
            try:
                info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            except OSError:
                continue
            here = rel + "/" + name if rel else name
            bad = name == TRASH
            if not bad:
                try:
                    safefs.Policy.name_ok(name)
                except safefs.FileDenied:
                    bad = True
            if bad:
                found.append(here)
                if len(found) > MAX_PROTECTED:
                    raise Refuse("too_many_protected_files")
                continue
            if stat.S_ISDIR(info.st_mode):
                try:
                    sub = os.open(name, _DIR, dir_fd=dirfd)
                except OSError:
                    continue
                try:
                    scan(sub, here, depth + 1)
                finally:
                    os.close(sub)
    fd = os.open(path, _DIR)
    try:
        scan(fd, "", 0)
    finally:
        os.close(fd)
    return {"path": path, "protected": found}


OPS = {"prepare": op_prepare, "check": op_check, "home_names": op_home_names, "disk": op_disk, "enroll": op_enroll,
       "unenroll": op_unenroll, "protected": op_protected}


def main(argv):
    try:
        request = json.loads(argv[1])
        op = OPS[request["op"]]
        out = {"ok": True, **op(request)}
    except Refuse as refused:
        out = {"ok": False, "error": str(refused)}
    except (KeyError, ValueError, TypeError, IndexError):
        out = {"ok": False, "error": "request_invalid"}
    except OSError as error:
        out = {"ok": False, "error": "os_error_%s" % type(error).__name__}
    sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
