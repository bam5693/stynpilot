"""The projects helper: everything that touches the owner's home folder on behalf of the root installer.

It runs AS THE OWNER (an unprivileged user, no capabilities: in production a transient systemd unit, in tests a real uid drop),
so the root installer never needs to see the home folder (its unit keeps ProtectHome=yes) and a path race can never give root
power over anything: the owner can only change what the owner already owns.

Every walk is race-safe: folders are opened with O_NOFOLLOW from the previous folder's descriptor, files are opened with
O_PATH|O_NOFOLLOW and re-checked on the descriptor itself (regular, one link, same device, same inode), and ACLs are applied to
``/proc/self/fd/N`` (the inode we hold), never to a name. A link swapped in mid-walk is skipped, not followed.

Access model (the runtime boundary for new files): the sandbox accounts get NAMED ACL entries on what exists NOW, granted again at
every job start. There is deliberately NO default entry for them: a file or folder created in the workspace later (by the owner, by an
AI tool, by anything else) starts with no access for the sandbox accounts and with no "other" access at all (default ACL
``o::---``), whatever its name, until the next job start has looked at it. A scan that cannot be completed is a refusal, never a
partial result.

Usage: ``python3 -I projects_helper.py '<json request>'`` -> one JSON line. Standard library plus stynpilot.safefs only.
"""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from stynpilot import archive_store, deckplay_snapshot, repo_archive, repo_git, safefs, vault  # noqa: E402
from stynpilot.server.clients import ClientDenied, RevocationFile  # noqa: E402

MAX_ENTRIES = 50000
MAX_DEPTH = 64
BATCH = 100
MAX_PROTECTED = 64
TRASH = ".stynpilot-trash"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class Refuse(Exception):
    pass


def is_protected_name(name):
    if name == TRASH:
        return True
    try:
        safefs.Policy.name_ok(name)
    except safefs.FileDenied:
        return True
    return False


def _no_links(path):
    if type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path:
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
    if os.path.lexists(projects):
        _no_links(projects)
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
    if is_protected_name(name):
        raise Refuse("workspace_name_protected")
    _own_folder(projects)
    path = os.path.join(projects, name)
    if create and not os.path.lexists(path):
        os.mkdir(path, 0o700)
    _no_links(path)
    _own_folder(path)
    return path


def _setfacl(args, fds, ignore_failure=False):
    done = subprocess.run(["setfacl"] + args + ["--"] + ["/proc/self/fd/%d" % fd for fd in fds], pass_fds=fds, capture_output=True,
                          env=_ENV, timeout=120, check=False)
    if done.returncode != 0 and not ignore_failure:
        raise Refuse("could_not_set_permissions")


def _open_checked(dirfd, name, dev):
    """(fd, is_dir) for a plain file or folder on the same file system, verified on the descriptor itself; None for anything else
    (links, devices, other file systems, hard-linked files, or a name that vanished). A real error is a refusal."""
    try:
        before = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refuse("scan_incomplete") from None
    mode = before.st_mode
    if before.st_dev != dev or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return None
    try:
        fd = os.open(name, (_DIR if stat.S_ISDIR(mode) else os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC), dir_fd=dirfd)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise Refuse("scan_incomplete") from None
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
        self.protected = []


def _walk(dirfd, dev, apply, count, rel="", depth=0, include_protected=False):
    """Visit one folder: ``apply(file_fds, dir_fds)`` on batches, then recurse. Protected names are recorded (and not visited) unless
    ``include_protected``. Anything that stops the walk from seeing a folder completely raises Refuse: no partial scans."""
    if depth > MAX_DEPTH:
        raise Refuse("workspace_too_deep")
    try:
        names = sorted(os.listdir(dirfd))
    except OSError:
        raise Refuse("scan_incomplete") from None
    files, subdirs, names_of, owned = [], [], {}, set()
    try:
        for name in names:
            here = rel + "/" + name if rel else name
            if not include_protected and is_protected_name(name):
                count.protected.append(here)
                count.skipped += 1
                if len(count.protected) > MAX_PROTECTED:
                    raise Refuse("too_many_protected_files")
                got = _open_checked(dirfd, name, dev)          # take any sandbox access away from it too (best effort)
                if got is not None:
                    try:
                        apply([got[0]] if not got[1] else [], [got[0]] if got[1] else [], strip_only=True)
                    finally:
                        os.close(got[0])
                continue
            got = _open_checked(dirfd, name, dev)
            if got is None:
                count.skipped += 1
                continue
            count.entries += 1
            if count.entries > MAX_ENTRIES:
                os.close(got[0])
                raise Refuse("workspace_too_large")
            mine = os.fstat(got[0]).st_uid == os.geteuid()       # only the owner can change an ACL; the sandbox accounts repair their own
            if got[1]:
                subdirs.append(got[0])
                names_of[got[0]] = here
                if mine:
                    owned.add(got[0])
            elif mine:
                files.append(got[0])
            else:
                os.close(got[0])
            if len(files) >= BATCH:
                apply(files, [])
                for fd in files:
                    os.close(fd)
                files = []
        apply(files, [])
        for fd in subdirs:
            if fd in owned:
                apply([], [fd])
        for fd in subdirs:
            _walk(fd, dev, apply, count, names_of[fd], depth + 1, include_protected)
    finally:
        for fd in files + subdirs:
            try:
                os.close(fd)
            except OSError:
                pass


def _users(request):
    run_users, owner_user = request.get("run_users"), request.get("owner_user")
    if type(run_users) is not list or not run_users or len(run_users) > 8:
        raise Refuse("user_name_invalid")
    for u in list(run_users) + [owner_user]:
        if type(u) is not str or not _USER.fullmatch(u):
            raise Refuse("user_name_invalid")
    return run_users, owner_user


def _foreign(fds, ours):
    """The descriptors whose ACL already has a named user/group entry that is not one of ours. Adding our entries recalculates the ACL
    mask, which could widen what such an entry effectively allows, so those files are left exactly as they are (and stay closed to
    the sandbox)."""
    if not fds:
        return set()
    done = subprocess.run(["getfacl", "-p", "--"] + ["/proc/self/fd/%d" % fd for fd in fds], pass_fds=fds, capture_output=True, text=True,
                          env=_ENV, timeout=120, check=False)
    if done.returncode != 0:
        raise Refuse("could_not_read_permissions")
    flagged, current = set(), None
    for line in done.stdout.splitlines():
        if line.startswith("# file: /proc/self/fd/"):
            current = int(line.rsplit("/", 1)[1])
            continue
        parts = line.removeprefix("default:").split(":")
        if current is not None and len(parts) >= 3 and parts[0] in ("user", "group") and parts[1] != "" and not (parts[0] == "user" and parts[1] in ours):
            flagged.add(current)
    return flagged


def _granter(run_users, owner_user, left_alone):
    named = ",".join("u:%s:rwX" % u for u in run_users + [owner_user])
    drop = ",".join("u:%s" % u for u in run_users)
    ours = set(run_users) | {owner_user}

    def apply(files, dirs, strip_only=False):
        if strip_only:
            for group in (files, dirs):
                if group:
                    _setfacl(["-x", drop], group, ignore_failure=True)
            return
        odd = _foreign(files + dirs, ours)
        left_alone.extend(sorted(odd))
        files, dirs = [fd for fd in files if fd not in odd], [fd for fd in dirs if fd not in odd]
        if files:
            _setfacl(["-m", named], files)
        if dirs:
            _setfacl(["-m", named], dirs)
            # No default entry for the sandbox accounts, and nothing for "other": a file created here later is closed to them
            # until a job start has looked at it. The owner keeps access to whatever the sandbox creates.
            _setfacl(["-d", "-x", drop], dirs, ignore_failure=True)
            _setfacl(["-d", "-m", "u:%s:rwX,g::---,o::---" % owner_user], dirs)
    return apply


def _revoker(run_users):
    drop = ",".join("u:%s" % u for u in run_users)

    def apply(files, dirs, strip_only=False):
        if files:
            _setfacl(["-x", drop], files, ignore_failure=True)
        if dirs:
            _setfacl(["-x", drop], dirs, ignore_failure=True)
            _setfacl(["-k"], dirs, ignore_failure=True)
    return apply


def op_prepare(request):
    projects, home = request.get("projects"), request.get("home")
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


def block_devices(path, mountinfo="/proc/self/mountinfo"):
    """Whole-disk 'major:minor' strings under the file system holding ``path`` (so a write-rate limit can be set on them), or []."""
    try:
        best, source = "", None
        real = os.path.realpath(path)
        for line in open(mountinfo).read().splitlines():
            left, _, right = line.partition(" - ")
            fields, rfields = left.split(), right.split()
            mount = fields[4].replace("\\040", " ")
            if (real == mount or real.startswith(mount.rstrip("/") + "/")) and len(mount) >= len(best) and len(rfields) >= 2:
                best, source = mount, rfields[1]
        if not source or not source.startswith("/dev/"):
            return []
        return sorted(_whole_disks(os.stat(os.path.realpath(source)).st_rdev))
    except (OSError, ValueError, IndexError):
        return []


def _whole_disks(rdev, depth=0):
    found = set()
    if depth > 4:
        return found
    node = "/sys/dev/block/%d:%d" % (os.major(rdev), os.minor(rdev))
    real = os.path.realpath(node)
    if os.path.exists(os.path.join(real, "partition")):
        real = os.path.dirname(real)
    slaves = os.path.join(real, "slaves")
    inner = os.listdir(slaves) if os.path.isdir(slaves) else []
    if inner:
        for name in inner:
            try:
                found |= _whole_disks(os.stat("/dev/" + name).st_rdev, depth + 1)
            except OSError:
                continue
        return found
    try:
        found.add(open(os.path.join(real, "dev")).read().strip())
    except OSError:
        pass
    return found


def op_disk(request):
    path = request.get("path")
    _no_links(path)
    info = os.statvfs(path)
    return {"free": info.f_bavail * info.f_frsize, "total": info.f_blocks * info.f_frsize,
            "ifree": info.f_favail, "itotal": info.f_files, "devices": block_devices(path)}


def _open_root(path):
    fd = os.open(path, _DIR)
    return fd, os.fstat(fd)


def _sweep(request, create):
    run_users, owner_user = _users(request)
    path = _workspace(request, create=create)
    fd, info = _open_root(path)
    count = Counter()
    left_alone = []
    apply = _granter(run_users, owner_user, left_alone)
    try:
        apply([], [fd])
        _walk(fd, info.st_dev, apply, count)
    finally:
        os.close(fd)
    return {"path": path, "entries": count.entries + 1, "skipped": count.skipped + len(left_alone), "protected": count.protected,
            "left_alone": len(left_alone)}


def op_enroll(request):
    return _sweep(request, create=True)


def op_grant(request):
    """At every job start: look at everything that exists NOW, give the sandbox access to the ordinary parts, take it away from the
    protected names and report them (to be hidden by the sandbox). Incomplete = refusal."""
    return _sweep(request, create=False)


def op_unenroll(request):
    run_users, _ = _users({"run_users": request.get("run_users"), "owner_user": "x"})
    path = _workspace(request)
    fd, info = _open_root(path)
    count = Counter()
    apply = _revoker(run_users)
    try:
        apply([], [fd])
        _walk(fd, info.st_dev, apply, count, include_protected=True)
    finally:
        os.close(fd)
    return {"path": path}


def scan_protected(path):
    """Relative paths of protected names below ``path`` (folders are not entered). Raises Refuse if the scan cannot be completed."""
    fd, info = _open_root(path)
    count = Counter()
    try:
        _walk(fd, info.st_dev, lambda files, dirs, strip_only=False: None, count)
    finally:
        os.close(fd)
    return count.protected


def op_protected(request):
    path = _workspace(request)
    return {"path": path, "protected": scan_protected(path)}


def op_import_checkout(request):
    """Import the broker's exact bundle as the owner, without network or existing Git config."""
    if request.get("name") != repo_git.WORKSPACE:
        raise Refuse("git_workspace_not_bound")
    commit, digest = request.get("commit"), request.get("digest")
    if (type(commit) is not str or not re.fullmatch(r"[a-f0-9]{40}", commit)
            or type(digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", digest)):
        raise Refuse("checkout_binding_invalid")
    path = _workspace(request)
    if os.listdir(path):
        # A lost response may be retried, but occupied workspaces are never
        # inspected by Git with owner privileges or changed by this operation.
        raise Refuse("checkout_workspace_not_empty")
    try:
        data = repo_git.read_bundle(commit, digest, sys.stdin.buffer)
    except repo_git.WorkspaceError as error:
        raise Refuse(error.code) from None
    _materialize_checkout(request, path, commit, data, repo_git.ORIGIN)
    return {"workspace": repo_git.WORKSPACE, "repository": "bam5693/stynpilot", "commit": commit}


def _materialize_checkout(request, path, commit, data, origin, expected_tree=None, target_identity=None, provenance=None):
    with _checkout_scratch(request) as scratch:
        bundle = os.path.join(scratch, "checkout.bundle")
        with open(bundle, "xb") as output:
            output.write(data)
        del data
        target = os.path.join(scratch, "worktree")
        os.mkdir(target, 0o700)
        ref = repo_git.BUNDLE_REF
        command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                   "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", "-C", target]

        def git(*args):
            result = subprocess.run(command + list(args), env=repo_git._ENV, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=35, check=False)
            if result.returncode:
                raise Refuse("checkout_git_refused")
            return result.stdout

        try:
            git("init", "--quiet", "--template=")
            if git("bundle", "list-heads", bundle).splitlines() != [f"{commit} {ref}".encode("ascii")]:
                raise Refuse("checkout_commit_mismatch")
            git("fetch", "--no-tags", "--no-recurse-submodules", "--", bundle, ref)
            if git("rev-parse", "--verify", "FETCH_HEAD^{commit}").strip() != commit.encode("ascii"):
                raise Refuse("checkout_commit_mismatch")
            entries = git("ls-tree", "-rlz", commit).split(b"\0")[:-1]
            sizes = [entry.split(b"\t", 1)[0].split()[-1] for entry in entries]
            if (not entries or len(entries) > MAX_ENTRIES or any(not size.isdigit() for size in sizes)
                    or sum(map(int, sizes)) > (64 << 20)):
                raise Refuse("checkout_tree_exceeds_limits")
            if expected_tree is not None:
                if (git("rev-parse", commit + "^{tree}").strip() != expected_tree.encode("ascii")
                        or git("rev-list", "--count", commit).strip() != b"1"
                        or git("fsck", "--full", "--strict", "--unreachable", "--no-reflogs", commit).strip()):
                    raise Refuse("snapshot_history_or_tree_mismatch")
            git("checkout", "--quiet", "--detach", "--no-recurse-submodules", commit)
            if expected_tree is not None:
                for entry in entries:
                    meta, raw_path = entry.split(b"\t", 1)
                    mode, kind, oid, size = meta.split()
                    name = raw_path.decode("utf-8")
                    if (not archive_store._unprotected_path(name) or kind != b"blob"
                            or mode not in (b"100644", b"100755") or int(size) > deckplay_snapshot.MAX_BLOB):
                        raise Refuse("snapshot_path_refused")
                    file = os.path.join(target, name)
                    info = os.lstat(file)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != int(size):
                        raise Refuse("snapshot_worktree_changed")
                    with os.fdopen(os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
                        value = stream.read(int(size) + 1)
                    if (not deckplay_snapshot.path_admitted(expected_tree, name, value)
                            or deckplay_snapshot.content_refusal(value)):
                        raise Refuse("snapshot_content_refused")
                    digest = hashlib.sha1(b"blob " + size + b"\0" + value).hexdigest().encode("ascii")
                    if digest != oid or bool(info.st_mode & stat.S_IXUSR) != (mode == b"100755"):
                        raise Refuse("snapshot_worktree_changed")
            git("remote", "add", "origin", origin)
            if provenance is not None:
                # Fsync with the rest of the staged tree before the final rename.
                vault._write_atomic(Path(target) / ".git", "stynpilot-checkout.json",
                                    json.dumps(provenance, sort_keys=True).encode("ascii") + b"\n")
        except subprocess.SubprocessError:
            raise Refuse("checkout_git_timed_out") from None
        if target_identity is None:
            os.replace(target, path)
        else:
            if "dispatch" in request:
                _deckplay_client_active(request)
            _publish_deckplay(target, path, target_identity)


def _publish_deckplay(target, path, target_identity):
    parent_fd, parent_stat, original = target_identity
    name = os.path.basename(path)
    archive_store._sync_tree(target)
    # The original destination and its parent stay pinned across verification.
    # The kernel's final nonempty-directory check also covers a late file write.
    if (not os.path.samestat(os.lstat(os.path.dirname(path)), parent_stat)
            or not os.path.samestat(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), original)):
        raise Refuse("checkout_destination_changed")
    try:
        os.replace(target, name, dst_dir_fd=parent_fd)
    except OSError as error:
        if error.errno in (errno.ENOTEMPTY, errno.EEXIST):
            raise Refuse("checkout_workspace_not_empty") from None
        raise
    try:
        os.fsync(parent_fd)
    except OSError:
        # The replacement may already be visible. Never report that the
        # workspace is unchanged or try to remove the published tree here.
        raise Refuse("checkout_outcome_unverified") from None


def _checkout_slot(request):
    job = request.get("checkout_job")
    if type(job) is not str or not re.fullmatch(r"[a-f0-9]{32}", job):
        raise Refuse("deckplay_checkout_dispatch_invalid")
    return os.path.join(_projects(request), ".stynpilot-deckplay-checkout-" + job)


@contextmanager
def _checkout_scratch(request):
    if "checkout_job" not in request:
        with tempfile.TemporaryDirectory(prefix=".stynpilot-checkout-", dir=request["projects"]) as path:
            yield path
        return
    path = _checkout_slot(request)
    os.mkdir(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path)


def op_deckplay_checkout_cleanup(request):
    path = _checkout_slot(request)
    if os.path.lexists(path):
        info = _own_folder(path)
        if info.st_mode & 0o077 or not shutil.rmtree.avoids_symlink_attacks:
            raise Refuse("deckplay_checkout_dispatch_invalid")
        shutil.rmtree(path)
        vault._fsync_dir(os.path.dirname(path))
    return {"cleaned": True}


def _deckplay_archive(request):
    # Fixed default owner-state layout; no caller-specified path or URL.
    path = os.path.join(request["home"], ".local", "state", "stynpilot", "repository-archives")
    _no_links(path)
    _deckplay_client_active(request)
    return archive_store.Store(path)


def _deckplay_client_active(request):
    path = os.path.join(request["home"], ".local", "state", "stynpilot", "revoked-clients.json")
    try:
        if request["client"] in RevocationFile(path).revoked():
            raise Refuse("deckplay_checkout_client_revoked")
    except ClientDenied as error:
        raise Refuse(error.code) from None


def _deckplay_empty(request):
    if request.get("name") != repo_git.DECKPLAY_WORKSPACE:
        raise Refuse("git_workspace_not_bound")
    path = _workspace(request)
    if os.listdir(path):
        raise Refuse("checkout_workspace_not_empty")
    return path


def op_deckplay_snapshot_preview(request):
    _deckplay_empty(request)
    try:
        plan = deckplay_snapshot.review(_deckplay_archive(request), request["client"], request["archive_id"],
                                        request["ref"], request["commit"])
    except repo_archive.ArchiveError as error:
        raise Refuse(error.code) from None
    return {"plan": plan, "plan_sha256": deckplay_snapshot.plan_digest(plan)}


def op_deckplay_snapshot_checkout(request):
    path = _deckplay_empty(request)
    if request.get("dispatch") != "/run/stynpilot-deckplay-dispatch":
        raise Refuse("deckplay_checkout_dispatch_invalid")
    with open(request["dispatch"], "rb") as dispatch:
        if dispatch.read(66) != (request["plan_sha256"] + "\n").encode("ascii"):
            raise Refuse("deckplay_checkout_dispatch_invalid")
    return _deckplay_checkout(request, path)


def _deckplay_checkout(request, path):
    parent_fd, parent_stat = _open_root(os.path.dirname(path))
    try:
        fd = os.open(os.path.basename(path), _DIR, dir_fd=parent_fd)
        try:
            target_identity = parent_fd, parent_stat, os.fstat(fd)
            if os.listdir(fd):
                raise Refuse("checkout_workspace_not_empty")
            with deckplay_snapshot.stage(_deckplay_archive(request), request["client"], request["archive_id"],
                                          request["ref"], request["commit"], request["plan_sha256"]) as (bundle, receipt):
                with bundle.open("rb") as stream:
                    data = repo_git.read_bundle(receipt["snapshot_commit"], receipt["snapshot_bundle_sha256"], stream)
                _materialize_checkout(request, path, receipt["snapshot_commit"], data, repo_git.DECKPLAY_ORIGIN,
                                      expected_tree=receipt["source_tree"], target_identity=target_identity,
                                      provenance={key: receipt[key] for key in ("archive_id", "ref", "source_commit",
                                          "source_tree", "source_bundle_sha256", "plan_sha256", "snapshot_commit")})
        finally:
            os.close(fd)
    except (repo_archive.ArchiveError, repo_git.WorkspaceError) as error:
        raise Refuse(error.code) from None
    finally:
        os.close(parent_fd)
    return {"workspace": repo_git.DECKPLAY_WORKSPACE, "receipt": receipt}


OPS = {"prepare": op_prepare, "check": op_check, "home_names": op_home_names, "disk": op_disk, "enroll": op_enroll,
       "grant": op_grant, "unenroll": op_unenroll, "protected": op_protected, "import_checkout": op_import_checkout,
       "deckplay_snapshot_preview": op_deckplay_snapshot_preview, "deckplay_snapshot_checkout": op_deckplay_snapshot_checkout,
       "deckplay_checkout_cleanup": op_deckplay_checkout_cleanup}


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
