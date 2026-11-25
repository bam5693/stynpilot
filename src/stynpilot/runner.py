"""S3a: the safety core of the sandboxed command runner. PURE POLICY: nothing here starts a process or touches the
machine. It decides (1) which folders may be workspaces, (2) which commands ("recipes") may run in them and with
which arguments, and (3) how the transient systemd unit that runs them is locked down.

Design rules (owner policy, master plan S3):
* Free-form commands NEVER run as the owner user and never as root. They run as the locked-down user ``stynpilot-run``
  inside a transient systemd unit started by the ROOT installer door (a later step, S3b). An AI never gets a shell.
* GREEN: a recipe (a named command family with validated arguments) inside an enrolled workspace. YELLOW: enrolling a
  workspace, and any one-off command that is not a recipe (the exact argv is shown and approved). BLACK: root commands,
  anything touching the owner's secrets or StyNpilot's own state.
* Everything the owner approves is exactly what runs: workspace paths must already be canonical (no symlink or ``..``
  tricks), arguments are validated one by one, argv is a LIST (no shell, no expansion), the environment is fixed.

What this module cannot prove by itself (verified on the real machine by the S3b self-test job, because they need the
real systemd): the unit properties below behave as documented; the file output route works under ProtectSystem=strict;
setfacl/ACLs are available on the workspace file system (the run user needs write access to files the OWNER owns, which
is granted by an ACL set at enrolment, never by widening the owner's own permissions).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import safefs

RUN_USER = "stynpilot-run"
MAX_ARGS, MAX_ARG_LEN = 12, 200
_PATH_CHARS = re.compile(r"[A-Za-z0-9._+/-]+")
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,60}")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,100}")
_EXPR = re.compile(r"[A-Za-z0-9_.() -]{1,100}")
_JOBS = re.compile(r"-j[0-9]{1,2}")
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
       "TERM": "dumb", "CI": "1", "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"}


class RunnerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------------------------------- workspaces
def check_workspace_text(path):
    """The purely lexical half of check_workspace (no file system access, so the root installer can run it with ProtectHome=yes)."""
    if type(path) is not str or not path or len(path) > 200 or not _PATH_CHARS.fullmatch(path) or not os.path.isabs(path):
        raise RunnerError("workspace_path_invalid")
    if os.path.normpath(path) != path or any(part.startswith(".") for part in path.split("/") if part):
        raise RunnerError("workspace_path_not_canonical_or_hidden")
    return path


def check_workspace(path, *, home, extra_deny=()):
    """The canonical real path of an acceptable workspace, or RunnerError. The path must ALREADY be canonical, so the
    folder the owner approves on the phone is byte-for-byte the folder commands will run in."""
    if type(path) is not str or not path or len(path) > 200 or not _PATH_CHARS.fullmatch(path) or not os.path.isabs(path):
        raise RunnerError("workspace_path_invalid")
    if os.path.normpath(path) != path or any(part.startswith(".") for part in path.split("/") if part):
        raise RunnerError("workspace_path_not_canonical_or_hidden")
    real = os.path.realpath(path)
    if real != path:
        raise RunnerError("workspace_path_is_or_contains_a_link")
    try:
        policy = safefs.Policy(home=home, roots=(), project_roots=[path], extra_deny=extra_deny)
        policy.location_ok(real)                                     # inside the home folder, not in a protected place
        for part in real[len(policy.home) + 1:].split("/"):
            policy.name_ok(part)                                     # no folder named like a credential store
    except (ValueError, safefs.FileDenied):
        raise RunnerError("workspace_not_allowed") from None
    info, home_info = os.stat(real), os.stat(policy.home)
    if info.st_uid != home_info.st_uid or info.st_mode & 0o002:
        raise RunnerError("workspace_must_belong_to_the_owner_and_not_be_world_writable")
    return real


# ------------------------------------------------------------------------------------------------------ arguments
def _relpath(value):
    """A path INSIDE the workspace, written relative to it. Lexical rules here; the S3b run step also resolves it."""
    if (not _PATH_CHARS.fullmatch(value) or value.startswith(("/", "-", ".")) or "//" in value
            or any(p in ("", "..") or p.startswith(".") for p in value.split("/"))):
        return False
    return True


def _resolved_inside(workspace, value):
    """If it exists, it must really live inside the workspace after symlinks are followed."""
    full = os.path.join(workspace, value)
    if not os.path.lexists(full):
        return True
    real = os.path.realpath(full)
    return real == workspace or real.startswith(workspace.rstrip("/") + "/")


@dataclass(frozen=True)
class Recipe:
    id: str
    title: str
    argv: tuple                       # fixed command and fixed arguments (absolute binary path)
    flags: frozenset = frozenset()    # exact optional flags
    flag_patterns: tuple = ()         # regexes for optional flags like -j4
    valued: tuple = ()                # (flag, kind) options that take one value; kind in word|module|expr|int|relpath
    positional: str = ""              # kind of free positional arguments: word|module|relpath|""
    max_extra: int = 8
    seconds: int = 600
    memory_mb: int = 2048
    tasks: int = 256
    writes: bool = True               # may the command write inside the workspace (ProtectSystem + ReadWritePaths)


_GIT = ("/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
        "-c", "protocol.allow=never", "-c", "core.pager=cat")
RECIPES = {r.id: r for r in (
    Recipe("python-unittest", "Python unittest", ("/usr/bin/python3", "-m", "unittest"),
           flags=frozenset({"-v", "-q", "-b", "-f"}), valued=(("-s", "relpath"), ("-t", "relpath"), ("-k", "expr")),
           positional="module"),
    Recipe("pytest", "pytest", ("/usr/bin/python3", "-m", "pytest", "-p", "no:cacheprovider"),
           flags=frozenset({"-q", "-v", "-x", "-s", "--tb=short", "--tb=line", "--tb=no"}), valued=(("-k", "expr"), ("--maxfail", "int")),
           positional="relpath"),
    Recipe("make", "make", ("/usr/bin/make",), flags=frozenset({"-k", "-n", "-s"}), flag_patterns=(_JOBS,), positional="word"),
    Recipe("npm-test", "npm test", ("/usr/bin/npm", "test"), max_extra=0),
    Recipe("cargo-test", "cargo test", ("/usr/bin/cargo", "test", "--offline"), flags=frozenset({"-q", "--release"}), positional="word"),
    Recipe("ruff-check", "ruff check", ("/usr/bin/ruff", "check", "--no-cache"), flags=frozenset({"--statistics"}),
           positional="relpath", seconds=300, writes=False),
    Recipe("git-status", "git status", _GIT + ("status", "--short", "--branch"), max_extra=0, seconds=60, writes=False),
    Recipe("git-diff", "git diff", _GIT + ("diff", "--no-ext-diff", "--no-textconv"),
           flags=frozenset({"--stat", "--cached", "--name-only"}), positional="relpath", seconds=60, writes=False),
    Recipe("git-log", "git log", _GIT + ("log", "--no-ext-diff", "--no-textconv"),
           flags=frozenset({"--oneline", "--stat"}), valued=(("-n", "int"),), seconds=60, writes=False),
)}


def _ok_value(kind, value, workspace):
    if kind == "word":
        return bool(_WORD.fullmatch(value))
    if kind == "module":
        return bool(_MODULE.fullmatch(value))
    if kind == "expr":
        return bool(_EXPR.fullmatch(value)) and not value.startswith("-")
    if kind == "int":
        return value.isdigit() and 0 < int(value) <= 50 and len(value) <= 2
    if kind == "relpath":
        return _relpath(value) and _resolved_inside(workspace, value)
    return False


def build_argv(recipe_id, args, workspace):
    """The exact argv list for a recipe, or RunnerError. Unknown flags, option-like words, path tricks and extra
    arguments are all refused; there is no shell and no variable expansion anywhere."""
    recipe = RECIPES.get(recipe_id) if type(recipe_id) is str else None
    if recipe is None:
        raise RunnerError("unknown_recipe")
    if type(args) not in (list, tuple) or len(args) > min(recipe.max_extra, MAX_ARGS):
        raise RunnerError("too_many_arguments")
    for a in args:
        if type(a) is not str or not a or len(a) > MAX_ARG_LEN or any(ord(c) < 32 or ord(c) == 127 for c in a):
            raise RunnerError("argument_invalid")
    out, i, valued = list(recipe.argv), 0, dict(recipe.valued)
    if out[0] == "/usr/bin/git":
        # The folder belongs to the owner and git runs as the locked-down account: git refuses that ("dubious
        # ownership") unless THIS folder, which the owner authorized, is named as safe on the command line.
        out[1:1] = ["-c", "safe.directory=" + workspace]
    while i < len(args):
        a = args[i]
        if a in recipe.flags or any(p.fullmatch(a) for p in recipe.flag_patterns):
            out.append(a)
        elif a in valued:
            if i + 1 >= len(args) or not _ok_value(valued[a], args[i + 1], workspace):
                raise RunnerError("argument_refused")
            out += [a, args[i + 1]]
            i += 1
        elif recipe.positional and not a.startswith("-") and _ok_value(recipe.positional, a, workspace):
            out.append(a)
        else:
            raise RunnerError("argument_refused")
        i += 1
    return tuple(out)


# ------------------------------------------------------------------------------------------------- the sandbox
HIDDEN_PATHS = ("/etc/stynpilot", "/var/lib/stynpilot", "/var/lib/stynpilot-installer", "/run/stynpilot", "/root",
                "/boot", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssl/private",
                "/var/lib/tailscale", "/run/user", "/run/dbus", "/run/systemd/private")


FSIZE_MB = 512          # largest single file a job may write (RLIMIT_FSIZE)
TMP_MB = 256            # size of the private /tmp (a memory-backed file system, so it can never fill the disk)
RUN_MB = 8
IO_WRITE_BPS = 64 * 1024 * 1024    # EXACT bytes per second ceiling per disk (systemd reads a "64M" suffix as 64,000,000, so a plain byte count is used everywhere:
                                   # unit, self-test and disk reserve). Bounds how far the disk can fill between two watchdog checks


RESOLVER_FILE = "/run/systemd/resolve/stub-resolv.conf"


def unit_command(job_id, argv, workspace, *, seconds, memory_mb, tasks, writes=True, network=False, run_user=RUN_USER, masked=(), io_devices=(), resolver=False):
    """The ``systemd-run`` argv list that runs ``argv`` in ``workspace`` as ``run_user`` with the sandbox below. A LIST, so
    nothing is ever parsed by a shell; every value that varies is validated here, and property values never contain
    separators that systemd would interpret."""
    if type(job_id) is not str or not re.fullmatch(r"[0-9a-f]{16,32}", job_id):
        raise RunnerError("job_id_invalid")
    if not _PATH_CHARS.fullmatch(workspace) or not os.path.isabs(workspace) or ".." in workspace.split("/"):
        raise RunnerError("workspace_path_invalid")
    for number in (seconds, memory_mb, tasks):
        if type(number) is not int or not 0 < number <= 86400:
            raise RunnerError("limit_invalid")
    if not argv or any(type(a) is not str or "\x00" in a for a in argv) or not os.path.isabs(argv[0]):
        raise RunnerError("argv_invalid")
    for m in masked:
        if type(m) is not str or not _PATH_CHARS.fullmatch(m) or not m.startswith(workspace + "/") or ".." in m.split("/"):
            raise RunnerError("protected_path_unsafe")
    for dev in io_devices:
        if type(dev) is not str or not re.fullmatch(r"[0-9]{1,4}:[0-9]{1,7}", dev):
            raise RunnerError("io_device_invalid")
    props = [
        "User=" + run_user, "Group=" + run_user, "SupplementaryGroups=",
        "WorkingDirectory=" + workspace,
        # who it can see and touch
        "ProtectSystem=strict", "ProtectHome=tmpfs", "BindPaths=" + workspace if writes else "BindReadOnlyPaths=" + workspace,
        "TemporaryFileSystem=/tmp:mode=1777,nosuid,nodev,size=%dM" % TMP_MB, "TemporaryFileSystem=/run:mode=0755,nosuid,nodev,size=%dM" % RUN_MB,
        "PrivateDevices=yes", "ProtectProc=invisible", "ProcSubset=pid", "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes", "ProtectClock=yes",
        "ProtectHostname=yes", "InaccessiblePaths=" + " ".join("-" + p for p in HIDDEN_PATHS + tuple(masked)),
        # what it can do
        "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictSUIDSGID=yes",
        "RestrictNamespaces=yes", "LockPersonality=yes", "RestrictRealtime=yes",
        "SystemCallArchitectures=native", "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources",
        "UMask=0077", "LimitCORE=0", "LimitNOFILE=1024", "LimitFSIZE=%dM" % FSIZE_MB, "KeyringMode=private",
        # network: none by default (a separate YELLOW grant would be needed)
        "PrivateNetwork=yes" if not network else "PrivateNetwork=no",
        "RestrictAddressFamilies=AF_UNIX" if not network else "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        # how much it can use
        "RuntimeMaxSec=%d" % seconds, "MemoryMax=%dM" % memory_mb, "MemorySwapMax=0", "TasksMax=%d" % tasks, "CPUQuota=200%",
        "KillMode=control-group", "TimeoutStopSec=5",
    ] + ["IOWriteBandwidthMax=/dev/block/%s %d" % (dev, IO_WRITE_BPS) for dev in io_devices]
    if network and resolver:
        # /etc/resolv.conf is a link into /run, which this sandbox replaces with an empty tmpfs; without this the unit has network but
        # cannot resolve a name. Expose ONLY that one read-only file (never the /run/systemd/resolve folder, which holds sockets).
        props.append("BindReadOnlyPaths=-" + RESOLVER_FILE)
    cmd = ["systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit", "stynpilot-job-" + job_id]
    for p in props:
        cmd += ["-p", p]
    for k, v in ENV.items():
        cmd += ["--setenv=%s=%s" % (k, v)]
    return cmd + ["--"] + list(argv)
