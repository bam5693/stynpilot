"""One fixed, networkless source test for a reviewed development lab artifact."""
from __future__ import annotations

import argparse
import os
import selectors
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from .dev_lab_policy import LabError, scenario_request
from .dev_lab_source import stage
from .redact import redact

TIMEOUT = 600
OUTPUT_LIMIT = 256 << 10
MEMORY_LIMIT = 2 << 30
TASK_LIMIT = 64
CPU_LIMIT = 2
_RECIPES = {
    "offline_normal": ["/usr/bin/python3", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                       "tests", "--ignore=tests/test_g7.py", "--ignore=tests/test_compat_check.py"],
}


def _require_containment():
    """Verify kernel limits before allocating a job or running project code."""
    try:
        own = Path("/proc/self/cgroup").read_text().splitlines()
        if len(own) != 1 or not own[0].startswith("0::/"):
            raise ValueError
        relative = own[0][4:]
        if not relative or any(component in ("", ".", "..") for component in relative.split("/")):
            raise ValueError
        group = Path("/sys/fs/cgroup") / relative
        memory = int((group / "memory.max").read_text())
        swap = int((group / "memory.swap.max").read_text())
        tasks = int((group / "pids.max").read_text())
        quota, period = map(int, (group / "cpu.max").read_text().split())
        if not (0 < memory <= MEMORY_LIMIT and swap == 0 and 0 < tasks <= TASK_LIMIT
                and 0 < quota <= CPU_LIMIT * period):
            raise ValueError
    except (OSError, ValueError):
        raise LabError("lab_worker_cgroup_not_bounded") from None


def _command(source, scenario):
    return [
        "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session",
        "--clearenv", "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/sbin", "/sbin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--ro-bind", "/etc/alternatives", "/etc/alternatives",
        "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--ro-bind", "/etc/os-release", "/etc/os-release",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run",
        "--size", str(256 << 20), "--tmpfs", "/tmp",
        "--ro-bind", str(source), "/work/src",
        "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", "C.UTF-8", "--setenv", "PYTHONPATH", "/work/src/src",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--setenv", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1",
        "--chdir", "/work/src", "--", *_RECIPES[scenario],
    ]


def _execute(argv, stop):
    deadline = time.monotonic() + TIMEOUT
    data = bytearray()
    with (subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           env={}, start_new_session=True) as child,
          selectors.DefaultSelector() as selector):
        selector.register(child.stdout, selectors.EVENT_READ)
        try:
            while True:
                if stop():
                    return "cancelled", None, b""
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "timeout", None, b""
                if selector.get_map():
                    if not selector.select(min(remaining, 0.1)):
                        continue
                    chunk = os.read(child.stdout.fileno(), min(65536, OUTPUT_LIMIT + 1 - len(data)))
                    if chunk:
                        data.extend(chunk)
                        if len(data) > OUTPUT_LIMIT:
                            # The log may end inside a credential. Discard it on overflow.
                            return "output_limit", None, b""
                        continue
                    selector.unregister(child.stdout)
                try:
                    code = child.wait(min(remaining, 0.1))
                except subprocess.TimeoutExpired:
                    continue
                return ("passed" if code == 0 else "failed"), code, data
        finally:
            if child.poll() is None:
                child.kill()


def run(archive, scratch_parent, commit, digest, scenario, *, stop=lambda: False):
    request = scenario_request(commit, scenario)
    if scenario not in _RECIPES:
        raise LabError("lab_scenario_not_implemented")
    if os.geteuid() == 0:
        raise LabError("lab_worker_must_be_unprivileged")
    _require_containment()
    parent = Path(scratch_parent).lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise LabError("lab_scratch_not_private")
    with tempfile.TemporaryDirectory(prefix="lab-job-", dir=scratch_parent) as scratch:
        if stop():
            return {**request, "state": "cancelled", "exit_code": None, "output": ""}
        source = stage(archive, scratch, commit, digest)
        state, code, raw = _execute(_command(source, scenario), stop)
    evidence, _ = redact(raw.decode("utf-8", "replace"))
    return {**request, "state": state, "exit_code": code, "output": evidence}


def main():
    """Local verification harness for the independently reviewed worker."""
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("commit")
    parser.add_argument("digest")
    parser.add_argument("scenario", choices=tuple(_RECIPES))
    args = parser.parse_args()
    cancelled = False

    def stop(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        result = run(args.archive, args.scratch, args.commit, args.digest, args.scenario, stop=lambda: cancelled)
    except (LabError, OSError, ValueError, EOFError, tarfile.TarError) as error:
        parser.exit(2, getattr(error, "code", "lab_worker_input_invalid") + "\n")
    print(json.dumps(result))
    return 0 if result["state"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
