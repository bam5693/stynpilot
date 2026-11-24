"""Live sandbox confinement self-test (GREEN: fixed probes, no inputs from any AI, nothing outside a scratch folder).

It runs a fixed probe program INSIDE the same sandbox the real jobs use, then judges what the probe saw. General job
execution stays closed until every REQUIRED check passes for this exact StyNpilot version; an upgrade closes the gate
again until the test is re-run. A failing or unreadable result keeps the gate closed (fail closed).

The probe prints only ``PASS|FAIL|SKIP <check>`` lines: no paths, no file contents.
"""
from __future__ import annotations

import json
import os
import pwd
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .. import runner

REQUIRED = ("identity", "no_capabilities", "no_new_privs", "hidden_paths", "home_invisible", "network_isolated",
            "writes_confined", "workspace_writable", "owner_edits_runner_files")
OPTIONAL = ("limits",)               # must match when readable; "unverified" when the kernel does not show it
TASKS, MEMORY_MB, SECONDS = 64, 256, 40

PROBE = r'''
import json, os, pwd, socket, sys
c = json.loads(sys.argv[1])
def say(ok, name):
    print(("PASS " if ok else "FAIL ") + name, flush=True)
def status():
    d = {}
    for line in open("/proc/self/status"):
        k, _, v = line.partition(":")
        d[k] = v.strip()
    return d
st = status()
try:
    me = pwd.getpwuid(os.getuid()).pw_name
except KeyError:
    me = "?"
say(os.getuid() == os.geteuid() == c["run_uid"] and me == c["run_user"] and os.getgid() == c["run_gid"]
    and os.getuid() not in (0, c["owner_uid"]) and set(os.getgroups()) <= {c["run_gid"]}, "identity")
say(all(int(st.get(k, "1"), 16) == 0 for k in ("CapEff", "CapPrm", "CapBnd", "CapAmb")), "no_capabilities")
say(st.get("NoNewPrivs") == "1", "no_new_privs")
def reads(path):
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            open(path, "rb").read(1)
        return True
    except OSError:
        return False
say(not any(reads(p) for p in c["hidden"]), "hidden_paths")
ws_parts = set(c["ws"].split("/"))
leaks = [n for n in c["home_names"] if n not in ws_parts and os.path.lexists(os.path.join(c["home"], n))]
say(not leaks, "home_invisible")
def connects(family, address):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(address)
        return True
    except OSError:
        return False
    finally:
        s.close()
def tcp(address):
    try:
        return connects(socket.AF_INET, address)
    except OSError:
        return False
say(not tcp(("127.0.0.1", c["port"])) and not tcp(("1.1.1.1", 53)), "network_isolated")
def writes(path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(path)
        return True
    except OSError:
        return False
say(not any(writes(os.path.join(d, ".stynpilot-selftest")) for d in c["no_write"]), "writes_confined")
mine = os.path.join(c["ws"], "probe.txt")
try:
    with open(mine, "w") as handle:
        handle.write("probe")
    ok = os.stat(mine).st_uid == c["run_uid"]
except OSError:
    ok = False
say(ok, "workspace_writable")
try:
    cg = open("/proc/self/cgroup").read().strip().split("::", 1)[1]
    base = "/sys/fs/cgroup" + cg
    pids, mem = open(base + "/pids.max").read().strip(), open(base + "/memory.max").read().strip()
    print(("PASS " if pids == str(c["tasks"]) and mem == str(c["memory_mb"] * 1024 * 1024) else "FAIL ") + "limits", flush=True)
except (OSError, IndexError):
    print("SKIP limits", flush=True)
'''


def _owner_can_edit(path, uid, gid):
    """As the OWNER (a real uid drop, no groups): can the file the sandbox made be read and rewritten?"""
    code = ("import sys\nwith open(sys.argv[1], 'r+') as f:\n    f.read()\n    f.seek(0)\n    f.write('owner-edit')\n")
    done = subprocess.run(["setpriv", "--reuid=%d" % uid, "--regid=%d" % gid, "--clear-groups", "--", "python3", "-I", "-c", code, path],
                          capture_output=True, timeout=30, check=False, env={"PATH": "/usr/bin:/bin"})
    return done.returncode == 0


def _judge(lines, owner_ok):
    seen = {}
    for line in lines:
        word, _, name = line.strip().partition(" ")
        if word in ("PASS", "FAIL", "SKIP") and name in REQUIRED + OPTIONAL:
            seen[name] = word
    seen["owner_edits_runner_files"] = "PASS" if owner_ok else "FAIL"
    passed = sorted(n for n, w in seen.items() if w == "PASS")
    failed = sorted([n for n in REQUIRED if seen.get(n) != "PASS"] + [n for n in OPTIONAL if seen.get(n) == "FAIL"])
    unverified = sorted(n for n in OPTIONAL if seen.get(n) in (None, "SKIP"))
    return {"ok": not failed, "passed": passed, "failed": failed, "unverified": unverified}


def run_selftest(jr, *, timeout=60):
    """Run the live confinement test. Always records the outcome; only a full pass opens the gate."""
    from .jobs import JobError, _write_json
    if not jr.enabled():
        raise JobError("runner_not_set_up")
    uid, gid = jr.ensure_user()
    owner = pwd.getpwuid(jr.owner_uid)
    root = Path(jr.selftest_root)
    root.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chmod(root, 0o755)
    scratch = root / "selftest"
    if scratch.is_symlink() or scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True) if not scratch.is_symlink() else scratch.unlink()
    scratch.mkdir(mode=0o700)
    os.chown(scratch, owner.pw_uid, owner.pw_gid)
    ws = str(os.path.realpath(scratch))
    spec = "u:%s:rwX,u:%s:rwX" % (jr.run_user, owner.pw_name)
    jr._acl_scratch(ws, spec)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    try:
        try:
            home_names = jr._ask("home_names")["names"]            # listed by the owner-side helper: root cannot see the home folder
        except Exception:
            home_names = []
        config = {"run_user": jr.run_user, "run_uid": uid, "run_gid": gid, "owner_uid": jr.owner_uid, "ws": ws,
                  "hidden": [p for p in runner.HIDDEN_PATHS + getattr(jr.backend, "extra_hidden", ()) if os.path.lexists(p)],
                  "home": jr.home, "home_names": home_names, "port": listener.getsockname()[1],
                  "no_write": ["/etc", "/usr", "/var/lib", "/opt", "/srv", jr.home, str(jr.dir), "/root"], "tasks": TASKS, "memory_mb": MEMORY_MB}
        lines, job_status, started = [], None, time.time()
        try:
            job = jr._start(ws, "selftest", [jr.python, "-I", "-c", PROBE, json.dumps(config)],
                            {"seconds": SECONDS, "memory_mb": MEMORY_MB, "tasks": TASKS, "writes": True}, SECONDS, need_enrolled=False)
            job_status = jr.wait(job["job_id"], timeout)
            try:
                lines = (jr.dir / "jobs" / job["job_id"] / "out.log").read_text(errors="replace").splitlines()
            except OSError:
                lines = []
        except (JobError, runner.RunnerError, OSError):
            lines = []
        owner_ok = False
        probe_file = os.path.join(ws, "probe.txt")
        if os.path.isfile(probe_file) and not os.path.islink(probe_file):
            try:
                owner_ok = _owner_can_edit(probe_file, owner.pw_uid, owner.pw_gid)
            except (OSError, subprocess.SubprocessError):
                owner_ok = False
        verdict = _judge(lines, owner_ok)
        if not job_status or job_status.get("state") != "done":
            verdict["ok"], verdict["failed"] = False, sorted(set(verdict["failed"]) | {"probe_did_not_finish_cleanly"})
        verdict.update({"version": jr.version, "at": int(time.time()), "ran": True, "seconds": round(time.time() - started, 1)})
        _write_json(jr._selftest_file, verdict)
        return verdict
    finally:
        listener.close()
        shutil.rmtree(scratch, ignore_errors=True)
