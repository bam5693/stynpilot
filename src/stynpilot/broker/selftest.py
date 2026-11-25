"""Live sandbox confinement self-test (GREEN: fixed probes, no inputs from any AI, nothing outside a scratch folder).

It runs a fixed probe program INSIDE the same sandbox the real jobs use, then judges what the probe saw. General job
execution stays closed until every REQUIRED check passes for this exact StyNpilot version; an upgrade closes the gate
again until the test is re-run. A failing or unreadable result keeps the gate closed (fail closed).

The probe prints only ``PASS|FAIL|SKIP <check>`` lines: no paths, no file contents.
"""
from __future__ import annotations

import glob
import json
import os
import pwd
import shutil
import socket
import subprocess
import re
import threading
import time
from pathlib import Path

from .. import runner

REQUIRED = ("identity", "no_capabilities", "no_new_privs", "hidden_paths", "home_invisible", "network_isolated",
            "writes_confined", "workspace_writable", "owner_edits_runner_files", "credentials_masked", "host_sockets_hidden", "new_files_isolated", "other_jobs_isolated")
OPTIONAL = ("limit_pids", "limit_memory", "limit_fsize", "limit_tmp", "limit_io")              # must match when readable; REQUIRED (fails if unseen) on a backend that enforces limits
SOCKET_GLOBS = ("/run/*.sock", "/run/*/*.sock", "/run/dbus/system_bus_socket", "/run/systemd/private", "/run/systemd/*/private",
                "/run/user/*/bus", "/run/user/*/*/bus", "/var/run/docker.sock", "/run/containerd/containerd.sock")
TASKS, MEMORY_MB, SECONDS = 64, 256, 40
DIAG_NAMES = OPTIONAL + ("cgroup_path", "limits_unreadable")

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
say(c["canaries"] and not any(reads(p) for p in c["canaries"]), "credentials_masked")
def unix(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(path)
        return True
    except OSError:
        return False
    finally:
        s.close()
say(not any(unix(p) for p in c["sockets"]), "host_sockets_hidden")
import time
def other_jobs():
    # a job running AT THE SAME TIME under another account, in another workspace: neither its folder (hidden), nor its processes'
    # view of the file system (/proc/<pid>/root), nor its files may be reachable from here
    if reads(c["decoy_ws"] + "/" + c["decoy_name"]):
        return False
    for pid in os.listdir("/proc"):
        if pid.isdigit() and int(pid) != os.getpid():
            try:
                open("/proc/%s/root%s/%s" % (pid, c["decoy_ws"], c["decoy_name"]), "rb").read(1)
                return False
            except OSError:
                pass
    return True
say(other_jobs(), "other_jobs_isolated")
def new_files():
    # files created in the workspace AFTER this job started (by the owner, whatever their name or mode) must be closed to it
    end = time.time() + 25
    while time.time() < end and c["late"][0] not in os.listdir(c["ws"]):
        time.sleep(0.2)
    return c["late"][0] in os.listdir(c["ws"]) and not any(reads(os.path.join(c["ws"], n)) for n in c["late"])
say(new_files(), "new_files_isolated")
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
    fd = os.open(mine, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)      # 0600 on purpose: the owner must still be able to edit it
    os.write(fd, b"probe")
    os.close(fd)
    ok = os.stat(mine).st_uid == c["run_uid"]
except OSError:
    ok = False
say(ok, "workspace_writable")
def diag(name, expected, actual):
    text = "%s %s %s" % (name, str(expected).replace(" ", "_"), str(actual).replace(" ", "_").replace("\n", ";"))
    print("DIAG " + text[:300], flush=True)
def limit(ok, name, expected, actual):
    say(ok, name)
    diag(name, expected, actual)
def readable(path):
    try:
        return open(path).read().strip()
    except OSError as e:
        return "unreadable:" + type(e).__name__
cg_text = readable("/proc/self/cgroup")
base = "/sys/fs/cgroup" + cg_text.split("::", 1)[1] if "::" in cg_text else ""
diag("cgroup_path", "-", (cg_text.split("::", 1)[1] if "::" in cg_text else cg_text).replace("/", ":"))
pids = readable(base + "/pids.max") if base else "no_cgroup"
mem = readable(base + "/memory.max") if base else "no_cgroup"
if pids.startswith(("unreadable", "no_cgroup")) and mem.startswith(("unreadable", "no_cgroup")):
    print("SKIP limits", flush=True)
    diag("limits_unreadable", "-", pids)
else:
    limit(pids == str(c["tasks"]), "limit_pids", c["tasks"], pids)
    limit(mem == str(c["memory_mb"] * 1024 * 1024), "limit_memory", c["memory_mb"] * 1024 * 1024, mem)
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit(soft == c["fsize"] and hard == c["fsize"], "limit_fsize", c["fsize"], "%s/%s" % (soft, hard))
    sv = os.statvfs("/tmp")
    size = sv.f_blocks * sv.f_frsize
    limit(size <= c["tmp_bytes"] if c["tmp_bytes"] else True, "limit_tmp", c["tmp_bytes"], size)
    if c["io_devs"]:
        text = readable(base + "/io.max")
        found = [l for l in text.splitlines() if l]
        ok = all(any(l.startswith(d + " ") and ("wbps=%d" % c["wbps"]) in l for l in found) for d in c["io_devs"])
        limit(ok, "limit_io", ",".join(c["io_devs"]) + ":wbps=%d" % c["wbps"], "|".join(l.split(" rbps")[0] + ":" + [w for w in l.split() if w.startswith("wbps=")][0] if "wbps=" in l else l[:40] for l in found) or text[:80])
    else:
        diag("limit_io", "no_device", "skipped")
'''


def _owner_can_edit(path, uid, gid):
    """As the OWNER (a real uid drop, no groups): can the file the sandbox made be read and rewritten?"""
    code = ("import sys\nwith open(sys.argv[1], 'r+') as f:\n    f.read()\n    f.seek(0)\n    f.write('owner-edit')\n")
    done = subprocess.run(["setpriv", "--reuid=%d" % uid, "--regid=%d" % gid, "--clear-groups", "--", "python3", "-I", "-c", code, path],
                          capture_output=True, timeout=30, check=False, env={"PATH": "/usr/bin:/bin"})
    return done.returncode == 0


_TOK = r"(?:[A-Za-z0-9_:=,.|;\-]|(?<=[0-9])/(?=[0-9-]))"          # a "/" is allowed only after a digit and before a digit or "-" (soft/hard limits), never a path
_DIAG = re.compile(r"DIAG ([a-z_]{1,32}) (" + _TOK + r"{1,80}) (" + _TOK + r"{0,200})")


def clean_diagnostics(raw):
    """Re-validate diagnostics wherever they cross a boundary: known check names, short safe tokens only, bounded count."""
    out = {}
    if isinstance(raw, dict):
        for name, pair in raw.items():
            if name in DIAG_NAMES and isinstance(pair, dict) and len(out) < 24:
                text = "DIAG %s %s %s" % (name, pair.get("expected"), pair.get("actual"))
                got = _DIAG.fullmatch(text)
                if got:
                    out[name] = {"expected": got.group(2), "actual": got.group(3)}
    return out


def _judge(lines, owner_ok, strict_limits=False):
    seen, diagnostics = {}, {}
    for line in lines:
        line = line.strip()
        word, _, name = line.partition(" ")
        if word == "SKIP" and name == "limits":                     # the cgroup files were not readable at all
            for n in OPTIONAL:
                seen.setdefault(n, "SKIP")
        if word in ("PASS", "FAIL", "SKIP") and name in REQUIRED + OPTIONAL:
            seen[name] = word
        got = _DIAG.fullmatch(line)
        if got and got.group(1) in DIAG_NAMES and len(diagnostics) < 24:
            diagnostics[got.group(1)] = {"expected": got.group(2), "actual": got.group(3)}          # numbers and short tokens only
    seen["owner_edits_runner_files"] = "PASS" if owner_ok else "FAIL"
    passed = sorted(n for n, w in seen.items() if w == "PASS")
    need = REQUIRED + (OPTIONAL if strict_limits else ())
    failed = sorted({n for n in need if seen.get(n) != "PASS"} | {n for n in OPTIONAL if seen.get(n) == "FAIL"})
    # A limit that could not be SEEN is "unverified" in every mode; under systemd (strict) it ALSO fails the gate.
    unverified = sorted(n for n in OPTIONAL if seen.get(n) in (None, "SKIP"))
    if "limit_io" in OPTIONAL and strict_limits and "limit_io" in failed and diagnostics.get("limit_io", {}).get("expected") == "no_device":
        failed.remove("limit_io")                                   # no resolvable disk: the start gate already refuses jobs (fail closed)
    return {"ok": not failed, "passed": passed, "failed": failed, "unverified": unverified, "diagnostics": clean_diagnostics(diagnostics)}


def _create_late_files(ws, uid, gid, delay):
    """After the probe has started: the OWNER (a real uid drop) creates a credential-named file and an ordinary one, world-readable by
    mode, in the probe's workspace. The sandbox must not be able to read either (nothing was granted for them)."""
    time.sleep(delay)
    code = ("import os, sys\nfor n in ('late.txt', 'late.env'):\n"
            "    fd = os.open(os.path.join(sys.argv[1], n), os.O_WRONLY | os.O_CREAT, 0o644)\n    os.write(fd, b'late')\n    os.close(fd)\n")
    subprocess.run(["setpriv", "--reuid=%d" % uid, "--regid=%d" % gid, "--clear-groups", "--", "python3", "-I", "-c", code, ws],
                   capture_output=True, timeout=30, check=False, env={"PATH": "/usr/bin:/bin"})


def run_selftest(jr, *, timeout=60):
    """Run the live confinement test. Always records the outcome; only a full pass opens the gate."""
    from .. import projects_helper
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
    jr._acl_scratch(ws)
    # Canaries: credential-looking files that are WORLD-READABLE (0666), the case an ACL "skip" does not protect against.
    os.makedirs(os.path.join(ws, ".ssh"), mode=0o777)
    os.makedirs(os.path.join(ws, ".stynpilot-trash"), mode=0o777)
    for rel in (".env", ".ssh/id_ed25519", ".stynpilot-trash/old.txt"):
        full = os.path.join(ws, rel)
        with open(full, "w") as handle:
            handle.write("canary")
        os.chmod(full, 0o666)
    for rel in (".ssh", ".stynpilot-trash"):
        os.chmod(os.path.join(ws, rel), 0o777)
    # A second workspace used by a job running AT THE SAME TIME under the other sandbox account. It lives inside the probe's own
    # workspace but is hidden from it, so the only ways to reach it are the ones this test is about (another job's /proc view).
    decoy = os.path.join(ws, "decoy")
    os.mkdir(decoy, 0o755)
    jr._acl_scratch(decoy)
    with open(os.path.join(decoy, "decoy.txt"), "w") as handle:
        handle.write("decoy")
    os.chmod(os.path.join(decoy, "decoy.txt"), 0o644)
    try:
        found = projects_helper.scan_protected(ws)
        masked = jr._safe_masked(ws, [ws + "/" + n for n in found] + [decoy])
    except projects_helper.Refuse as refused:
        raise JobError("selftest_scan_incomplete_" + str(refused)) from None
    canaries = [ws + "/.env", ws + "/.ssh/id_ed25519", ws + "/.stynpilot-trash/old.txt"]
    sockets = sorted({p for g in SOCKET_GLOBS for p in glob.glob(g)} | set(getattr(jr.backend, "extra_sockets", ())))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    decoy_job = None
    try:
        try:
            home_names = jr._ask("home_names")["names"]            # listed by the owner-side helper: root cannot see the home folder
        except Exception:
            home_names = []
        strict = bool(getattr(jr.backend, "enforces_limits", False))
        io_devs = projects_helper.block_devices(ws) if strict else []
        config = {"run_user": jr.pool[0], "run_uid": uid, "run_gid": gid, "owner_uid": jr.owner_uid, "ws": ws,
                  "hidden": [p for p in runner.HIDDEN_PATHS + getattr(jr.backend, "extra_hidden", ()) if os.path.lexists(p)],
                  "home": jr.home, "home_names": home_names, "port": listener.getsockname()[1],
                  "no_write": ["/etc", "/usr", "/var/lib", "/opt", "/srv", jr.home, str(jr.dir), "/root"], "tasks": TASKS, "memory_mb": MEMORY_MB,
                  "canaries": canaries, "sockets": sockets, "fsize": runner.FSIZE_MB * 1024 * 1024, "tmp_bytes": runner.TMP_MB * 1024 * 1024 + 4096,
                  "decoy_ws": decoy, "decoy_name": "decoy.txt", "late": ["late.txt", "late.env"],
                  "io_devs": io_devs, "wbps": runner.IO_WRITE_BPS}
        lines, job_status, started, start_error = [], None, time.time(), None
        try:
            limits = {"seconds": SECONDS, "memory_mb": MEMORY_MB, "tasks": TASKS, "writes": True}
            decoy_job = jr._start(decoy, "selftest", [jr.python, "-I", "-c", "import time; print('READY', flush=True); time.sleep(120)"],
                                  limits, SECONDS + 100, need_enrolled=False, masked=[], run_user=jr.pool[1])
            ready = False
            for _ in range(100):
                try:
                    ready = "READY" in (jr.dir / "jobs" / decoy_job["job_id"] / "out.log").read_text(errors="replace")
                except OSError:
                    ready = False
                if ready:
                    break
                time.sleep(0.1)
            if not ready:
                raise JobError("selftest_decoy_did_not_start")
            late = threading.Thread(target=_create_late_files, args=(ws, owner.pw_uid, owner.pw_gid, 1.5), daemon=True)
            late.start()
            job = jr._start(ws, "selftest", [jr.python, "-I", "-c", PROBE, json.dumps(config)], limits, SECONDS,
                            need_enrolled=False, masked=masked, run_user=jr.pool[0])
            job_status = jr.wait(job["job_id"], timeout)
            late.join(5)
            try:
                lines = (jr.dir / "jobs" / job["job_id"] / "out.log").read_text(errors="replace").splitlines()
            except OSError:
                lines = []
        except (JobError, runner.RunnerError, OSError) as stopped:
            lines, start_error = [], str(getattr(stopped, "code", type(stopped).__name__))[:80]
        owner_ok = False
        probe_file = os.path.join(ws, "probe.txt")
        if os.path.isfile(probe_file) and not os.path.islink(probe_file):
            try:
                owner_ok = _owner_can_edit(probe_file, owner.pw_uid, owner.pw_gid)
            except (OSError, subprocess.SubprocessError):
                owner_ok = False
        verdict = _judge(lines, owner_ok, strict_limits=strict)
        if not job_status or job_status.get("state") != "done":
            verdict["ok"], verdict["failed"] = False, sorted(set(verdict["failed"]) | {"probe_did_not_finish_cleanly"})
        if start_error:
            verdict["failed"] = sorted(set(verdict["failed"]) | {"could_not_run_probe_" + start_error})
        verdict.update({"version": jr.version, "at": int(time.time()), "ran": True, "seconds": round(time.time() - started, 1)})
        _write_json(jr._selftest_file, verdict)
        return verdict
    finally:
        if decoy_job is not None:
            try:
                jr.cancel(decoy_job["job_id"])
                jr.wait(decoy_job["job_id"], 15)
            except JobError:
                pass
        listener.close()
        shutil.rmtree(scratch, ignore_errors=True)
