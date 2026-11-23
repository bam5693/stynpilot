#!/usr/bin/env python3
"""G8 rehearsal in a disposable Ubuntu 26.04 VM (QEMU; free; no root on the host needed except to build the image).

Real systemd as PID 1, real polkit with its text agent on the owner's serial login (a real local, active session), real
apt, the real root installer. Only the OpenID provider is a test double (payload/fake_idp.py): the real passkey/Face ID
step is NOT simulated here and is verified on the real machine (see docs/G8_PLAN.md).

Usage: run_vm_test.py --base base.img --kernel vmlinuz --initrd initrd.img --deb stynpilot.deb --work DIR [--scenario all]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

import pexpect

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = []


def record(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    shown = str(detail)[-1500:] if not ok else str(detail)[:400]
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + shown) if detail else ""), flush=True)


class Serial:
    """The VM's console. A reader thread drains it continuously (otherwise QEMU stalls on a full pipe); expect() then
    searches what has arrived so far, like pexpect but never blocking the VM."""

    def __init__(self, child, log):
        import threading
        self.child, self.log, self.buf, self.pos, self.before, self.match = child, log, "", 0, "", None
        self.lock = threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            try:
                data = os.read(self.child.child_fd, 65536)
            except OSError:
                return
            if not data:
                return
            text = data.decode("utf-8", "replace")
            self.log.write(text)
            self.log.flush()
            with self.lock:
                self.buf += text

    def expect(self, pattern, timeout=300):
        rx = re.compile(pattern)
        end = time.time() + timeout
        while True:
            with self.lock:
                m = rx.search(self.buf, self.pos)
                if m:
                    self.before, self.match, self.pos = self.buf[self.pos:m.start()], m, m.end()
                    return m
            if time.time() > end:
                with self.lock:
                    tail = self.buf[-600:]
                raise TimeoutError("timed out waiting for %r; console tail: %r" % (pattern, tail))
            time.sleep(0.2)

    def sendline(self, text):
        self.child.sendline(text)

    def sendcontrol(self, ch):
        self.child.sendcontrol(ch)

    def wait_exit(self, timeout):
        end = time.time() + timeout
        while time.time() < end and self.child.isalive():
            time.sleep(1)


class Vm:
    def __init__(self, a):
        self.a, self.work = a, os.path.abspath(a.work)
        os.makedirs(self.work, exist_ok=True)
        self.key = a.key
        self.log = open(os.path.join(self.work, "serial.log"), "w", errors="replace")
        self.child = None

    def build_disks(self):
        overlay = os.path.join(self.work, "overlay.qcow2")
        if os.path.exists(overlay):
            os.unlink(overlay)
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-b", os.path.abspath(self.a.base), "-F", "raw", overlay], check=True)
        stage = os.path.join(self.work, "payload")
        shutil.rmtree(stage, ignore_errors=True)
        shutil.copytree(os.path.join(HERE, "payload"), stage)
        shutil.copy(self.a.deb, os.path.join(stage, "stynpilot.deb"))
        shutil.copytree(os.path.join(HERE, "..", "preview26"), os.path.join(stage, "preview26"))
        import make_fake_preview
        make_fake_preview.build(os.path.join(stage, "stynpilot-preview.deb"))
        img = os.path.join(self.work, "payload.img")
        if os.path.exists(img):
            os.unlink(img)
        subprocess.run(["truncate", "-s", "512M", img], check=True)
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", stage, img], check=True)
        return overlay, img

    def boot(self, first=False):
        overlay, img = self.build_disks() if first else (os.path.join(self.work, "overlay.qcow2"), os.path.join(self.work, "payload.img"))
        kvm = os.path.exists("/dev/kvm")
        cmd = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "host" if kvm else "max", "-smp", "2", "-m", "3072",
               "-nographic", "-kernel", self.a.kernel, "-initrd", self.a.initrd,
               "-append", "root=/dev/vda rw console=ttyS0 net.ifnames=0 panic=-1",
               "-drive", "file=%s,if=virtio" % overlay, "-drive", "file=%s,if=virtio,format=raw,readonly=on" % img,
               "-nic", "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:%d-:22" % self.a.ssh_port]
        if kvm:
            cmd[1:1] = ["-accel", "kvm"]
        self.child = Serial(pexpect.spawn(cmd[0], cmd[1:], timeout=900), self.log)

    # ---- serial session = the owner at the keyboard (a real local logind session)
    def login(self):
        c = self.child
        c.expect("g8vm login: ", timeout=900)
        c.sendline("owner")
        c.expect("Password: ")
        c.sendline("ownerpw")
        c.expect(r"owner@g8vm:~\$ ", timeout=120)
        c.sendline("stty -echo; export PS1='G8> '")
        c.expect("G8> ")
        c.expect("G8> ")

    def serial(self, command, timeout=300):
        c = self.child
        c.sendline("%s; echo __RC__$?__" % command)
        m = c.expect(r"__RC__(\d+)__", timeout=timeout)
        out, rc = c.before, int(m.group(1))
        c.expect("G8> ")
        return rc, out

    def pkexec_prompt(self, expect_text, password="ownerpw", timeout=300):
        """Answer the real polkit text prompt; returns the prompt text so the message can be checked."""
        c = self.child
        c.expect("Password: ", timeout=timeout)
        text = c.before
        record("polkit prompt shows %r" % expect_text[:40], expect_text in text, text[-300:])
        c.sendline(password)
        return text

    # ---- ssh side channel (a non-session remote login)
    def ssh(self, user, command, timeout=900, check=False):
        argv = ["ssh", "-i", self.key, "-p", str(self.a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "%s@127.0.0.1" % user, command]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return done.returncode, (done.stdout + done.stderr)

    def ssh_popen(self, user, command):
        argv = ["ssh", "-i", self.key, "-p", str(self.a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "%s@127.0.0.1" % user, command]
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def wait_ssh(self, seconds=900):
        end = time.time() + seconds
        while time.time() < end:
            try:
                if self.ssh("root", "true", timeout=20)[0] == 0:
                    return True
            except Exception:
                pass
            time.sleep(5)
        return False

    def set_proxy(self):
        """The sandbox's outbound proxy port changes between sessions; point the guest's apt at the current one."""
        import urllib.parse
        port = urllib.parse.urlsplit(os.environ.get("HTTPS_PROXY", "")).port
        if port:
            self.root("printf 'Acquire::http::Proxy \"http://10.0.2.2:%d\";\\nAcquire::https::Proxy \"http://10.0.2.2:%d\";\\n' > /etc/apt/apt.conf.d/99vmproxy" % (port, port))

    def root(self, command, **kw):
        return self.ssh("root", command, **kw)

    def as_owner(self, command, **kw):
        env = "XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
        return self.ssh("root", "runuser -u owner -- env %s %s" % (env, command), **kw)

    def guest(self, user_cmd, as_owner=True, **kw):
        fn = self.as_owner if as_owner else self.root
        rc, out = fn("python3 -I /mnt/payload/guest.py " + user_cmd, **kw)
        last = [l for l in out.splitlines() if l.startswith("{")]
        return rc, (json.loads(last[-1]) if last else {}), out


def req_state(obj):
    """The state of the request record itself (the dict that has a request_id), not an outer wrapper's 'state'."""
    if isinstance(obj, dict):
        if "request_id" in obj and isinstance(obj.get("state"), str):
            return obj["state"]
        for v in obj.values():
            r = req_state(v)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = req_state(v)
            if r is not None:
                return r
    return None


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def scenario(vm):
    A = vm.a
    # ---------------------------------------------------------------- boot 1
    vm.boot(first=True)
    record("VM boots to a login prompt with real systemd", vm.wait_ssh() is True)
    vm.set_proxy()
    rc, out = vm.root("systemctl is-system-running --wait; cat /etc/os-release | head -2; mkdir -p /mnt/payload && mount -o ro /dev/vdb /mnt/payload && ls /mnt/payload")
    record("machine is Ubuntu 26.04 and the payload is mounted", "26.04" in out and "stynpilot.deb" in out, out[-200:])
    rc, out = vm.root("systemctl is-active g8-fake-idp; curl -s https://auth.g8test.example/.well-known/openid-configuration | head -c 200")
    record("test identity provider reachable over trusted TLS", "authorization_endpoint" in out, out[-200:])

    # ---------------------------------------------------------------- install
    rc, out = vm.root("DEBIAN_FRONTEND=noninteractive apt-get install -y /mnt/payload/stynpilot.deb 2>&1 | tail -5", timeout=1200)
    rc2, ver = vm.root("/usr/bin/stynpilot version; dpkg -s stynpilot | grep -E '^(Status|Version)'")
    record("package installs with apt on 26.04", rc == 0 and "install ok installed" in ver, ver[-200:])
    rc, out = vm.root("systemctl is-enabled stynpilot-installer.service; systemctl is-active stynpilot-installer.service; "
                      "ls /etc/stynpilot 2>&1; ss -ltn | grep -E ':(18443|18444)\\b' || echo no-listeners")
    record("installing started and enabled nothing", "enabled" not in out.replace("disabled", "") and "no-listeners" in out and "installer.json" not in out and "inactive" in out, out)
    rc, out = vm.root("systemd-analyze verify /usr/lib/systemd/system/stynpilot-installer.service /usr/lib/systemd/user/stynpilot-owner.service 2>&1; echo rc=$?")
    record("systemd-analyze verify accepts both unit files", out.strip().endswith("rc=0") and "error" not in out.lower(), out[-400:])
    rc, out = vm.root("systemd-analyze security stynpilot-installer.service --no-pager 2>&1 | tail -3")
    print("INFO installer exposure:", out.strip()[-200:], flush=True)
    rc, js, out = vm.guest("pairing")
    record("legacy pairing database created for the owner", js.get("ok"), out[-200:])
    rc, out = vm.as_owner("/usr/bin/stynpilot doctor", timeout=120)
    record("doctor before setup says 'not set up yet' and creates nothing", "not set up yet" in out, out[-300:])

    # ---------------------------------------------------------------- the owner at the keyboard
    vm.login()
    c = vm.child
    record("owner logs in on a real local session", True)
    rc, out = vm.serial("loginctl show-session $(loginctl --no-legend | awk '$3==\"owner\"{print $1}' | head -1) -p Active -p Remote -p Class | tr '\\n' ' '")
    record("that login is a local active session (what polkit's allow_active needs)", "Active=yes" in out and "Remote=no" in out, out[-200:])
    c.sendline("PYTHONUNBUFFERED=1 BROWSER=true stynpilot setup")
    c.expect(r"Setup page: (http://\S+)", timeout=180)
    url = c.match.group(1).strip()
    wiz = vm.ssh_popen("owner", "python3 -I /mnt/payload/guest.py wizard %s --start" % url)
    try:
        vm.pkexec_prompt("StyNpilot wants to copy ONE settings file to /etc/stynpilot/installer.json", timeout=120)      # root-setup
    except TimeoutError:
        if wiz.poll() is not None:
            record("wizard driver ran", False, wiz.stdout.read()[-1500:])
        else:
            wiz.kill()
            record("wizard driver ran", False, "driver still running (no password prompt came); " + wiz.stdout.read()[-800:])
        raise
    vm.pkexec_prompt("StyNpilot wants to START its software installer", timeout=300)                     # root-start (the Start button)
    wout, _ = wiz.communicate(timeout=900)
    record("wizard drove setup to the end through the real polkit prompt", '"finished": true' in wout, wout[-500:])
    record("wizard Start button started StyNpilot", '"step": "start", "status": 200' in wout or '"status": 200' in wout, wout[-300:])
    c.sendcontrol("c")
    c.expect("G8> ", timeout=60)
    for _ in range(40):
        if vm.root("ss -ltnH | grep -c -E ':(18443|18444)\\b'")[1].strip() == "2":
            break
        time.sleep(3)
    rc, out = vm.root("stat -c '%U %a %n' /etc/stynpilot/installer.json /etc/stynpilot/setup-receipt.json; "
                      "systemctl is-enabled stynpilot-installer; systemctl is-active stynpilot-installer; "
                      "runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active stynpilot-owner; "
                      "loginctl show-user owner -p Linger; ss -ltnH | awk '{print $4}' | grep -E '18443|18444'")
    record("root settings 0600 + public receipt; installer and owner service running", "root 600 /etc/stynpilot/installer.json" in out
           and "root 644 /etc/stynpilot/setup-receipt.json" in out and out.split().count("active") >= 2 and "Linger=yes" in out, out)
    record("listeners are loopback only", "127.0.0.1:18443" in out and "127.0.0.1:18444" in out and "0.0.0.0" not in out, out[-150:])
    if "127.0.0.1:18443" not in out:
        record("diagnostics (why it did not start)", False, vm.root("systemctl status stynpilot-installer --no-pager -l | tail -15; journalctl -b --no-pager -u stynpilot-installer | tail -15; "
               "runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 sh -c 'systemctl --user status stynpilot-owner --no-pager -l | tail -15; journalctl --user -u stynpilot-owner --no-pager | tail -20'; uptime")[1])
    rc, out = vm.as_owner("/usr/bin/stynpilot doctor", timeout=180)
    record("doctor after start: no FAIL lines", "FAIL" not in out, out[-600:])

    # ---------------------------------------------------------------- the whole workflow
    rc, js, out = vm.guest("request claude-connector htop")
    result = js.get("result", {})
    rid = find_key(result, "request_id")
    record("Claude files an install request (htop) and gets an owner approval link", bool(rid) and "approve/" in json.dumps(result), json.dumps(result)[:300])
    rc, js2, _ = vm.guest("status chatgpt-connector %s pending 30" % rid)
    record("ChatGPT sees the same pending request", req_state(js2) == "pending", json.dumps(js2)[:200])
    rc, js3, _ = vm.guest("ai-cannot-approve claude-connector %s" % rid)
    record("AI side has no approve/decide tool and cannot reach the approval page",
           not any(w in t for t in js3.get("tools", []) for w in ("approve", "decide", "deny", "confirm"))
           and all(v in (404, 405) for v in js3.get("routes", {}).values()), json.dumps(js3)[:300])
    rc, js4, _ = vm.guest("bad-token")
    record("a forged AI token is refused", js4.get("result", {}).get("http") in (401, 403) or "error" in json.dumps(js4.get("result", {})), json.dumps(js4)[:200])
    rc, js5, out = vm.guest("approve %s approve" % rid, timeout=900)
    record("owner approves in the approval page (provider sign-in, PKCE, nonce-bound proof)", js5.get("http") in (200, 303), json.dumps(js5)[:500])
    rc, js6, out = vm.guest("status claude-connector %s done,failed,needs_owner_intervention 1500" % rid, timeout=1700)
    state = req_state(js6)
    record("the root installer installed htop and both AIs can see 'done'", state == "done", json.dumps(js6)[:600])
    rollback_id = find_key(js6, "rollback_id")
    rc, out = vm.root("dpkg -s htop | grep -E '^Status'; which htop")
    record("htop is really installed on the machine", "install ok installed" in out, out)
    rc, jsc, _ = vm.guest("status chatgpt-connector %s done 30" % rid)
    record("ChatGPT reports the same accurate result", req_state(jsc) == "done", json.dumps(jsc)[:200])

    # ---------------------------------------------------------------- reboot
    vm.root("systemctl reboot")
    time.sleep(20)
    record("VM boots again after reboot", vm.wait_ssh(1200))
    rc, out = vm.root("systemctl is-active stynpilot-installer; runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active stynpilot-owner; "
                      "test -S /run/stynpilot/installer.sock && echo socket-ok; mount -o ro /dev/vdb /mnt/payload 2>&1; echo mounted")
    deadline = time.time() + 240
    def both_up(text):
        return text.split().count("active") >= 2 and "socket-ok" in text and vm.root("ss -ltnH | grep -c -E ':(18443|18444)\\b'")[1].strip() == "2"
    while time.time() < deadline and not both_up(out):
        time.sleep(10)
        rc, out = vm.root("systemctl is-active stynpilot-installer; runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active stynpilot-owner; test -S /run/stynpilot/installer.sock && echo socket-ok")
    record("after reboot the installer and owner service came back by themselves (nobody logged in)", both_up(out), out)
    rc, out = vm.root("mount -o ro /dev/vdb /mnt/payload 2>&1; ls /mnt/payload | head -3")
    rc, jsd, _ = vm.guest("status claude-connector %s done 120" % rid)
    record("the finished request is still reported 'done' after the reboot", req_state(jsd) == "done", json.dumps(jsd)[:200])

    # ---------------------------------------------------------------- crash and restart
    rc, out = vm.root("kill -9 $(systemctl show -p MainPID --value stynpilot-installer); sleep 15; systemctl is-active stynpilot-installer")
    record("systemd restarts the installer after it is killed", out.strip().endswith("active"), out)
    rc, out = vm.as_owner("systemctl --user restart stynpilot-owner; sleep 10; systemctl --user is-active stynpilot-owner")
    record("owner service restarts cleanly", out.strip().endswith("active"), out)
    rc, jse, _ = vm.guest("status chatgpt-connector %s done 120" % rid)
    record("request state survives both restarts", req_state(jse) == "done", json.dumps(jse)[:200])

    # ---------------------------------------------------------------- rollback via the same approval path
    rc, jr, out = vm.guest("request-rollback chatgpt-connector htop %s" % rollback_id)
    rrid = find_key(jr.get("result", {}), "request_id")
    record("ChatGPT files a rollback request for that install", bool(rrid), json.dumps(jr)[:300])
    rc, jra, _ = vm.guest("approve %s approve" % rrid, timeout=900)
    rc, jrs, _ = vm.guest("status chatgpt-connector %s done,failed,needs_owner_intervention 900" % rrid, timeout=1000)
    record("rollback completes after the owner's approval", req_state(jrs) == "done", json.dumps(jrs)[:500])
    rc, out = vm.root("dpkg -s htop 2>&1 | head -2")
    record("htop is gone again", "not installed" in out or "deinstall" in out or "config-files" in out, out)

    # ---------------------------------------------------------------- M1: a package that is NOT in the catalog
    rc, jsi, _ = vm.guest("inventory claude-connector")
    inv = jsi.get("result", {}).get("inventory", {})
    record("M1: read-only hardware/software inventory works and leaks no identifiers",
           bool(inv.get("os", {}).get("name")) and inv.get("memory", {}).get("total_bytes")
           and not any(w in json.dumps({k: v for k, v in inv.items() if k != "software"}) for w in ("serial", "uuid", "hostname")), json.dumps(inv)[:300])
    rc, jss, _ = vm.guest("search claude-connector ncdu")
    hits = jss.get("result", {}).get("results", [])
    record("M1: AI searches the signed Ubuntu lists and finds a non-catalog package", any(h.get("name") == "ncdu" and h.get("ai_may_request") and not h.get("installed") for h in hits), json.dumps(jss)[:300])
    rc, jsb, _ = vm.guest("search claude-connector sudo")
    record("M1: search marks sudo as not requestable by an AI", any(h.get("name") == "sudo" and h.get("ai_may_request") is False for h in jsb.get("result", {}).get("results", [])), json.dumps(jsb)[:300])
    for blocked in ("sudo", "openssh-server", "linux-image-generic"):
        rc, jb, _ = vm.guest("request-packages chatgpt-connector %s" % blocked)
        record("M1: requesting %s is refused before any request exists" % blocked,
               jb.get("result", {}).get("error") == "blocked_package" and not find_key(jb.get("result", {}), "request_id"), json.dumps(jb)[:300])
    rc, ji, _ = vm.guest("request-packages chatgpt-connector Ncdu")
    record("M1: an invalid package name is refused", ji.get("result", {}).get("error") == "invalid_package_name", json.dumps(ji)[:200])
    rc, jn, _ = vm.guest("request-packages chatgpt-connector ncdu")
    nrid = find_key(jn.get("result", {}), "request_id")
    nsoft = find_key(jn.get("result", {}), "software")
    record("M1: ChatGPT files an install request for ncdu by name", bool(nrid) and str(nsoft).startswith("apt-ncdu-"), json.dumps(jn)[:400])
    record("M1: the owner's summary says the assistant chose it and that scripts run as root",
           "run as root" in json.dumps(jn) and "ncdu" in json.dumps(jn), json.dumps(jn.get("result", {}).get("summary"))[:300])
    rc, jna, _ = vm.guest("approve %s approve" % nrid, timeout=900)
    rc, jnd, _ = vm.guest("status claude-connector %s done,failed,needs_owner_intervention 1500" % nrid, timeout=1700)
    record("M1: after independent owner approval StyNpilot installs ncdu and the AI sees 'done'", req_state(jnd) == "done", json.dumps(jnd)[:500])
    nroll = find_key(jnd, "rollback_id")
    rc, out = vm.root("dpkg -s ncdu | grep -E '^Status'; which ncdu")
    record("M1: ncdu is really installed", "install ok installed" in out, out)
    rc, jv, _ = vm.guest("search claude-connector ncdu")
    record("M1: the AI verifies it through the search tool (installed=true)", any(h.get("name") == "ncdu" and h.get("installed") for h in jv.get("result", {}).get("results", [])), json.dumps(jv)[:300])
    rc, jd, _ = vm.guest("request-packages claude-connector ncdu")
    record("M1: asking again reports already_installed and files nothing", jd.get("result", {}).get("already_installed") is True and not find_key(jd.get("result", {}), "request_id"), json.dumps(jd)[:300])
    rc, jr2, _ = vm.guest("request-rollback chatgpt-connector %s %s" % (nsoft, nroll))
    rrid2 = find_key(jr2.get("result", {}), "request_id")
    record("M1: rollback of the non-catalog install can be requested", bool(rrid2), json.dumps(jr2)[:300])
    rc, _, _ = vm.guest("approve %s approve" % rrid2, timeout=900)
    rc, jrs2, _ = vm.guest("status chatgpt-connector %s done,failed,needs_owner_intervention 900" % rrid2, timeout=1000)
    record("M1: rollback completes after owner approval", req_state(jrs2) == "done", json.dumps(jrs2)[:400])
    rc, out = vm.root("dpkg -s ncdu 2>&1 | head -2")
    record("M1: ncdu is gone again", "not installed" in out or "deinstall" in out or "config-files" in out, out)

    # ---------------------------------------------------------------- backups through real prompts + stop/start
    vm.login()
    rc, out = vm.serial("stynpilot backup --out ~/owner.tar", timeout=120)
    record("owner-state backup works without a password", rc == 0, out[-200:])
    c.sendline("stynpilot root-backup --out ~/root.tar; echo __RC__$?__")
    vm.pkexec_prompt("StyNpilot wants to READ its software-install rollback records")
    c.expect(r"__RC__(\d+)__", timeout=120)
    record("root backup through the real password prompt", c.match.group(1) == "0", c.before[-200:])
    c.expect("G8> ")
    rc, out = vm.root("tar -tf /home/owner/root.tar | head -5; stat -c '%U %a' /home/owner/root.tar")
    record("root backup file is owned by the owner and private", "owner 600" in out and "manifest.json" in out, out)
    c.sendline("stynpilot root-restore --archive ~/root.tar; echo __RC__$?__")
    vm.pkexec_prompt("StyNpilot wants to WRITE back")
    c.expect(r"__RC__(\d+)__", timeout=120)
    record("restore is refused while the installer is running (or destination not empty)", c.match.group(1) != "0", c.before[-300:])
    c.expect("G8> ")
    c.sendline("stynpilot stop; echo __RC__$?__")
    vm.pkexec_prompt("StyNpilot wants to STOP its software installer")
    c.expect(r"__RC__(\d+)__", timeout=180)
    record("stop works through its own prompt", c.match.group(1) == "0", c.before[-300:])
    c.expect("G8> ")
    rc, out = vm.root("systemctl is-active stynpilot-installer; systemctl is-enabled stynpilot-installer; "
                      "runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user is-active stynpilot-owner")
    record("after stop nothing is running or enabled", out.count("inactive") + out.count("disabled") >= 3, out)
    c.sendline("stynpilot start; echo __RC__$?__")
    vm.pkexec_prompt("StyNpilot wants to START its software installer")
    c.expect(r"__RC__(\d+)__", timeout=300)
    record("start again works", c.match.group(1) == "0", c.before[-300:])
    c.expect("G8> ")

    # ---------------------------------------------------------------- a wrong user cannot use the helper
    rc, out = vm.root("PKEXEC_UID=1001 /usr/libexec/stynpilot/root-helper root-stop; echo rc=$?")
    record("the root helper refuses anyone but the configured owner", "belongs_to_another_user" in out or "rc=1" in out, out[-200:])
    vm.root("poweroff")
    vm.child.wait_exit(300)



def scenario_remote(vm):
    """The owner is on SSH (a REMOTE logind session, no seat): finish setup's password step from the terminal. Real polkit,
    real pkexec text agent, real sshd. Nothing here starts a service except the final start/stop round trip."""
    import pexpect
    vm.boot(first=True)
    record("VM boots with real systemd", vm.wait_ssh() is True)
    vm.set_proxy()
    vm.root("mkdir -p /mnt/payload && mount -o ro /dev/vdb /mnt/payload")
    rc, out = vm.root("DEBIAN_FRONTEND=noninteractive apt-get install -y /mnt/payload/stynpilot.deb 2>&1 | tail -2; useradd -m -s /bin/bash mallory; "
                      "echo mallory:mallorypw | chpasswd; mkdir -p ~mallory/.ssh; cp ~owner/.ssh/authorized_keys ~mallory/.ssh/; "
                      "chown -R mallory ~mallory/.ssh; id mallory", timeout=1200)
    record("package installed; a second, non-admin account exists", "uid=" in out, out[-200:])
    # --- make this VM match the real Ryzen: Ubuntu's current polkit (127-2ubuntu1.1) with the SOCKET-ACTIVATED password helper
    rc, out = vm.root("chmod 0755 /usr/lib/polkit-1/polkit-agent-helper-1; systemctl unmask polkit-agent-helper.socket; "
                      "systemctl enable --now polkit-agent-helper.socket; "
                      "echo 'deb https://archive.ubuntu.com/ubuntu resolute-updates main' > /etc/apt/sources.list.d/up.list; "
                      "apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y polkitd pkexec libpolkit-agent-1-0 "
                      "libpolkit-gobject-1-0 >/dev/null 2>&1; dpkg-query -W -f='${Version}' polkitd; echo; "
                      "stat -c %a /usr/lib/polkit-1/polkit-agent-helper-1; systemctl is-active polkit-agent-helper.socket", timeout=1200)
    record("VM uses the Ryzen's polkit 127-2ubuntu1.1 with the socket-activated (non-setuid) helper",
           "127-2ubuntu1.1" in out and "\n755\n" in out and "\nactive" in out, out)

    def pty(user, command, timeout=120):
        argv = ["-tt", "-i", vm.key, "-p", str(vm.a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR", "%s@127.0.0.1" % user, command]
        return pexpect.spawn("ssh", argv, encoding="utf-8", timeout=timeout)

    def finish(child):
        child.expect(pexpect.EOF)
        return child.before

    rc, out = vm.ssh("owner", "loginctl show-session $XDG_SESSION_ID -p Remote -p Seat -p Active | tr '\\n' ' '")
    record("the owner's SSH login is a REMOTE session with no seat (the Termius case)", "Remote=yes" in out and "Seat=" in out, out)
    rc, js, out = vm.guest("pairing")
    record("pairing database exists for the owner", js.get("ok"), out[-200:])
    # --- the owner fills the form (page over SSH), exactly as before; the system step is left pending
    setup = vm.ssh_popen("owner", "PYTHONUNBUFFERED=1 BROWSER=true stynpilot setup")
    url = ""
    for line in setup.stdout:
        if line.startswith("Setup page:"):
            url = line.split()[-1]
            break
    rc, js, out = vm.guest("wizard %s --save-only" % url)
    setup.kill()
    record("form saved from the remote login; system step pending", '"step": "saved"' in out, out[-300:])
    rc, before = vm.as_owner("bash -c 'cd ~ && sha256sum .config/stynpilot/owner.json .config/stynpilot/installer.proposed.json'")
    record("owner.json and installer.proposed.json exist", before.count("stynpilot") == 2, before)

    # --- diagnosis: what polkit says for this very login
    rc, out = vm.ssh("owner", "pkcheck --action-id org.stynpilot.root-setup --process $$; echo rc=$?")
    record("polkit now says 'requires authentication' (exit 2) for the remote login", "rc=2" in out, out)

    # --- the failure ChatGPT reported, reproduced; then the proposed workarounds, each tried for real
    helper_cmd = "pkexec /usr/libexec/stynpilot/root-helper root-setup --from /nonexistent"

    def typed(cmd, pw="ownerpw"):
        c = pty("owner", cmd + "; echo END_RC=$?")
        text = ""
        while True:
            i = c.expect(["[Pp]assword: ?", "END_RC=\\d+", pexpect.EOF])
            text += c.before + (c.after if isinstance(c.after, str) else "")
            if i == 0:
                c.sendline(pw)
                continue
            return text
    text = typed(helper_cmd)
    record("REPRODUCED: pkexec's own prompt fails with 'No session for cookie' (polkit issue 686)",
           "No session for cookie" in text and "END_RC=127" in text, text[-300:])
    text = typed("bash -c 'exec %s'" % helper_cmd)
    record("'exec pkexec' does NOT fix it", "No session for cookie" in text, text[-300:])
    text = typed("pkttyagent --process $$ --fallback & sleep 1; %s" % helper_cmd)
    record("an agent run as the owner (non-interactive shell) works: authentication completes",
           "AUTHENTICATION COMPLETE" in text and "No session for cookie" not in text, text[-300:])

    def two_terminals(agent_command):
        s1 = pexpect.spawn("ssh", ["-tt", "-i", vm.key, "-p", str(vm.a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o",
                                   "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "owner@127.0.0.1", "bash --norc -i"],
                           encoding="utf-8", timeout=40)
        s1.expect(r"\$ ")
        s1.sendline("echo PID=$$")
        s1.expect(r"PID=(\d+)\s")
        pid = s1.match.group(1)
        s2 = pexpect.spawn("ssh", ["-tt", "-i", vm.key, "-p", str(vm.a.ssh_port), "-o", "StrictHostKeyChecking=no", "-o",
                                   "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "owner@127.0.0.1", "bash --norc -i"],
                           encoding="utf-8", timeout=40)
        s2.expect(r"\$ ")
        s2.sendline(agent_command % pid)
        time.sleep(2)
        s1.sendline(helper_cmd + "; echo END_RC=$?")
        if s2.expect(["[Pp]assword: ?", pexpect.TIMEOUT], timeout=10) == 0:
            s2.sendline("ownerpw")
        time.sleep(3)
        s1.expect("END_RC=\\d+", timeout=20)
        out1 = s1.before
        s2.expect(pexpect.TIMEOUT, timeout=2)
        out2 = s2.before
        s1.close()
        s2.close()
        return out1, out2
    out1, out2 = two_terminals("pkttyagent --process %s")
    record("ONE-TIME WORKAROUND: agent as the owner in a second terminal succeeds",
           "AUTHENTICATION COMPLETE" in out2 and "No session for cookie" not in out1 + out2 and "Not authorized" not in out1, out1[-200:] + out2[-200:])
    out1, out2 = two_terminals("echo ownerpw | sudo -S -p '' pkttyagent --process %s")
    record("the same agent started with sudo (root) still fails: the agent must run as the owner",
           "No session for cookie" in out2 + out1, (out1 + out2)[-300:])

    def nothing_in_etc():
        return vm.root("ls /etc/stynpilot 2>&1 | grep -c -E 'installer.json|receipt'")[1].strip() == "0"

    c = pty("owner", "stynpilot auth-check")
    text = finish(c)
    record("auth-check explains this login (remote, will ask, socket helper handled) and changes nothing",
           "remote (SSH)" in text and "will ask for the administrator password" in text and "No session for cookie" in text
           and "Nothing was changed" in text, text[-500:])
    # --- wrong password
    c = pty("owner", "stynpilot setup-system")
    c.expect("Password: ")
    c.sendline("wrongpw")
    text = finish(c)
    record("wrong password: refused, says so, nothing written", "refused" in text and "did not finish" in text and nothing_in_etc(), text[-300:])
    # --- cancel with Ctrl-D (end of input at the prompt)
    c = pty("owner", "stynpilot setup-system")
    c.expect("Password: ")
    c.sendeof()
    text = finish(c)
    record("cancelled at the prompt (Ctrl-D): did not finish, nothing written", "did not finish" in text and nothing_in_etc(), text[-300:])
    # --- cancel with Ctrl-C
    c = pty("owner", "stynpilot setup-system")
    c.expect("Password: ")
    c.sendintr()
    text = finish(c)
    record("cancelled at the prompt (Ctrl-C): no crash, nothing written", "Traceback" not in text and nothing_in_etc(), text[-300:])
    # --- the prompt names exactly what is being approved; right password
    c = pty("owner", "stynpilot setup-system")
    c.expect("Password: ")
    prompt = c.before
    record("prompt names the one operation", "AUTHENTICATING FOR org.stynpilot.root-setup" in prompt and "ONE settings file" in prompt, prompt[-300:])
    c.sendline("ownerpw")
    text = finish(c)
    rc, files = vm.root("ls -l /etc/stynpilot; systemctl is-active stynpilot-installer.service; ss -ltn | grep -c -E ':(18443|18444)\\b'")
    record("right password: system settings written, nothing started", "System settings are in place" in text and "installer.json" in files
           and "setup-receipt.json" in files
           and "inactive" in files, text[-200:] + files)
    rc, after = vm.as_owner("bash -c 'cd ~ && sha256sum .config/stynpilot/owner.json .config/stynpilot/installer.proposed.json'")
    record("the saved answers were not touched (nothing re-entered)", after == before, after)
    rc, mode = vm.root("stat -c '%U %a' /etc/stynpilot/installer.json")
    record("settings file is root-owned and private", mode.strip() == "root 600", mode)
    # --- repeat: asks for nothing
    c = pty("owner", "stynpilot setup-system")
    i = c.expect(["Password: ", pexpect.EOF])
    text = c.before
    record("repeating asks for no password and changes nothing", i == 1 and "already finished" in text, text[-200:])
    # --- a different account cannot use the owner's installer
    c = pty("mallory", "PYTHONPATH=/usr/lib/stynpilot/lib python3 -c \"from stynpilot.setup_wizard import pkexec_run; "
                         "pkexec_run(['pkexec', '/usr/libexec/stynpilot/root-helper', 'root-start'])\"")
    c.expect("Password: ")
    c.sendline("ownerpw")                       # even with the admin's password, the helper checks WHO asked
    text = finish(c)
    rc, act = vm.root("systemctl is-active stynpilot-installer.service")
    record("another account is refused by the helper even after authenticating", "belongs_to_another_user" in text and "inactive" in act, text[-300:])
    c = pty("mallory", "stynpilot setup-system")
    text = finish(c)
    record("another account cannot run the owner's setup step", "Nothing was changed" in text, text[-200:])
    # --- the next step works remotely too (this is the first time anything starts)
    c = pty("owner", "stynpilot start", timeout=240)
    c.expect("Password: ")
    c.sendline("ownerpw")
    text = finish(c)
    record("stynpilot start works from the remote login", "StyNpilot is running" in text, text[-300:])
    c = pty("owner", "stynpilot stop", timeout=240)
    c.expect("Password: ")
    c.sendline("ownerpw")
    text = finish(c)
    rc, act = vm.root("systemctl is-active stynpilot-installer.service")
    record("stynpilot stop works from the remote login", "stopped" in text and "inactive" in act, text[-300:])


def scenario_preview26(vm):
    """Rehearses the Preview26 safety net: back up a stand-in install, add the new StyNpilot beside it, wreck the
    stand-in, restore, and prove it is byte-for-byte what it was."""
    vm.boot(first=True)
    record("VM boots", vm.wait_ssh())
    vm.set_proxy()
    vm.root("systemctl is-system-running --wait >/dev/null; mkdir -p /mnt/payload && mount -o ro /dev/vdb /mnt/payload")
    rc, out = vm.root("DEBIAN_FRONTEND=noninteractive apt-get install -y dpkg-repack /mnt/payload/stynpilot-preview.deb 2>&1 | tail -2; dpkg-query -W stynpilot-preview", timeout=900)
    record("stand-in Preview26 package installs", "0.5.13~preview26" in out, out[-200:])
    rc, js, out = vm.guest("pairing")                                   # the owner's pairing database (Preview26 layout)
    record("owner pairing database exists (as Preview26 leaves it)", js.get("ok"), out[-200:])
    vm.root("mkdir -p /etc/stynpilot && printf '{\"secret\": \"SECRET-MARKER-26\"}' > /etc/stynpilot/remote-broker.json && chmod 600 /etc/stynpilot/remote-broker.json && chmod 750 /home/owner")
    vm.root("loginctl enable-linger owner; sleep 5; runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user enable --now stynpilot-commander-user.service; systemctl enable --now stynpilot-remote-broker.service; sleep 5")
    check = "python3 -I /mnt/payload/p26_check.py"
    DB = "/home/owner/.local/state/stynpilot-owner/pairing.sqlite3"
    vm.root("nohup runuser -u owner -- python3 -I /mnt/payload/walholder.py %s > /tmp/wal.out 2>&1 &" % DB)
    time.sleep(6)
    rc, out = vm.root("cat /tmp/wal.out; ls -la %s*" % DB)
    record("a live service holds committed rows only in the -wal file (as a running Preview26 would)", "ready" in out and "-wal" in out and "-shm" in out, out[-300:])

    def fingerprint():
        rc, out = vm.root(check)
        lines = [l for l in out.splitlines() if l.startswith("{")]
        if not lines:
            raise RuntimeError("fingerprint failed: " + out[-600:])
        return json.loads(lines[-1])
    base = fingerprint()
    record("stand-in is really running (user unit, root unit, both ports)", base["units"] == {"system:stynpilot-remote-broker": "active", "user:stynpilot-commander-user": "active"}
           and all(base["ports"].values()), json.dumps(base["units"]) + json.dumps(base["ports"]))
    P = "/mnt/payload/preview26"
    ENV = "SUDO_USER=owner"
    rc, out = vm.root("%s sh %s/inventory.sh 2>&1" % (ENV, P))
    record("inventory lists the package and prints no secret", "stynpilot-preview 0.5.13~preview26 installed" in out and "SECRET-MARKER-26" not in out and "remote-broker.json" in out, out[-300:])
    rc, out = vm.root("%s sh %s/backup.sh 2>&1; ls -la /home/owner/preview26-backup-*.tar* 2>&1" % (ENV, P), timeout=600)
    arch = re.findall(r"backup written: (\S+\.tar)", out)
    record("backup runs and writes a private archive owned by the owner", rc == 0 and bool(arch) and "-rw------- 1 owner" in out, out[-500:])
    arch = arch[0] if arch else "/home/owner/missing.tar"
    record("backup changed nothing (same fingerprint, same running state)", fingerprint() == base)
    rc, out = vm.root("tar -tf %s | grep -E 'sqlite3-(wal|shm|journal)' ; echo end; mkdir -p /tmp/x && tar -xf %s -C /tmp/x files%s && python3 -c \"import sqlite3;d=sqlite3.connect('/tmp/x/files%s');print(d.execute('select v from wal_marker').fetchall(), d.execute('pragma integrity_check').fetchone())\"" % (arch, arch, DB, DB))
    record("snapshot has the WAL-only rows, passes integrity, and no -wal/-shm/-journal companions are archived", "ONLY-IN-THE-WAL" in out and "'ok'" in out and out.split("end")[0].strip() == "", out[-300:])
    rc, out = vm.root("tar -tf %s | grep -E 'remote-broker|pairing|package.deb'; tar -xOf %s meta/INFO; echo %s >/dev/null" % (arch, arch, arch))
    record("archive holds the files, the settings, the sqlite copy and a reinstallable package copy", "remote-broker.json" in out and "pairing.sqlite3" in out and "package.deb" in out and "format 1" in out, out[-400:])

    # ---- the new StyNpilot goes in next to it
    rc, out = vm.root("DEBIAN_FRONTEND=noninteractive apt-get install -y /mnt/payload/stynpilot.deb 2>&1 | tail -2; dpkg-query -W stynpilot", timeout=900)
    record("new StyNpilot installs beside Preview26 without touching it", rc == 0 and "stynpilot\t0.1.0" in out and fingerprint() == base, out[-200:])
    rc, out = vm.as_owner("/usr/bin/stynpilot doctor", timeout=180)
    record("doctor notices the existing Preview26 service", "existing Preview26 service" in out and "found" in out.split("existing Preview26 service")[1][:60], out[-500:])
    rc, out = vm.root("ls /usr/share/polkit-1/actions | grep -c stynpilot; systemd-analyze verify /usr/lib/systemd/system/stynpilot-installer.service /usr/lib/systemd/system/stynpilot-remote-broker.service 2>&1 | head -3")
    record("both policy sets coexist and both unit files verify", out.split()[0] == "2", out[-200:])

    # ---- damage: package removed with purge, state corrupted, settings gone
    vm.root("pkill -f walholder.py; sleep 1; printf 'STALE-GARBAGE' > %s-wal; printf 'STALE-GARBAGE' > %s-shm; chown owner %s-wal %s-shm" % (DB, DB, DB, DB))
    vm.root("runuser -u owner -- env XDG_RUNTIME_DIR=/run/user/1000 systemctl --user stop stynpilot-commander-user; systemctl stop stynpilot-remote-broker; "
            "apt-get purge -y stynpilot-preview >/dev/null 2>&1; rm -f /etc/stynpilot/remote-broker.json; : > /home/owner/.local/state/stynpilot-owner/pairing.sqlite3; echo damaged")
    broken = fingerprint()
    record("the damage is real (package gone, settings gone, database emptied, services down)", broken["dpkg"] != base["dpkg"] and "/etc/stynpilot/remote-broker.json" not in broken["files"]
           and not any(broken["ports"].values()), broken["dpkg"])
    rc, out = vm.root("%s sh %s/restore.sh %s 2>&1" % (ENV, P, arch))
    record("dry run reports what would change and changes nothing", "DRY RUN" in out and fingerprint() == broken, out[-300:])
    vm.root("cp %s /tmp/bad.tar && printf 'X' | dd of=/tmp/bad.tar bs=1 seek=2000 conv=notrunc 2>/dev/null; cp %s.sha256 /tmp/bad.tar.sha256; sed -i 's#preview26-backup-[0-9TZ]*.tar#bad.tar#' /tmp/bad.tar.sha256; chown owner /tmp/bad.tar*; chmod 600 /tmp/bad.tar*" % (arch, arch))
    rc, out = vm.root("%s sh %s/restore.sh /tmp/bad.tar --really 2>&1" % (ENV, P))
    record("a damaged archive is refused and nothing is restored", rc != 0 and ("MISMATCH" in out or "refusing" in out or "not a Preview26" in out) and fingerprint() == broken, out[-200:])
    vm.root("chmod 644 %s" % arch)
    rc, out = vm.root("%s sh %s/restore.sh %s --really 2>&1" % (ENV, P, arch))
    record("a world-readable archive is refused", rc != 0 and "private" in out and fingerprint() == broken, out[-200:])
    vm.root("chmod 600 %s" % arch)
    rc, out = vm.root("%s sh %s/restore.sh %s --really 2>&1" % (ENV, P, arch), timeout=900)
    record("restore completes (package reinstalled from the backup's own copy)", rc == 0 and "reinstalled stynpilot-preview" in out, out[-400:])
    time.sleep(8)
    after = fingerprint()
    same_files = {k: v for k, v in after["files"].items()} == base["files"]
    record("everything is exactly as before: files, modes, owners, database content", same_files, json.dumps({k: (base["files"].get(k), after["files"].get(k)) for k in set(base["files"]) | set(after["files"]) if base["files"].get(k) != after["files"].get(k)})[:500])
    rc, out = vm.root("grep -l STALE-GARBAGE %s %s-wal %s-shm 2>/dev/null; echo end; python3 -c \"import sqlite3;d=sqlite3.connect('%s');print(d.execute('select v from wal_marker').fetchall(), d.execute('pragma integrity_check').fetchone())\"" % (DB, DB, DB, DB))
    record("restore removed the stale -wal/-shm and the database holds the WAL-only rows, intact", out.split("end")[0].strip() == "" and "ONLY-IN-THE-WAL" in out and "'ok'" in out, out[-300:])
    record("services are running again as before", after["units"] == base["units"] and after["ports"] == base["ports"] and after["dpkg"] == base["dpkg"], json.dumps(after["units"]) + after["dpkg"])
    rc, out = vm.root("dpkg-query -W stynpilot; dpkg -V stynpilot | head -3; systemctl is-enabled stynpilot-installer; echo end")
    record("the new StyNpilot was left alone by the restore", "0.1.0" in out and out.split("end")[0].strip().endswith("disabled"), out[-200:])
    vm.root("poweroff")
    vm.child.wait_exit(300)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--kernel", required=True)
    p.add_argument("--initrd", required=True)
    p.add_argument("--deb", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ssh-port", type=int, default=2222)
    p.add_argument("--scenario", choices=["full", "preview26", "remote"], default="full")
    a = p.parse_args()
    vm = Vm(a)
    try:
        {"full": scenario, "preview26": scenario_preview26, "remote": scenario_remote}[a.scenario](vm)
    except Exception as error:
        record("scenario aborted: %s" % type(error).__name__, False, str(error)[-500:])
    finally:
        try:
            vm.child.child.close(force=True)
        except Exception:
            pass
    failed = [r for r in RESULTS if not r[1]]
    print("\nRESULT: %s  (%d checks, %d failed)" % ("PASS" if not failed else "FAIL", len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
