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
    c.sendline("BROWSER=true stynpilot setup")
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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--kernel", required=True)
    p.add_argument("--initrd", required=True)
    p.add_argument("--deb", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ssh-port", type=int, default=2222)
    a = p.parse_args()
    vm = Vm(a)
    try:
        scenario(vm)
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
