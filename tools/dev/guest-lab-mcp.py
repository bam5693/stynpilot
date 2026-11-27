"""Exercise the installed lab tools over authenticated MCP inside the NIC-free guest."""
import hashlib
import base64
import html
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time

# This fixture enforces the disposable DMI, root and NIC checks on import.
sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")
import httpx
import jwt
from softauth import SoftAuthenticator
from stynpilot.broker import lab
from stynpilot.broker.passkeys import PasskeyStore
from stynpilot.approval_web import COOKIE

HOST = "owner.example.test"
CASES = {
    "pass": b"""from pathlib import Path
def test_offline():
    assert not Path('/run/stynpilot').exists()
    assert not Path('/home').exists()
    assert not Path('/dev/kvm').exists()
    assert set(line.split(':')[0].strip() for line in
               Path('/proc/net/dev').read_text().splitlines()[2:]) == {'lo'}
""",
    "slow": b"""import subprocess
def test_wait():
    with subprocess.Popen(['/usr/bin/sleep', '300'], start_new_session=True) as descendant:
        descendant.wait()
""",
}


def artifact(case):
    # Trusted synthetic input in the installer-owned build record. The NIC-free
    # guest deliberately avoids the real release authority's GitHub fetch.
    content = CASES[case]
    commit = hashlib.sha1(content).hexdigest()
    store = fixture.STATE / "release/builds" / commit
    store.mkdir(mode=0o700)
    archive = store / "lab-source.tar"
    with tarfile.open(archive, "w", pax_headers={"comment": commit}) as tar:
        member = tarfile.TarInfo("tests/test_fixture.py")
        member.size = len(content)
        tar.addfile(member, io.BytesIO(content))
    archive.chmod(0o600)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    fixture.write(store / "record.json", {"state": "ready", "commit": commit, "tests_failed": 0,
                                          "reproducible": True, "lab_source_sha256": digest})
    return {"repository": lab.REPOSITORY, "commit": commit, "artifact_sha256": digest}


def main():
    signing_key = fixture.setup(check_restore_path=False, lab=True)
    fast, slow = artifact("pass"), artifact("slow")
    with httpx.Client(base_url="http://127.0.0.1:18443", headers={"Host": HOST}, timeout=45, trust_env=False) as http:
        def call(tool, *, client="fixture", **kw):
            now = int(time.time())
            token = jwt.encode({"iss": fixture.ISSUER, "aud": "https://" + HOST + "/mcp",
                                "sub": "fixture|test-owner", "iat": now, "exp": now + 120,
                                "azp": client, "scope": "health.read workspace.propose"},
                               signing_key, algorithm="RS256", headers={"kid": "fixture"})
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": {"device_id": fixture.DEVICE, **kw}}}
            response = http.post("/mcp", json=request, headers={"Authorization": "Bearer " + token,
                                  "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26"})
            response.raise_for_status()
            reply = response.json()
            result = reply["result"]
            return result.get("structuredContent") or json.loads(result["content"][0]["text"])

        def ok(tool, **kw):
            reply = call(tool, **kw)
            assert reply["ok"], reply
            return reply["result"]

        def unauthorised():
            reply = call("dev_lab_start", **fast)
            return reply if reply.get("error") not in ("installer_unavailable", "lab_restart_reconciling",
                                                        "restore_admission_busy") else None

        try:
            before_enrollment = fixture.until(unauthorised, 8)
        except RuntimeError:
            print("GUEST_LAB_BROKER_DIAGNOSTICS", flush=True)
            raw = fixture.as_owner("systemctl", "--user", "show", "stynpilot-owner.service",
                                   "-p", "MainPID", "--value")
            pid = raw.stdout.strip()
            print(Path("/proc", pid, "attr/current").read_text(),
                  [line for line in Path("/proc", pid, "status").read_text().splitlines()
                   if line.startswith(("Uid:", "Gid:", "Seccomp:"))])
            subprocess.run(["journalctl", "-k", "--no-pager", "-g", "DENIED", "-n", "12"], check=False)
            probe = ("import socket; s=socket.socket(socket.AF_UNIX); "
                     "s.connect('/run/stynpilot/installer.sock'); print('fixture_socket_connected')")
            subprocess.run(["nsenter", "--mount=/proc/" + pid + "/ns/mnt", "--", "setpriv",
                            "--reuid=1000", "--regid=1000", "--clear-groups",
                            "/usr/bin/python3", "-IB", "-c", probe], check=False)
            print(fixture.broker("runner", "lab_enrollment", {"client": "fixture", "repository": lab.REPOSITORY}))
            try:
                print(fixture.broker("runner", "lab_start", dict(fast, client="fixture", scenario=lab.PROFILE)))
            except subprocess.CalledProcessError as error:
                print(error.stderr)
            raise
        assert before_enrollment.get("error") == "lab_enrollment_required", before_enrollment
        filed = ok("commander_request_dev_lab_enrollment", repository=lab.REPOSITORY)
        keys = PasskeyStore(fixture.STATE / "passkeys.sqlite3", rp_id=HOST, origin="https://" + HOST)
        auth = SoftAuthenticator("https://" + HOST, HOST)
        enrollment = "e" * 64
        keys.open_window(enrollment, "Lab guest approver", "fixture")
        key = keys.complete(enrollment, auth.register(bytes.fromhex(keys.begin(enrollment)["challenge"])))
        keys.activate(key["kid"], key["label"], key["pub"], enrollment, "fixture")
        with httpx.Client(base_url="http://127.0.0.1:18444", headers={"Host": HOST}, timeout=20, trust_env=False) as phone:
            page = phone.get("/approve/" + filed["request_id"])
            page.raise_for_status()
            assert "Approval requires an enrolled passkey" in page.text
            options = json.loads(html.unescape(re.search("data-o='([^']+)'", page.text).group(1)))
            nonce = base64.urlsafe_b64decode(options["challenge"]["approve"] + "==")
            proof = json.dumps(auth.assert_(nonce))
            cookie = {COOKIE: options["view"]}
            response = phone.post("/approve/passkey", cookies=cookie, headers={"Origin": "https://" + HOST},
                                  json={"view": options["view"], "csrf": options["csrf"],
                                        "decision": "approve", "assertion": proof})
            assert response.json()["ok"], response.text
        fixture.until(lambda: fixture.broker("status", filed["request_id"])["state"] == "done", 20)
        assert ok("commander_request_dev_lab_enrollment", repository=lab.REPOSITORY)["already_enrolled"]
        print("GUEST_LAB_PASSKEY_ENROLLED", flush=True)
        assert call("dev_lab_start", **dict(fast, artifact_sha256="f" * 64))["error"] == "lab_source_not_verified"

        def terminal(job_id):
            reply = call("dev_lab_job_status", job_id=job_id)
            if reply["ok"] and reply["result"]["state"] not in ("starting", "running"):
                return reply["result"]
            return None

        job = ok("dev_lab_start", **fast)["id"]
        outcome = fixture.until(lambda: terminal(job), 40)
        evidence = ok("dev_lab_job_output", job_id=job)
        assert outcome["state"] == "passed" and "1 passed" in evidence["text"], (outcome, evidence)
        assert not ok("dev_lab_jobs", client="fixture-other")["jobs"]
        assert call("dev_lab_job_output", client="fixture-other", job_id=job)["error"] == "lab_unknown_job"

        def active():
            job_id = ok("dev_lab_start", **slow)["id"]
            events = Path("/sys/fs/cgroup/system.slice") / lab._name(job_id) / "cgroup.events"
            fixture.until(lambda: "populated 1" in events.read_text(), 10)
            fixture.until(lambda: any(Path("/proc", pid, "comm").read_text().strip() == "sleep"
                                      for pid in (events.parent / "cgroup.procs").read_text().split()), 15)
            return job_id, events

        job, events = active()
        assert call("dev_lab_cancel", client="fixture-other", job_id=job)["error"] == "lab_unknown_job"
        assert (fixture.STATE / "managed-activity").exists()
        assert ok("dev_lab_cancel", job_id=job)["state"] == "cancelled"
        assert not events.exists() or "populated 0" in events.read_text()
        assert not (fixture.STATE / "managed-activity").exists()

        job, events = active()
        fixture.command("systemctl", "restart", "stynpilot-installer.service")
        assert fixture.until(lambda: terminal(job), 40)["state"] == "interrupted"
        assert not events.exists() or "populated 0" in events.read_text()
        assert not (fixture.STATE / "managed-activity").exists()
        assert len(ok("dev_lab_jobs")["jobs"]) == 3
    print("STYNPILOT_LAB_MCP_OK", flush=True)


if __name__ == "__main__":
    main()
