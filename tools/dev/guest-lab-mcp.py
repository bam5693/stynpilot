"""Exercise the installed lab tools over authenticated MCP inside the NIC-free guest."""
import hashlib
import base64
import html
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from urllib.parse import urlsplit

# This fixture enforces the disposable DMI, root and NIC checks on import.
sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")
import httpx
import jwt
from softauth import SoftAuthenticator
from stynpilot.broker import lab
from stynpilot.broker.passkeys import PasskeyStore
from stynpilot.broker.proof import repository_credential_nonce
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



def fixture_push_origin(root, workspace, base, token):
    """NIC-free replacement for the fixed GitHub host, with real smart HTTPS."""
    cert, key = root / "github.crt", root / "github.key"
    fixture.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-x509", "-nodes", "-days", "2",
                    "-subj", "/CN=github.com", "-addext", "subjectAltName=DNS:github.com",
                    "-keyout", str(key), "-out", str(cert))
    trust = Path("/usr/local/share/ca-certificates/stynpilot-fixture-github.crt")
    trust.write_bytes(cert.read_bytes())
    fixture.command("update-ca-certificates")
    with Path("/etc/hosts").open("a") as hosts:
        hosts.write("\n127.0.0.2 github.com\n")

    remote = root / "bam5693" / "stynpilot.git"
    remote.parent.mkdir()
    fixture.command("git", "init", "--quiet", "--bare", str(remote))
    fixture.command("git", "-C", str(remote), "-c", "protocol.file.allow=always", "-c",
                    "safe.directory=" + str(workspace), "fetch", "--quiet", "--no-tags", str(workspace),
                    base + ":refs/heads/main")
    auth = "Basic " + base64.b64encode(("x-access-token:" + token).encode()).decode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.cgi()

        def do_POST(self):
            self.cgi()

        def cgi(self):
            target = urlsplit(self.path)
            if target.path not in ("/bam5693/stynpilot.git/info/refs", "/bam5693/stynpilot.git/git-upload-pack",
                                   "/bam5693/stynpilot.git/git-receive-pack"):
                self.send_error(404)
                return
            if self.headers.get("Authorization") != auth:
                self.send_error(403)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 <= size <= 1 << 20:
                self.send_error(413)
                return
            env = {"PATH": "/usr/bin:/bin", "GIT_PROJECT_ROOT": str(root), "GIT_HTTP_EXPORT_ALL": "1",
                   "PATH_INFO": target.path, "QUERY_STRING": target.query, "REQUEST_METHOD": self.command,
                   "REMOTE_USER": "isolated-fixture", "CONTENT_LENGTH": str(size),
                   "CONTENT_TYPE": self.headers.get("Content-Type", "")}
            result = subprocess.run(["/usr/lib/git-core/git-http-backend"], input=self.rfile.read(size), env=env,
                                    capture_output=True, timeout=20, check=True)
            if target.path.endswith("/git-receive-pack"):
                self.server.receive_posts += 1
                if self.server.drop_receive:
                    self.server.drop_receive = False
                    self.close_connection = True
                    return
            header, body = result.stdout.split(b"\r\n\r\n", 1)
            fields = [line.decode().split(": ", 1) for line in header.split(b"\r\n")]
            status = next((int(value.split()[0]) for name, value in fields if name.lower() == "status"), 200)
            self.send_response(status)
            for name, value in fields:
                if name.lower() not in ("status", "content-length"):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    listener = ThreadingHTTPServer(("127.0.0.2", 443), Handler)
    listener.receive_posts = 0
    listener.drop_receive = False
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    listener.socket = tls.wrap_socket(listener.socket, server_side=True)
    threading.Thread(target=listener.serve_forever, daemon=True).start()
    return listener, remote


def main():
    signing_key = fixture.setup(check_restore_path=False, lab=True)
    properties = ("show", "-p", "MainPID", "-p", "LimitCORE", "-p", "LimitCORESoft")
    services = (
        fixture.command("systemctl", *properties, "stynpilot-installer.service"),
        fixture.as_owner("systemctl", "--user", *properties, "stynpilot-owner.service").stdout,
    )
    for service in services:
        fields = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
        assert fields["LimitCORE"] == fields["LimitCORESoft"] == "0", fields
        pid = int(fields["MainPID"])
        assert pid > 1, fields
        limits = Path("/proc", str(pid), "limits").read_text().splitlines()
        core = next(line.split() for line in limits if line.startswith("Max core file size"))
        assert core[4:6] == ["0", "0"], core
    print("STYNPILOT_PACKAGED_CREDENTIAL_SERVICE_LIMITS_OK", flush=True)
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
        def approve(request_id, *, required=False, credential=None, substitution=None):
            with httpx.Client(base_url="http://127.0.0.1:18444", headers={"Host": HOST}, timeout=20, trust_env=False) as phone:
                page = phone.get("/approve/" + request_id)
                page.raise_for_status()
                if required:
                    assert "Approval requires an enrolled passkey" in page.text
                options = json.loads(html.unescape(re.search("data-o='([^']+)'", page.text).group(1)))
                nonce = base64.urlsafe_b64decode(options["challenge"]["approve"] + "==")
                if credential is not None:
                    assert 'type=password' in page.text
                    assert options.get("repository_credential") and not options.get("autostart")
                    nonce = bytes.fromhex(repository_credential_nonce(nonce.hex(), hashlib.sha256(credential.encode()).hexdigest()))
                proof = json.dumps(auth.assert_(nonce))
                cookie = {COOKIE: options["view"]}
                body = {"view": options["view"], "csrf": options["csrf"], "decision": "approve", "assertion": proof}
                if credential is not None:
                    body["credential"] = substitution if substitution is not None else credential
                response = phone.post("/approve/passkey", cookies=cookie, headers={"Origin": "https://" + HOST}, json=body)
                if credential:
                    assert credential not in page.text and credential not in response.text
                if substitution is not None:
                    assert not response.json()["ok"], response.text
                else:
                    assert response.json()["ok"], response.text
        approve(filed["request_id"], required=True)
        fixture.until(lambda: fixture.broker("status", filed["request_id"])["state"] == "done", 20)
        assert ok("commander_request_dev_lab_enrollment", repository=lab.REPOSITORY)["already_enrolled"]
        print("GUEST_LAB_PASSKEY_ENROLLED", flush=True)
        workspace = "stynpilot"
        requested = ok("commander_request_workspace_authorization", name=workspace)
        approve(requested["request_id"])
        fixture.until(lambda: fixture.broker("status", requested["request_id"])["state"] == "done", 20)
        selftest = ok("runner_selftest")
        assert len(selftest["passed"]) == 21 and not selftest["failed"], selftest
        folder = fixture.HOME / "StyNpilot-Projects" / workspace

        def git(*args):
            return fixture.as_owner(
                "/usr/bin/git", "-C", str(folder), "-c", "core.hooksPath=/dev/null",
                "-c", "user.name=Guest fixture", "-c", "user.email=fixture@example.invalid", *args,
            ).stdout.strip()

        def git_job(recipe, args, *, succeeds=True):
            job = ok("job_run", workspace_name=workspace, recipe=recipe, args=args)["job_id"]

            def git_terminal():
                result = ok("job_status", job_id=job)
                return result if result["state"] != "running" else None

            result = fixture.until(git_terminal, 30)
            output = ok("job_output", job_id=job)["text"].strip()
            assert (result["exit_code"] == 0) == succeeds, (result, output)
            return output

        repo = lab.REPOSITORY

        def seed_bundle(source, commit, bundle):
            fixture.command("/usr/bin/git", "-C", str(source), "update-ref", "refs/heads/stynpilot-import", commit)
            fixture.command("/usr/bin/git", "-C", str(source), "bundle", "create", str(bundle), "refs/heads/stynpilot-import")
            data = bundle.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            record = fixture.STATE / "release/builds" / commit
            record.mkdir(mode=0o700)
            path = record / "checkout.bundle"
            path.write_bytes(data)
            path.chmod(0o600)
            fixture.write(record / "record.json", {"state": "ready", "commit": commit, "tests_failed": 0,
                                                  "reproducible": True, "checkout_bundle_sha256": digest})
            return {"repository": repo, "commit": commit, "bundle_sha256": digest}

        with tempfile.TemporaryDirectory(prefix="fixture-source-") as scratch:
            source, bundle = Path(scratch) / "source", Path(scratch) / "fixture.bundle"
            source.mkdir()
            def source_git(*args):
                return fixture.command("/usr/bin/git", "-C", str(source), "-c", "user.name=Bundle fixture",
                                       "-c", "user.email=fixture@example.invalid", *args)
            source_git("init", "--quiet", "--initial-branch=main", "--template=")
            (source / "base.txt").write_text("base\n")
            source_git("add", "--", "base.txt")
            source_git("commit", "--quiet", "-m", "fixture base")
            base = source_git("rev-parse", "HEAD").strip()
            prepared = seed_bundle(source, base, bundle)
            assert call("workspace_checkout_stynpilot", **dict(prepared, bundle_sha256="f" * 64))["error"] == "checkout_bundle_not_verified"
            assert ok("workspace_checkout_stynpilot", **prepared)["commit"] == base
            assert call("workspace_checkout_stynpilot", **prepared)["error"] == "checkout_workspace_not_empty"
            assert git("rev-parse", "HEAD") == base
            (source / "base.txt").write_text("upstream\n")
            source_git("commit", "--quiet", "-am", "fixture upstream")
            upstream = source_git("rev-parse", "HEAD").strip()
            imported = ok("workspace_fetch_stynpilot", **seed_bundle(source, upstream, bundle))
            def fetched():
                result = ok("job_status", job_id=imported["job_id"])
                return result if result["state"] != "running" else None
            result = fixture.until(fetched, 30)
            output = ok("job_output", job_id=imported["job_id"])["text"].strip()
            assert result["exit_code"] == 0, (result, output)
            assert output == upstream, output
            assert imported["verified_ref"] == "refs/stynpilot/verified/" + upstream
            assert git("rev-parse", imported["verified_ref"]) == upstream and git("rev-parse", "HEAD") == base
        print("STYNPILOT_PACKAGED_REPO_READ_OK", flush=True)
        assert git_job("git-work-branch", ["work/fixture", base]) == base
        assert git_job("git-work-branch", ["test/fixture", base]) == base
        ok("workspace_write", workspace_name=workspace, path="new.txt", content="new\n")
        dirty = git_job("git-work-switch", ["work/fixture", base, base], succeeds=False)
        assert dirty == "git_workspace_dirty", dirty
        changed = git_job("git-work-commit", ["test/fixture", base, "fixture new file", "new.txt"])
        assert changed == git("rev-parse", "HEAD") and git("show", changed + ":new.txt") == "new"
        assert git_job("git-work-switch", ["work/fixture", changed, base]) == base
        assert git_job("git-work-fast-forward", ["work/fixture", base, changed]) == changed
        assert git("rev-parse", "test/fixture") == changed and not git("status", "--porcelain")
        push = {"repository": lab.REPOSITORY, "branch": "work/fixture", "commit": changed, "expected_remote": "0" * 40}
        assert call("commander_request_stynpilot_push", **push)["error"] == "git_push_credential_unavailable"
        token = "github_pat_fixture_only_01234567890123456789"
        credential = fixture.STATE / "repository-github-token"
        setup_tool = "commander_request_stynpilot_credential_setup"
        assert call(setup_tool, client="fixture-other", repository=lab.REPOSITORY)["error"] == "lab_enrollment_required"
        setup_request = ok(setup_tool, repository=lab.REPOSITORY)
        approve(setup_request["request_id"], required=True, credential=token, substitution=token + "X")
        assert not credential.exists()
        approve(setup_request["request_id"], required=True, credential=token)
        configured = fixture.until(lambda: fixture.broker("status", setup_request["request_id"])["state"] == "done", 20)
        assert configured and credential.read_text() == token and credential.stat().st_mode & 0o777 == 0o600
        assert token not in json.dumps(fixture.broker("status", setup_request["request_id"]))
        print("STYNPILOT_PACKAGED_PHONE_CREDENTIAL_OK", flush=True)
        with tempfile.TemporaryDirectory(prefix="fixture-push-") as scratch:
            origin, remote = fixture_push_origin(Path(scratch), folder, base, token)
            try:
                assert call("commander_request_stynpilot_push", **dict(push, branch="main"))["error"] == "git_push_binding_invalid"
                assert call("commander_request_stynpilot_push", client="fixture-other", **push)["error"] == "lab_enrollment_required"
                origin.drop_receive = True
                filed_push = ok("commander_request_stynpilot_push", **push)
                approve(filed_push["request_id"], required=True)
                def pushed():
                    result = fixture.broker("status", filed_push["request_id"])
                    return result if result["state"] in ("done", "failed") else None
                result = fixture.until(pushed, 100)
                assert result["state"] == "failed", result
                assert fixture.command("git", "-C", str(remote), "rev-parse", "refs/heads/work/fixture") == changed
                receives = origin.receive_posts
                filed_push = ok("commander_request_stynpilot_push", **dict(push, expected_remote=changed))
                approve(filed_push["request_id"], required=True)
                result = fixture.until(pushed, 100)
                assert result["state"] == "done", result
                assert origin.receive_posts == receives
                print("STYNPILOT_PACKAGED_PUSH_INTERRUPTION_OK", flush=True)
                ok("workspace_write", workspace_name=workspace, path="second.txt", content="second\n")
                descendant = git_job("git-work-commit", ["work/fixture", changed, "fixture push update", "second.txt"])
                for expected, state in (("0" * 40, "failed"), (changed, "done")):
                    filed_push = ok("commander_request_stynpilot_push",
                                    **dict(push, commit=descendant, expected_remote=expected))
                    approve(filed_push["request_id"], required=True)
                    result = fixture.until(pushed, 100)
                    assert result["state"] == state, result
                    head = changed if state == "failed" else descendant
                    assert fixture.command("git", "-C", str(remote), "rev-parse", "refs/heads/work/fixture") == head
                assert fixture.command("git", "-C", str(remote), "rev-parse", "refs/heads/main") == base
                print("STYNPILOT_PACKAGED_PUSH_MCP_OK", flush=True)
            finally:
                origin.shutdown()
                origin.server_close()
        print("STYNPILOT_PACKAGED_GIT_MCP_OK", flush=True)
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
