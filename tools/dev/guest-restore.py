"""Stage 3 integration fixture. Run only from the NoCloud test disk inside an isolated guest."""
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import signal
import ssl
import subprocess
import sys
import threading
import time

if (os.geteuid() != 0 or Path("/sys/class/dmi/id/product_name").read_text().strip() != "STYNPILOT-DISPOSABLE"
        or len(list(Path("/sys/class/net").iterdir())) != 1):
    raise SystemExit("requires the NIC-free StyNpilot disposable guest")

sys.path[:0] = ["/usr/lib/stynpilot/lib", str(Path(__file__).parent)]
sys.path.append("/usr/lib/stynpilot/vendor")
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from legacy_pairing import make_pairing_db
from softauth import SoftAuthenticator
from stynpilot.broker.passkeys import PasskeyStore
from stynpilot.broker.proof import decision_nonce
from stynpilot.identity import account_id
from stynpilot.requests import request_id
from stynpilot.service import InstallerConfig, root_vault

DEVICE = "dtdev_SYNTHETIC900"
HOST = "issuer.example.test"
ISSUER = "https://" + HOST + "/"
OWNER = account_id(verified_issuer=ISSUER, verified_subject="fixture|test-owner")
STATE = Path("/var/lib/stynpilot-installer")
ETC = Path("/etc/stynpilot")
SOCKET = "/run/stynpilot/installer.sock"
OWNER_USER = pwd.getpwuid(1000)
UID, GID = OWNER_USER.pw_uid, OWNER_USER.pw_gid
HOME = Path(OWNER_USER.pw_dir)
CONFIG = HOME / ".config/stynpilot/owner.json"
PYTHON = sys.executable
LAB = Path("/var/lib/stynpilot-lab")
RESUME = LAB / "power-resume.json"


def trim():
    assert not (STATE / "restore-control/pending.json").exists()


def command(*argv):
    return subprocess.run(argv, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def write(path, values, uid=0, gid=0):
    path.write_text(json.dumps(values))
    path.chmod(0o600)
    os.chown(path, uid, gid)


def as_owner(*argv, capture=True):
    return subprocess.run(argv, user=UID, group=GID, extra_groups=[], check=True, text=True,
                          env={**os.environ, "HOME": str(HOME), "XDG_RUNTIME_DIR": f"/run/user/{UID}"},
                          capture_output=capture, timeout=150)


def broker(method, *args):
    probe = ("import json,sys;sys.path.insert(0,'/usr/lib/stynpilot/lib');"
             "from stynpilot.broker.service import BrokerClient;"
             "method,args=json.loads(sys.argv[2]);print(json.dumps(getattr(BrokerClient(sys.argv[1]),method)(*args)))")
    result = as_owner(PYTHON, "-IB", "-c", probe, SOCKET, json.dumps([method, args]))
    return json.loads(result.stdout)


def until(predicate, seconds=210):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if value := predicate():
                return value
        except (subprocess.CalledProcessError, OSError):
            pass
        time.sleep(0.3)
    raise RuntimeError("timed out waiting for guest service")


def issuer():
    public = jwt.algorithms.RSAAlgorithm.to_jwk(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key(),
                                                as_dict=True)
    public.update(kid="fixture", alg="RS256", use="sig")
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = {"keys": [public]} if self.path == "/jwks" else {
                "issuer": ISSUER, "jwks_uri": ISSUER + "jwks",
                "authorization_endpoint": ISSUER + "authorize", "token_endpoint": ISSUER + "token",
                "revocation_endpoint": ISSUER + "revoke", "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"], "grant_types_supported": ["authorization_code", "refresh_token"],
                "scopes_supported": ["openid", "offline_access"]}
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

    cert, key = ("/usr/local/share/ca-certificates/stynpilot-guest-fixture.crt", "/run/stynpilot-fixture.key")
    command("openssl", "req", "-new", "-newkey", "rsa:2048", "-x509", "-nodes", "-days", "2", "-keyout", key,
            "-out", cert, "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}")
    command("update-ca-certificates")
    with Path("/etc/hosts").open("a") as hosts:
        hosts.write(f"\n127.0.0.1 {HOST}\n")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", 443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()


def setup(*, check_restore_path=True):
    issuer()
    ETC.mkdir(mode=0o700, exist_ok=True)
    write(ETC / "installer.json", {"issuer": ISSUER, "approval_client_id": "fixture", "owner": OWNER,
                                  "device": DEVICE, "owner_uid": UID, "state_dir": str(STATE), "socket_path": SOCKET})
    write(ETC / "passkeys.json", {"passkey_rp_id": "owner.example.test", "passkey_origin": "https://owner.example.test"})
    for path in (CONFIG.parent, CONFIG.parent.parent, HOME / ".local", HOME / ".local/state",
                 HOME / "StyNpilot-Projects"):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(path, UID, GID)
    pairing = make_pairing_db(HOME / ".local/state/pairing", [(DEVICE, OWNER, 10**10, None, ["system.read"])])
    for path in (pairing, pairing.parent):
        os.chown(path, UID, GID)
    write(CONFIG, {"issuer": ISSUER, "approval_client_id": "fixture", "authorize_endpoint": ISSUER + "authorize",
                   "token_endpoint": ISSUER + "token", "approval_public_host": "owner.example.test", "approval_port": 18444,
                   "mcp_public_host": "owner.example.test", "mcp_port": 18443,
                   "state_dir": str(HOME / ".local/state/stynpilot"), "broker_socket": SOCKET, "pairing_db": str(pairing),
                   "enrolled_clients": [{"client_id": "fixture", "name": "synthetic", "kind": "chatgpt"}]}, UID, GID)
    as_owner("/usr/bin/stynpilot", "service", "provision", "--config", str(CONFIG))
    command("loginctl", "enable-linger", OWNER_USER.pw_name)
    command("systemctl", "start", f"user@{UID}.service")
    as_owner("systemctl", "--user", "daemon-reload")
    as_owner("systemctl", "--user", "start", "stynpilot-owner.service")
    command("systemctl", "daemon-reload")
    command("systemctl", "start", "stynpilot-installer.service")
    until(lambda: broker("runner", "status"), 30)
    try:
        until(lambda: as_owner("systemctl", "--user", "is-active", "--quiet", "stynpilot-owner.service"), 12)
        from stynpilot.upgrade_worker import endpoint_answers
        until(lambda: endpoint_answers({"port": 18443, "host": "owner.example.test"}), 12)
    except RuntimeError:
        result = subprocess.run(["/usr/bin/systemctl", "--user", "status", "stynpilot-owner.service", "--no-pager"],
                                user=UID, group=GID, extra_groups=[], check=False,
                                env={**os.environ, "HOME": str(HOME), "XDG_RUNTIME_DIR": f"/run/user/{UID}"},
                                text=True, capture_output=True, timeout=10)
        print(result.stdout + result.stderr, flush=True)
        subprocess.run(["journalctl", "-b", "_SYSTEMD_USER_UNIT=stynpilot-owner.service", "--no-pager", "-n", "60"], check=False)
        raise
    write(STATE / "runner-enabled.json", {"enabled": True})
    if not check_restore_path:
        return None
    # Confirm real packaged path dispatch independently from the approved run.
    control = STATE / "restore-control"
    control.mkdir(mode=0o700, exist_ok=True)
    intent = control / "pending.json"
    temporary = control / "fixture-intent.tmp"
    write(temporary, {"phase": "approved", "rid": "a" * 64})
    temporary.rename(intent)
    until(lambda: not intent.exists(), 30)
    assert command("systemctl", "show", "stynpilot-restore.service", "-p", "Result", "--value") == "success"
    assert not (control / "safe.json").exists()
    print("STYNPILOT_PACKAGED_PATH_OK", flush=True)
    return PasskeyStore(STATE / "passkeys.sqlite3", rp_id="owner.example.test", origin="https://owner.example.test")


def run():
    keys = setup()
    fault_cases = "--fault-cases" in sys.argv[1:]
    auth = SoftAuthenticator("https://owner.example.test", "owner.example.test")
    enrollment = "e" * 64
    keys.open_window(enrollment, "Guest passkey", "fixture")
    pending = keys.begin(enrollment)
    key = keys.complete(enrollment, auth.register(bytes.fromhex(pending["challenge"])))
    keys.activate(key["kid"], key["label"], key["pub"], enrollment, "fixture")
    archive_marker = STATE / "attention" / "synthetic-history.json"
    write(archive_marker, {"fixture": "restored"})
    config = InstallerConfig.from_file(ETC / "installer.json")
    vault = root_vault(ETC / "installer.json", config)
    backup = vault.backup_now()
    assert backup["ok"] and backup["complete"], backup
    archive_marker.unlink()
    power_case = "--power-case" in sys.argv[1:]
    approved_restore(auth, backup["backup"], archive_marker, "power" if power_case else "success")
    if fault_cases:
        archive_marker.unlink()
        approved_restore(auth, backup["backup"], archive_marker, "rollback")
        approved_restore(auth, backup["backup"], archive_marker, "safe")
        print("STYNPILOT_RESTORE_FAULT_CASES_OK", flush=True)


def approved_restore(auth, archive, archive_marker, scenario):
    details = broker("restore_preview", archive)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    payload = {**details, "action": "restore_root", "kind": "backup", "side": "root", "owner": OWNER, "device": DEVICE,
               "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}
    rid, _ = request_id(payload)
    challenge = broker("challenge", payload, "approve")["challenge"]
    nonce = bytes.fromhex(decision_nonce("approve", rid, rid, challenge))
    pid = command("systemctl", "show", "stynpilot-installer.service", "-p", "MainPID", "--value")
    if scenario in ("rollback", "safe"):
        as_owner("systemctl", "--user", "stop", "stynpilot-owner.service")
    if scenario == "power":
        arm_power_recovery(rid, archive_marker)
    try:
        result = broker("backup_admin", payload, json.dumps(auth.assert_(nonce)), challenge)
        assert result["pending"], result
    except subprocess.CalledProcessError:
        print("installer socket closed during the approved request, observing durable result", flush=True)
    def result():
        state = broker("status", rid)
        return state if state["state"] in ("done", "failed", "needs_owner_intervention") else None
    held = False
    deadline = time.monotonic() + 210
    state = None
    owner_restarted = False
    while time.monotonic() < deadline and state is None:
        try:
            journal = STATE / "restore-control/pending.json"
            if scenario == "power" and journal.exists() and json.loads(journal.read_text())["phase"] == "verify":
                await_power_cut(journal)
            if scenario == "rollback" and not owner_restarted and journal.exists():
                if json.loads(journal.read_text())["phase"] == "verify_original":
                    as_owner("systemctl", "--user", "start", "stynpilot-owner.service")
                    owner_restarted = True
            state = result()
            if state is None and (STATE / "restore-control/pending.json").exists():
                held |= not broker("runner", "status")["gate_open"]
        except (subprocess.CalledProcessError, OSError):
            pass
        time.sleep(0.2)
    assert state is not None, "no durable terminal restore outcome"
    assert scenario != "power", "restoration finished before the power interruption"
    print("RUNNER_GATE_OBSERVED_CLOSED=" + str(held), flush=True)
    print(json.dumps(state), flush=True)
    verdict = state["result"]
    runner = broker("runner", "status")
    if scenario == "safe":
        assert state["state"] == "needs_owner_intervention" and verdict["restore"] == "safe_recovery" and not runner["gate_open"]
        assert (STATE / "restore-control/safe.json").is_file()
        assert not archive_marker.exists()
        print("STYNPILOT_SAFE_RECOVERY_OK", flush=True)
        return
    trim()
    assert pid != command("systemctl", "show", "stynpilot-installer.service", "-p", "MainPID", "--value")
    assert held and runner["gate_open"] and len(runner["selftest"]["passed"]) == 21, runner
    if scenario == "rollback":
        assert owner_restarted and state["state"] == "failed" and verdict["restore"] == "rolled_back", state
        assert not archive_marker.exists()
        print("STYNPILOT_AUTOMATIC_ROLLBACK_OK", flush=True)
    else:
        assert state["state"] == "done" and archive_marker.is_file(), state
        print("STYNPILOT_APPROVED_RESTORE_OK", flush=True)


def arm_power_recovery(rid, archive_marker):
    LAB.mkdir(mode=0o700)
    write(RESUME, {"rid": rid, "marker": str(archive_marker)})
    unit = Path("/etc/systemd/system/stynpilot-lab-resume.service")
    unit.write_text("""[Unit]
Description=Resume the synthetic Stage 3 power interruption test
ConditionPathExists=/var/lib/stynpilot-lab/power-resume.json
After=local-fs.target
Conflicts=serial-getty@ttyS0.service

[Service]
Type=oneshot
ExecStartPre=/usr/bin/mkdir -p /mnt/stynpilot-fixture
ExecStartPre=/usr/bin/mount -o ro /dev/sr1 /mnt/stynpilot-fixture
ExecStart=/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-restore.py --after-power-cut
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
TimeoutStartSec=360

[Install]
WantedBy=multi-user.target
""")
    command("systemctl", "enable", "stynpilot-lab-resume.service")
    # The next boot uses loopback services only.
    command("systemctl", "mask", "systemd-networkd-wait-online.service")
    Path("/etc/cloud/cloud-init.disabled").touch()
    os.sync()


def await_power_cut(journal):
    pid = int(command("systemctl", "show", "stynpilot-restore.service", "-p", "MainPID", "--value"))
    if not pid:
        return
    os.kill(pid, signal.SIGSTOP)
    try:
        if not journal.exists() or json.loads(journal.read_text())["phase"] != "verify":
            return
        assert not broker("runner", "status")["gate_open"]
        with Path("/dev/ttyS0").open("w") as output:
            print("STYNPILOT_CUT_POWER_NOW", file=output, flush=True)
        time.sleep(30)
        raise RuntimeError("host did not cut power")
    finally:
        os.kill(pid, signal.SIGCONT)


def resume_power_test():
    try:
        expected = json.loads(RESUME.read_text())
        issuer()
        command("systemctl", "start", f"user@{UID}.service")
        as_owner("systemctl", "--user", "start", "stynpilot-owner.service")
        command("systemctl", "start", "stynpilot-installer.service")

        def completed():
            record = broker("status", expected["rid"])
            return record if record["state"] in ("done", "failed", "needs_owner_intervention") else None

        result = until(completed)
        assert result["state"] == "done", result
        assert Path(expected["marker"]).is_file()
        trim()
        runner = broker("runner", "status")
        assert runner["gate_open"] and len(runner["selftest"]["passed"]) == 21, runner
        print("STYNPILOT_POWER_RECOVERY_OK", flush=True)
    finally:
        for argv in (["journalctl", "-b", "-u", "stynpilot-restore.service", "-u", "run-*.service", "--no-pager", "-n", "80"],
                     ["journalctl", "-b", "_SYSTEMD_USER_UNIT=stynpilot-owner.service", "--no-pager", "-n", "30"]):
            subprocess.run(argv, check=False)
        command("systemctl", "poweroff", "--no-block")


if __name__ == "__main__":
    if "--after-power-cut" in sys.argv[1:]:
        resume_power_test()
    else:
        run()
