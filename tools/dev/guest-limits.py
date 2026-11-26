"""Fault injections scoped to the disposable guest, using its real ext4 and cgroups."""
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import py_compile
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
fixture = __import__("guest-restore")  # its DMI, network and UID guards run on import
from stynpilot.broker.proof import decision_nonce
from stynpilot.requests import request_id
from stynpilot.service import InstallerConfig, root_vault
from softauth import SoftAuthenticator

STATE = fixture.STATE
CONTROL = STATE / "restore-control"
FILL = STATE / "fixture-fill"
MODE = STATE / "fixture-pressure"
INJECTED = STATE / "fixture-injected"
UNIT = "stynpilot-restore.service"
TRIGGER = "stynpilot-restore.path"


def compact_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def full():
    with FILL.open("wb", buffering=0) as f:
        while True:
            try:
                f.write(bytes(1 << 20))
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                break
        while True:
            try:
                f.write(bytes(4096))
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
                break
        os.fsync(f.fileno())
    try:
        (STATE / "failed-write").write_bytes(bytes(8192))
    except OSError as error:
        assert error.errno == errno.ENOSPC, error
    else:
        raise AssertionError("ordinary writes still succeed")
    finally:
        (STATE / "failed-write").unlink(missing_ok=True)
    print("GUEST_ORDINARY_WRITE_ENOSPC", flush=True)


def worker():
    from stynpilot import restore_service
    original = restore._trees

    def inject(stage, entries):
        if not MODE.exists():
            return original(stage, entries)
        mode = MODE.read_text()
        assert restore.held(STATE)
        if mode == "disk":
            MODE.unlink()
            INJECTED.write_text(mode)
            full()
        elif mode in ("memory", "memory-once"):
            if mode == "memory-once":
                MODE.unlink()
            with INJECTED.open("a") as evidence:
                cg = Path("/sys/fs/cgroup" + Path("/proc/self/cgroup").read_text().split(":")[-1].strip())
                print(cg.joinpath("memory.max").read_text().strip(), file=evidence)
                evidence.flush()
                os.fsync(evidence.fileno())
            pressure = []
            while True:
                pressure.append(bytearray(8 << 20))  # touch pages until the real restore cgroup kills this worker
        return original(stage, entries)

    restore._trees = inject
    config_path = fixture.ETC / "installer.json"
    return restore_service.run(str(config_path), InstallerConfig.from_file(config_path))


def approve(archive, auth):
    details = fixture.broker("restore_preview", archive)
    payload = dict(details, action="restore_root", kind="backup", side="root", owner=fixture.OWNER, device=fixture.DEVICE,
                   expires_at=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
                   .strftime("%Y-%m-%dT%H:%M:%SZ"))
    rid, _ = request_id(payload)
    challenge = fixture.broker("challenge", payload, "approve")["challenge"]
    nonce = bytes.fromhex(decision_nonce("approve", rid, rid, challenge))
    proof = json.dumps(auth.assert_(nonce))
    result = fixture.broker("backup_admin", payload, proof, challenge)
    assert result["pending"], result
    return rid, payload, proof, challenge


def expect_refusal(method, *args):
    try:
        fixture.broker(method, *args)
    except subprocess.CalledProcessError as err:
        return err.stderr
    raise AssertionError("expected refusal")


def check_authority(rid, challenge, keys, revoked):
    with sqlite3.connect(STATE / "runs.sqlite3") as database:
        assert database.execute("SELECT proof FROM runs WHERE request_id=?", (rid,)).fetchone()[0]
        assert database.execute("SELECT used FROM challenges WHERE challenge=?", (challenge,)).fetchone()[0]
    assert keys.audit_ok()
    assert any(key["kid"] == revoked and key["revoked"] for key in keys.everything())


def terminal(rid):
    status = fixture.broker("status", rid)
    return status if status["state"] in ("done", "failed", "needs_owner_intervention") else None


def limits():
    # A dedicated guest-only ext4 volume leaves the guest OS/journal usable during exhaustion.
    volume = Path("/var/tmp/stynpilot-fixture.ext4")
    with volume.open("wb") as file:
        file.truncate(256 << 20)
    fixture.command("mkfs.ext4", "-q", "-F", str(volume))
    STATE.mkdir(mode=0o700, exist_ok=True)
    fixture.command("mount", "-o", "loop", str(volume), str(STATE))
    STATE.chmod(0o700)
    keys = fixture.setup()
    auth = SoftAuthenticator("https://owner.example.test", "owner.example.test")
    enrollment = "e" * 64
    keys.open_window(enrollment, "Guest passkey", "fixture")
    challenge = keys.begin(enrollment)["challenge"]
    result = keys.complete(enrollment, auth.register(bytes.fromhex(challenge)))
    keys.activate(result["kid"], result["label"], result["pub"], enrollment, "fixture")

    restored = STATE / "attention/synthetic-archived.json"
    fixture.write(restored, {"record": "archived"})
    config_path = fixture.ETC / "installer.json"
    vault = root_vault(config_path, InstallerConfig.from_file(config_path))
    archived = vault.backup_now()
    assert archived["ok"] and archived["complete"], archived
    restored.unlink()
    rejected = SoftAuthenticator("https://owner.example.test", "owner.example.test")
    enrollment = "d" * 64
    keys.open_window(enrollment, "Revoked fixture key", "fixture")
    challenge = keys.begin(enrollment)["challenge"]
    revoked = keys.complete(enrollment, rejected.register(bytes.fromhex(challenge)))
    keys.activate(revoked["kid"], revoked["label"], revoked["pub"], enrollment, "fixture")
    keys.revoke(revoked["kid"], "c" * 64)
    archive = archived["backup"]
    archive_file = vault.folder / archive
    sha = compact_hash(archive_file)
    original = restore._manifest_hash(STATE)

    memory = (Path(__file__).parent / "oom-case").exists()
    if not memory:
        full()
        try:
            refused = expect_refusal("restore_preview", archive)
            assert "insufficient_combined_restore_storage" in refused, refused
            assert not restore.held(STATE)
        finally:
            FILL.unlink(missing_ok=True)
        assert restore._manifest_hash(STATE) == original and compact_hash(archive_file) == sha
        print("STYNPILOT_DISK_BEFORE_OK", flush=True)

    drop = Path("/etc/systemd/system/stynpilot-restore.service.d")
    drop.mkdir()
    override = drop / "pressure.conf"
    override.write_text("[Service]\nExecStart=\nExecStart=/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-limits.py --worker\n")
    fixture.command("systemctl", "daemon-reload")
    if memory:
        MODE.write_text("memory-once")
        rid, payload, proof, challenge = approve(archive, auth)
        tx = CONTROL / rid
        result = fixture.until(lambda: terminal(rid), 90)
        assert result["state"] == "done" and restored.exists(), result
        assert fixture.broker("runner", "status")["gate_open"]
        assert compact_hash(archive_file) == sha
        assert len(list(vault.folder.glob("*.stynvault"))) == 2
        assert len(list(tx.glob("*.stynvault"))) == 1
        assert not (tx / "staging").exists()
        assert expect_refusal("backup_admin", payload, proof, challenge)
        check_authority(rid, challenge, keys, revoked["kid"])
        restored.unlink()
        original = restore._manifest_hash(STATE)
        print("GUEST_OOM_RESUME_OK", flush=True)

        # Allow the service manager's generic start-rate interval to expire between independent approvals.
        time.sleep(12)
        INJECTED.unlink()
        MODE.write_text("memory")
        rid, payload, proof, challenge = approve(archive, auth)
        tx = CONTROL / rid
        result = fixture.until(lambda: terminal(rid), 90)
        assert result["state"] == "needs_owner_intervention", result
        assert not fixture.broker("runner", "status")["gate_open"]
        attempts = INJECTED.read_text().splitlines()
        assert attempts == [str(1536 << 20)] * 3, attempts
        time.sleep(4)
        assert INJECTED.read_text().splitlines() == attempts
        journal = fixture.command("journalctl", "-b", "-u", UNIT, "--no-pager")
        print("\n".join(line for line in journal.splitlines() if "oom" in line.lower()), flush=True)
        assert "oom-kill" in journal or "OOM killer" in journal, journal
        assert restore._manifest_hash(STATE) == original and compact_hash(archive_file) == sha
        assert len(list(vault.folder.glob("*.stynvault"))) == 3, "temporary safety copies accumulated"
        assert len(list(tx.glob("*.stynvault"))) == 1
        assert not (tx / "staging").exists()
        assert json.loads((CONTROL / "safe.json").read_text())["error"] == "restore_worker_retry_limit"
        assert not (CONTROL / "pending.json").exists()
        assert expect_refusal("backup_admin", payload, proof, challenge)
        check_authority(rid, challenge, keys, revoked["kid"])
        print("GUEST_OOM_ATTEMPTS", len(attempts), "CGROUP_MEMORY_MAX", attempts[0], flush=True)
        print("STYNPILOT_CGROUP_OOM_OK", flush=True)
        return
    MODE.write_text("disk")
    rid, payload, proof, challenge = approve(archive, auth)
    error = None
    try:
        fixture.until(lambda: INJECTED.exists(), 30)
        end = fixture.until(lambda: terminal(rid), 18)
        assert end["state"] == "needs_owner_intervention", end
        assert not fixture.broker("runner", "status")["gate_open"]
        assert restore._manifest_hash(STATE) == original
        assert compact_hash(archive_file) == sha
        assert (CONTROL / "safe.json").exists()
        assert not (CONTROL / "pending.json").exists()
        assert len(list((CONTROL / rid).glob("*.stynvault"))) == 1
        assert expect_refusal("backup_admin", payload, proof, challenge)
        assert not (CONTROL / restore.RESERVE).exists()
        check_authority(rid, challenge, keys, revoked["kid"])
        print("STYNPILOT_DISK_DURING_OK", flush=True)
    except Exception as err:
        error = err
        print("DISK_BLOCKER", type(err).__name__, str(err), flush=True)
    finally:
        FILL.unlink(missing_ok=True)
    if error:
        raise error

    # A fresh guest is needed after the deliberate terminal hold. OOM is tested in a separate invocation.


def upgrade():
    source = Path("/usr/lib/stynpilot/lib/stynpilot/__init__.py")
    old = source.read_bytes()
    info = source.stat()
    assert b"0.1.0.dev24" in old
    source.write_bytes(old.replace(b"0.1.0.dev24", b"0.1.0.dev22"))
    os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns))
    py_compile.compile(str(source), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
    source.write_bytes(old)
    os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert fixture.command("dpkg-query", "-W", "-f=${Version}", "stynpilot") == "0.1.0~dev24"
    assert fixture.command("/usr/bin/stynpilot", "version") == "0.1.0.dev22"
    fixture.setup(check_restore_path=False)
    fixture.write(STATE / "runner-enabled.json", {"enabled": True})
    old_test = fixture.broker("runner", "selftest")
    assert old_test["version"] == "0.1.0.dev22" and len(old_test["passed"]) == 21, old_test
    fixture.command("dpkg", "-i", next(str(p) for p in Path("/mnt/stynpilot-fixture/repo").glob("stynpilot*dev25*.deb")))
    fixture.command("systemctl", "daemon-reload")
    fixture.as_owner("systemctl", "--user", "daemon-reload")
    fixture.command("systemctl", "restart", "stynpilot-installer.service")
    fixture.as_owner("systemctl", "--user", "restart", "stynpilot-owner.service")
    assert fixture.command("dpkg-query", "-W", "-f=${Version}", "stynpilot") == "0.1.0~dev25"
    assert fixture.command("/usr/bin/stynpilot", "version") == "0.1.0.dev25"
    status = fixture.until(lambda: fixture.broker("runner", "status"), 30)
    assert not status["gate_open"] and status["selftest"]["version"] == "0.1.0.dev22", status
    current = fixture.broker("runner", "selftest")
    assert current["version"] == "0.1.0.dev25" and len(current["passed"]) == 21 and current["ok"], current
    assert fixture.broker("runner", "status")["gate_open"]
    print("STYNPILOT_PACKAGED_DEV24_UPGRADE_OK", flush=True)


if (Path(__file__).parent / "upgrade-case").exists():
    upgrade()
else:
    from stynpilot import root_restore as restore

    if "--worker" in sys.argv:
        raise SystemExit(worker())
    limits()
