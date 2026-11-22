"""G7: backup/restore, doctor, first-run setup (incl. the polkit root step) and the .deb contents."""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    import jwt
    from stynpilot import backup, doctor, service, setup_wizard
    from stynpilot.service import ConfigError
    import test_service as ts
    from test_service import owner_data
except ImportError:          # pragma: no cover
    jwt = None

import test_broker as tb
from legacy_pairing import make_pairing_db

ROOT = Path(__file__).resolve().parent.parent
HOME_MODE = 0o700


def tmpdir(test):
    t = tempfile.TemporaryDirectory()
    test.addCleanup(t.cleanup)
    path = Path(t.name)
    os.chmod(path, 0o700)
    return path


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp))
        service.provision_owner_state(self.config)
        from stynpilot.server.clients import RevocationFile
        RevocationFile(self.config.state_dir / "revoked-clients.json").set_revoked("claude-connector", True)

    def test_backup_then_restore_into_an_empty_folder_keeps_revocations(self):
        archive = self.tmp / "b" / "backup.tar"
        manifest = backup.make_backup(self.config.state_dir, archive)
        self.assertEqual(set(manifest["files"]), set(backup.OWNER_FILES))
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        restored = self.tmp / "restored"
        backup.restore_backup(archive, restored)
        self.assertEqual(json.loads((restored / "revoked-clients.json").read_text()), {"revoked": ["claude-connector"]})
        self.assertEqual((restored / "requests.sqlite3").stat().st_mode & 0o777, 0o600)

    def test_restore_refuses_to_overwrite_and_a_tampered_archive_is_refused(self):
        archive = self.tmp / "b.tar"
        backup.make_backup(self.config.state_dir, archive)
        with self.assertRaises(backup.BackupError) as refused:
            backup.restore_backup(archive, self.config.state_dir)
        self.assertIn("not_empty", str(refused.exception))
        bad = self.tmp / "bad.tar"
        with tarfile.open(archive) as src, tarfile.open(bad, "w") as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == "revoked-clients.json":
                    data = b'{"revoked": []}'                                   # someone un-revokes the client
                member.size = len(data)
                import io
                dst.addfile(member, io.BytesIO(data))
        with self.assertRaises(backup.BackupError) as refused:
            backup.restore_backup(bad, self.tmp / "r2")
        self.assertIn("hash", str(refused.exception))

    def test_odd_archive_members_are_refused(self):
        evil = self.tmp / "evil.tar"
        import io
        with tarfile.open(evil, "w") as tar:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(backup.BackupError):
            backup.read_backup(evil)

    def test_backup_never_overwrites_an_existing_file_and_needs_a_private_folder(self):
        archive = self.tmp / "once.tar"
        backup.make_backup(self.config.state_dir, archive)
        with self.assertRaises(FileExistsError):
            backup.make_backup(self.config.state_dir, archive)
        os.chmod(self.config.state_dir, 0o755)
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.config.state_dir, self.tmp / "x.tar")

    def test_partial_and_cross_kind_backups_are_refused(self):
        import io
        full = self.tmp / "full.tar"
        backup.make_backup(self.config.state_dir, full)

        def rewrite(dest, drop=None, add=None, kind=None):
            with tarfile.open(full) as src, tarfile.open(dest, "w") as out:
                data = {m.name: src.extractfile(m).read() for m in src.getmembers()}
            manifest = json.loads(data.pop("manifest.json"))
            if drop:
                data.pop(drop)
                manifest["files"].pop(drop)
            if add:
                data[add] = b"x"
                manifest["files"][add] = hashlib.sha256(b"x").hexdigest()
            if kind:
                manifest["kind"] = kind
            data["manifest.json"] = json.dumps(manifest).encode()
            with tarfile.open(dest, "w") as out:
                for name, content in data.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    out.addfile(info, io.BytesIO(content))
        rewrite(self.tmp / "missing.tar", drop="revoked-clients.json")                # hashes valid, set incomplete
        with self.assertRaises(backup.BackupError) as e:
            backup.restore_backup(self.tmp / "missing.tar", self.tmp / "r1")
        self.assertIn("exactly_the_expected", str(e.exception))
        rewrite(self.tmp / "extra.tar", add="runs.sqlite3")                            # an installer file smuggled in
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(self.tmp / "extra.tar", self.tmp / "r2")
        rewrite(self.tmp / "kind.tar", kind="root")                                    # labelled as a root backup
        with self.assertRaises(backup.BackupError):
            backup.restore_backup(self.tmp / "kind.tar", self.tmp / "r3")
        with self.assertRaises(backup.BackupError) as e:
            backup.restore_backup(full, self.tmp / "r4", kind="root")                  # owner archive as root records
        self.assertIn("owner_backup_not_a_root", str(e.exception))
        self.assertFalse((self.tmp / "r1").exists() and any((self.tmp / "r1").iterdir()))

    def test_a_missing_state_file_stops_the_backup(self):
        (self.config.state_dir / "revoked-clients.json").unlink()
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.config.state_dir, self.tmp / "y.tar")


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class RootBackupTests(unittest.TestCase):
    """Software-install rollback records are a separate backup kind, never mixed with owner state."""

    def setUp(self):
        from stynpilot.broker.executor import Runs
        from stynpilot.ledger import InstallLedger
        self.tmp = tmpdir(self)
        self.state = self.tmp / "inst"
        self.state.mkdir(mode=0o700)
        self.runs = Runs(self.state / "runs.sqlite3")
        self.ledger = InstallLedger(self.state / "installs.sqlite3")
        self.ledger.record(rollback_id="a1" * 8, software="htop", owner="o", device="d", request_id="r1",
                           snapshot_id="abc", snapshot_verified=True)
        snap = self.state / "snapshots/abc/debs"
        snap.mkdir(parents=True)
        (self.state / "snapshots/abc/files").mkdir()
        (self.state / "attention").mkdir()
        self.deb = b"deb bytes"
        (snap / "htop_1.deb").write_bytes(self.deb)
        (self.state / "snapshots/abc/files/c0py").write_bytes(b"conf")
        (self.state / "snapshots/abc/manifest.json").write_text(json.dumps({
            "debs": {"htop": {"file": "htop_1.deb", "sha256": hashlib.sha256(self.deb).hexdigest()}},
            "files": {"/etc/x": {"copy": "c0py", "sha256": hashlib.sha256(b"conf").hexdigest()}}}))
        (self.state / "attention/r.json").write_text("{}")

    def test_root_backup_round_trips_ledgers_snapshots_and_attention_records(self):
        out = self.tmp / "root.tar"
        manifest = backup.make_backup(self.state, out, kind="root")
        self.assertEqual(manifest["kind"], "root")
        self.assertIn("snapshots/abc/debs/htop_1.deb", manifest["files"])
        dest = self.tmp / "restored"
        backup.restore_backup(out, dest, kind="root")
        self.assertEqual((dest / "snapshots/abc/debs/htop_1.deb").read_bytes(), self.deb)
        self.assertTrue((dest / "attention/r.json").exists())
        self.assertEqual((dest / "runs.sqlite3").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(backup.BackupError) as refused:                      # owner restore of a root archive
            backup.restore_backup(out, self.tmp / "x", kind="owner")
        self.assertIn("root_backup", str(refused.exception))

    def test_snapshot_without_its_files_or_with_changed_packages_is_refused(self):
        import io
        out = self.tmp / "root.tar"
        backup.make_backup(self.state, out, kind="root")

        def rebuilt(name, mutate):
            with tarfile.open(out) as src:
                data = {m.name: src.extractfile(m).read() for m in src.getmembers()}
            manifest = json.loads(data.pop("manifest.json"))
            mutate(data, manifest)
            data["manifest.json"] = json.dumps(manifest).encode()
            with tarfile.open(self.tmp / name, "w") as dst:
                for n, c in data.items():
                    info = tarfile.TarInfo(n)
                    info.size = len(c)
                    dst.addfile(info, io.BytesIO(c))
            return self.tmp / name

        def drop_deb(d, m):
            d.pop("snapshots/abc/debs/htop_1.deb")
            m["files"].pop("snapshots/abc/debs/htop_1.deb")

        def swap_deb(d, m):
            d["snapshots/abc/debs/htop_1.deb"] = b"evil"
            m["files"]["snapshots/abc/debs/htop_1.deb"] = hashlib.sha256(b"evil").hexdigest()

        def drop_db(d, m):
            d.pop("installs.sqlite3")
            m["files"].pop("installs.sqlite3")
        for name, fn, expect in (("a.tar", drop_deb, "snapshot_package"), ("b.tar", swap_deb, "snapshot_package"),
                                 ("c.tar", drop_db, "missing_its_databases")):
            with self.assertRaises(backup.BackupError) as refused:
                backup.restore_backup(rebuilt(name, fn), self.tmp / ("r_" + name), kind="root")
            self.assertIn(expect, str(refused.exception))

    def test_backup_of_state_with_a_symlink_or_missing_folder_is_refused(self):
        (self.state / "snapshots/abc/link").symlink_to("/etc/passwd")
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.state, self.tmp / "l.tar", kind="root")

    def test_root_helper_acts_only_for_the_authenticated_caller(self):
        from stynpilot import root_helper
        if os.geteuid() < 1000:
            self.skipTest("needs a normal user id")
        env = {"PKEXEC_UID": str(os.geteuid())}
        out = self.tmp / "h.tar"
        root_helper.root_backup(out, state=self.state, environ=env, geteuid=lambda: 0)
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ConfigError):
            root_helper.root_backup(self.tmp / "n.tar", state=self.state, environ={}, geteuid=lambda: 0)         # not polkit
        with self.assertRaises(ConfigError):
            root_helper.root_backup(self.tmp / "n.tar", state=self.state, environ={"PKEXEC_UID": "0"}, geteuid=lambda: 0)
        with self.assertRaises(ConfigError):
            root_helper.root_backup(self.tmp / "n.tar", state=self.state, environ=env, geteuid=lambda: 1000)     # not root
        loose = self.tmp / "loose"
        loose.mkdir(mode=0o755)
        os.chmod(loose, 0o755)
        with self.assertRaises(ConfigError):
            root_helper.root_backup(loose / "x.tar", state=self.state, environ=env, geteuid=lambda: 0)
        os.chmod(out, 0o644)
        with self.assertRaises(ConfigError):
            root_helper.root_restore(out, state=self.tmp / "empty", environ=env, geteuid=lambda: 0)


    # --- consistency, locking, ledger/snapshot cross-check, bounds -----------------------------------
    def test_backup_is_refused_while_an_install_or_rollback_holds_the_operation_lock_and_the_change_is_refused_while_backing_up(self):
        from stynpilot import statelock
        with statelock.operation(self.state):                                       # an install/rollback is in progress
            with self.assertRaises(backup.BackupError) as refused:
                backup.make_backup(self.state, self.tmp / "b.tar", kind="root")
            self.assertIn("is_running", str(refused.exception))
        self.assertFalse((self.tmp / "b.tar").exists())                              # nothing half-written
        real = backup._gather
        seen = {}

        def while_reading(state, kind):                                              # a change tries to start mid-backup
            with self.assertRaises(statelock.Busy):
                with statelock.operation(state):
                    pass
            seen["refused"] = True
            return real(state, kind)
        backup._gather = while_reading
        try:
            backup.make_backup(self.state, self.tmp / "ok.tar", kind="root")
        finally:
            backup._gather = real
        self.assertTrue(seen["refused"])

    def test_the_real_executor_refuses_to_change_anything_while_a_backup_holds_the_lock(self):
        from stynpilot import statelock
        from stynpilot.broker.executor import ExecutionDenied, Executor
        executor = Executor(state_dir=self.state, owner=tb.OWNER, device=tb.DEVICE, verifier=None, require_root=False)
        with statelock.operation(self.state):
            for call in (executor.install, executor.rollback):
                with self.assertRaises(ExecutionDenied) as refused:
                    call({}, "proof", "challenge")
                self.assertEqual(refused.exception.code, "a_backup_or_restore_is_running_try_again")

    def test_restore_is_refused_while_the_installer_is_running(self):
        from stynpilot.broker.executor import Executor
        out = self.tmp / "root.tar"
        backup.make_backup(self.state, out, kind="root")
        live = self.tmp / "live"
        live.mkdir(mode=0o700)
        executor = Executor(state_dir=live, owner=tb.OWNER, device=tb.DEVICE, verifier=None, require_root=False)
        with self.assertRaises(backup.BackupError) as refused:
            backup.restore_backup(out, live, kind="root")
        self.assertIn("installer_is_running", str(refused.exception))
        self.assertEqual(sorted(p.name for p in live.iterdir() if p.name.endswith(".sqlite3")),
                         ["installs.sqlite3", "runs.sqlite3"])                       # only the installer's own, untouched
        executor._alive and os.close(executor._alive)                                # installer stopped
        executor._alive = None

    def test_installer_refuses_to_start_during_a_restore(self):
        from stynpilot import statelock
        from stynpilot.broker.executor import ExecutionDenied, Executor
        with statelock.exclusive_for_restore(self.state):
            with self.assertRaises(ExecutionDenied):
                Executor(state_dir=self.state, owner=tb.OWNER, device=tb.DEVICE, verifier=None, require_root=False)

    def test_an_interrupted_install_blocks_the_backup_until_the_installer_has_recorded_it(self):
        self.runs.issue("r2", "approve")
        self.runs.consume(challenge=self.runs_challenge("r2"), request_id="r2", decision="approve", proof="p", kind="install")
        self.assertEqual(self.runs.running(), ["r2"])
        with self.assertRaises(backup.BackupError) as refused:
            backup.make_backup(self.state, self.tmp / "x.tar", kind="root")
        self.assertIn("marked_running", str(refused.exception))
        self.runs.finish("r2", "needs_owner_intervention", {"ok": False})            # what the installer does when it restarts
        (self.state / "attention/r2.json").write_text("{}")
        out = self.tmp / "after.tar"
        manifest = backup.make_backup(self.state, out, kind="root")
        self.assertIn("attention/r2.json", manifest["files"])                         # the owner-must-check record is kept

    def runs_challenge(self, rid):
        import sqlite3
        db = sqlite3.connect(self.state / "runs.sqlite3")
        try:
            return db.execute("SELECT challenge FROM challenges WHERE request_id=?", (rid,)).fetchone()[0]
        finally:
            db.close()

    def test_every_snapshot_the_ledger_points_at_must_be_in_the_backup(self):
        shutil.rmtree(self.state / "snapshots/abc")                                   # snapshot lost, ledger still points at it
        with self.assertRaises(backup.BackupError) as refused:
            backup.make_backup(self.state, self.tmp / "m.tar", kind="root")
        self.assertIn("ledger_points_at_a_snapshot", str(refused.exception))
        self.assertFalse((self.tmp / "m.tar").exists())

    def test_incomplete_snapshots_are_refused_for_backup(self):
        (self.state / "snapshots/abc/debs/htop_1.deb").unlink()                       # package file missing
        with self.assertRaises(backup.BackupError) as refused:
            backup.make_backup(self.state, self.tmp / "i1.tar", kind="root")
        self.assertIn("snapshot_package", str(refused.exception))
        (self.state / "snapshots/abc/debs/htop_1.deb").write_bytes(b"changed")        # present but different from its hash
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.state, self.tmp / "i2.tar", kind="root")
        (self.state / "snapshots/abc/debs/htop_1.deb").write_bytes(self.deb)
        (self.state / "snapshots/abc/manifest.json").unlink()                          # half-made snapshot (crash)
        with self.assertRaises(backup.BackupError) as refused:
            backup.make_backup(self.state, self.tmp / "i3.tar", kind="root")
        self.assertIn("without_its_manifest", str(refused.exception))

    def test_a_ledger_entry_already_rolled_back_does_not_demand_its_snapshot(self):
        self.ledger.mark_rolled_back("a1" * 8)
        shutil.rmtree(self.state / "snapshots/abc")
        backup.make_backup(self.state, self.tmp / "rb.tar", kind="root")

    def archive_with(self, entries, kind="owner"):
        import io
        path = self.tmp / ("dup%d.tar" % len(list(self.tmp.iterdir())))
        with tarfile.open(path, "w") as tar:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return path

    def test_duplicate_archive_members_are_refused(self):
        good = json.dumps({"schema": 1, "kind": "owner", "created": 1, "files": {}}).encode()
        path = self.archive_with([("requests.sqlite3", b"first"), ("requests.sqlite3", b"second"),
                                  ("manifest.json", good)])
        with self.assertRaises(backup.BackupError) as refused:
            backup.read_backup(path)
        self.assertIn("repeats", str(refused.exception))
        twin = self.archive_with([("manifest.json", good), ("manifest.json", good)])
        with self.assertRaises(backup.BackupError):
            backup.read_backup(twin)

    def test_size_limits_apply_when_making_and_when_reading(self):
        old = backup._MAX_TOTAL, backup._MAX_FILE, backup._MAX_FILES
        try:
            backup._MAX_TOTAL = 10
            with self.assertRaises(backup.BackupError) as refused:
                backup.make_backup(self.state, self.tmp / "big.tar", kind="root")
            self.assertIn("too_large", str(refused.exception))
            backup._MAX_TOTAL = old[0]
            good = self.tmp / "g.tar"
            backup.make_backup(self.state, good, kind="root")
            for limit, value in (("_MAX_TOTAL", 100), ("_MAX_FILE", 50), ("_MAX_FILES", 2)):
                setattr(backup, limit, value)
                with self.assertRaises(backup.BackupError):
                    backup.read_backup(good)
                backup._MAX_TOTAL, backup._MAX_FILE, backup._MAX_FILES = old
        finally:
            backup._MAX_TOTAL, backup._MAX_FILE, backup._MAX_FILES = old


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        make_pairing_db(self.tmp / "pairing", [(ts.DEVICE, ts.OWNER, time.time() + 3600, None, ["workspace.propose"])])
        self.pairing = next((self.tmp / "pairing").iterdir())
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp, pairing_db=str(self.pairing)))

    def levels(self, **kw):
        return {name: level for name, level, _ in doctor.run_checks(owner_config=self.config, units=False, **kw)}

    def test_unprovisioned_state_is_a_failure_with_the_safe_remedy_and_nothing_is_created(self):
        levels = self.levels(listeners=lambda h, p: [])
        self.assertEqual(levels["owner state folder"], doctor.FAIL)
        self.assertFalse(self.config.state_dir.exists())                            # doctor never creates anything

    def test_healthy_state_and_loopback_listeners_pass(self):
        service.provision_owner_state(self.config)
        checks = doctor.run_checks(owner_config=self.config, units=False, listeners=lambda h, p: [(h, p)],
                                   client=SimpleNamespace(status=lambda rid: {"state": "not_started"}))
        levels = {n: l for n, l, _ in checks}
        self.assertEqual(levels["owner state files"], doctor.OK)
        self.assertEqual(levels["approval page listener"], doctor.OK)
        self.assertEqual(levels["pairing database"], doctor.OK)
        self.assertEqual(levels["installer answers"], doctor.OK)
        self.assertEqual(levels["installer socket"], doctor.WARN)                  # not running here: a warning, not fail
        self.assertEqual(doctor.exit_code(checks), 0)

    def test_loose_permissions_and_missing_state_are_failures(self):
        service.provision_owner_state(self.config)
        os.chmod(self.config.state_dir / "revoked-clients.json", 0o644)
        (self.config.state_dir / "provisioned.json").unlink()
        checks = doctor.run_checks(owner_config=self.config, units=False)
        by = {n: (l, d) for n, l, d in checks}
        self.assertEqual(by["state file revoked-clients.json"][0], doctor.FAIL)
        self.assertEqual(by["owner state files"][0], doctor.FAIL)
        self.assertIn("never recreate by hand", by["owner state files"][1])
        self.assertEqual(doctor.exit_code(checks), 1)

    def test_missing_dependency_and_unreadable_pairing_are_reported(self):
        def importer(name):
            if name == "mcp":
                raise ImportError(name)
        self.assertEqual(doctor.check_modules(importer)[1], doctor.FAIL)
        self.assertEqual(doctor.check_pairing(self.tmp / "none.db")[1], doctor.FAIL)

    def test_socket_checks_and_report_text_never_leak_values(self):
        import socket
        path = self.tmp / "s.sock"
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(str(path))
        os.chmod(path, 0o666)
        self.assertEqual(doctor.check_socket(path)[1], doctor.FAIL)
        os.chmod(path, 0o600)
        self.assertEqual(doctor.check_socket(path, os.geteuid())[1], doctor.OK)
        text = doctor.render(doctor.run_checks(owner_config=self.config, units=False))
        self.assertIn("Nothing was changed", text)
        self.assertNotIn("approval-app", text)

    def test_existing_preview26_service_is_reported_as_left_alone(self):
        d = self.tmp / "units"
        d.mkdir()
        (d / "stynpilot-remote-broker.service").write_text("x")
        name, level, detail = doctor.check_legacy((str(d),))
        self.assertEqual(level, doctor.OK)
        self.assertIn("untouched", detail)


FORM = {"issuer": "tenant.example.auth", "approval_client_id": "approval-app", "approval_public_host": "pc.example.test:8444",
        "mcp_public_host": "pc.example.test", "pairing_db": "", "chatgpt_client_id": "cg", "claude_client_id": "cl"}


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class SetupTests(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        make_pairing_db(self.home / ".local/state/stynpilot-owner", [(ts.DEVICE, ts.OWNER, time.time() + 3600, None, ["workspace.propose"])])
        self.pairing = self.home / ".local/state/stynpilot-owner/pairing.sqlite3"
        self.form = dict(FORM, pairing_db=str(self.pairing))
        self.uid = os.geteuid()
        self.root_config = self.home / "etc-installer.json"            # stands in for /etc/stynpilot/installer.json
        self.paths = setup_wizard.default_paths(self.home)
        real_uid = setup_wizard.ROOT_UID
        setup_wizard.ROOT_UID = os.geteuid()                              # stands in for "owned by root" in this test
        self.addCleanup(setattr, setup_wizard, "ROOT_UID", real_uid)

    def install_root_config(self):
        """The real privileged step (root_setup), as pkexec would run it: settings file 0600 + public receipt."""
        setup_wizard.root_setup(self.paths["proposed"], dest=self.root_config, geteuid=lambda: 0, invoking_uid=self.uid)

    @property
    def receipt(self):
        return self.root_config.with_name(setup_wizard.RECEIPT_NAME)

    def status(self):
        return setup_wizard.setup_status(self.home, self.uid, self.root_config)

    def resume(self, form="form", **kw):
        return setup_wizard.resume_setup(self.form if form == "form" else form, self.home, self.uid, self.root_config)

    def test_the_existing_pairing_database_is_found_read_only(self):
        self.assertEqual(setup_wizard.discover_pairing_db(self.home), str(self.pairing))
        before = hashlib.sha256(self.pairing.read_bytes()).hexdigest()
        setup_wizard.discover_pairing_db(self.home)
        self.assertEqual(hashlib.sha256(self.pairing.read_bytes()).hexdigest(), before)
        self.assertIsNone(setup_wizard.discover_pairing_db(self.home / "nowhere"))

    def test_setup_writes_private_config_derives_owner_from_pairing_and_provisions_state(self):
        status = self.resume()
        self.assertEqual((status["config"], status["proposal"], status["state"], status["system"]),
                         ("ok", "ok", "complete", "pending"))
        self.assertEqual(self.paths["config"].stat().st_mode & 0o777, 0o600)
        proposal = json.loads(self.paths["proposed"].read_text())
        self.assertEqual((proposal["owner"], proposal["device"], proposal["owner_uid"]), (ts.OWNER, ts.DEVICE, self.uid))
        self.assertEqual(service.OwnerConfig.from_file(self.paths["config"]).issuer, "https://tenant.example.auth/")

    def test_running_setup_again_with_the_same_answers_is_a_safe_resume_that_changes_nothing(self):
        self.resume()
        from stynpilot.server.clients import RevocationFile
        RevocationFile(self.paths["state"] / "revoked-clients.json").set_revoked("claude-connector", True)
        digest = lambda: {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.paths["state"].iterdir()}
        before = digest()
        self.resume()
        self.resume(None)
        self.assertEqual(digest(), before)                                         # revocation untouched

    def test_interrupted_after_owner_settings_resumes_without_retyping(self):
        real = setup_wizard.write_new_private

        def dies_on_proposal(path, data):
            if Path(path).name == "installer.proposed.json":
                raise KeyboardInterrupt("closed the window")
            return real(path, data)
        setup_wizard.write_new_private = dies_on_proposal
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.resume()
        finally:
            setup_wizard.write_new_private = real
        status = setup_wizard.setup_status(self.home, self.uid, self.root_config)
        self.assertEqual((status["config"], status["proposal"], status["state"]), ("ok", "missing", "missing"))
        done = self.resume(None)                                                   # "Continue where I left off"
        self.assertEqual((done["proposal"], done["state"]), ("ok", "complete"))

    def test_interrupted_while_creating_state_completes_only_the_missing_files_and_keeps_existing_ones(self):
        from stynpilot.server.clients import RevocationFile
        self.resume()
        for name in ("provisioned.json", "requests.sqlite3"):                       # as if it died before the end
            (self.paths["state"] / name).unlink()
        RevocationFile(self.paths["state"] / "revoked-clients.json").set_revoked("claude-connector", True)
        self.assertEqual(setup_wizard.setup_status(self.home, self.uid, self.root_config)["state"], "partial")
        self.resume(None)
        self.assertEqual(setup_wizard.setup_status(self.home, self.uid, self.root_config)["state"], "complete")
        self.assertEqual(RevocationFile(self.paths["state"] / "revoked-clients.json").revoked(), {"claude-connector"})

    def test_after_setup_is_complete_lost_state_is_never_recreated(self):
        self.resume()
        for p in list(self.paths["state"].iterdir()):
            p.unlink()
        self.install_root_config()                                                  # the root step had been done
        with self.assertRaises(ConfigError) as refused:
            self.resume(None)
        self.assertIn("restore_a_backup", str(refused.exception))
        self.assertEqual(list(self.paths["state"].iterdir()), [])
        # and a finished provisioning whose other files vanish is refused inside provisioning itself
        self.root_config.unlink()
        service.provision_owner_state(service.OwnerConfig.from_file(self.paths["config"]), resume=True)
        (self.paths["state"] / "revoked-clients.json").unlink()
        with self.assertRaises(ConfigError):
            service.provision_owner_state(service.OwnerConfig.from_file(self.paths["config"]), resume=True)

    def test_existing_settings_that_differ_or_are_tampered_fail_closed(self):
        self.resume()
        with self.assertRaises(ConfigError):
            self.resume(dict(self.form, approval_client_id="somebody-else"))        # typed something different
        data = json.loads(self.paths["proposed"].read_text())
        os.chmod(self.paths["proposed"], 0o600)
        self.paths["proposed"].write_text(json.dumps(dict(data, owner_uid=1234)))   # proposed root config tampered
        with self.assertRaises(ConfigError) as refused:
            self.resume(None)
        self.assertIn("do_not_match", str(refused.exception))
        self.assertEqual(setup_wizard.setup_status(self.home, self.uid, self.root_config)["proposal"], "mismatch")
        os.chmod(self.paths["config"], 0o644)                                       # owner settings made world-readable
        with self.assertRaises(ConfigError):
            self.resume(None)
        self.assertEqual(setup_wizard.setup_status(self.home, self.uid, self.root_config)["config"], "invalid")

    def test_the_root_step_leaves_a_public_receipt_and_a_private_config_and_setup_checks_only_the_receipt(self):
        self.resume()
        self.install_root_config()
        self.assertEqual(self.root_config.stat().st_mode & 0o777, 0o600)            # the settings stay private
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o644)                # the receipt carries no secrets
        record = json.loads(self.receipt.read_text())
        self.assertEqual(set(record), {"schema", "owner_uid", "config_sha256"})
        self.assertEqual(record["owner_uid"], self.uid)
        self.assertTrue(self.status()["complete"])
        os.chmod(self.root_config, 0)                                               # unreadable even to us: still "done"
        self.assertEqual(self.status()["system"], "done")
        os.chmod(self.root_config, 0o600)

    def test_wrong_or_tampered_receipts_and_loose_files_are_refused(self):
        self.resume()
        self.install_root_config()
        good = self.receipt.read_text()

        def put(**changes):
            os.chmod(self.receipt, 0o644)
            self.receipt.write_text(json.dumps(dict(json.loads(good), **changes)))
        for label, change in (("other owner", dict(owner_uid=self.uid + 1)), ("other settings", dict(config_sha256="0" * 64)),
                              ("future schema", dict(schema=2)), ("extra field", dict(extra=1))):
            put(**change)
            status = self.status()
            self.assertEqual((status["system"], status["complete"]), ("mismatch", False), label)
        self.receipt.write_text("not json")
        self.assertEqual(self.status()["system"], "mismatch")
        self.receipt.write_text(good)
        self.assertEqual(self.status()["system"], "done")
        os.chmod(self.receipt, 0o666)                                               # writable by others
        self.assertEqual(self.status()["system"], "mismatch")
        os.chmod(self.receipt, 0o644)
        os.chmod(self.root_config, 0o644)                                           # settings made readable by others
        self.assertEqual(self.status()["system"], "mismatch")
        os.chmod(self.root_config, 0o600)
        setup_wizard.ROOT_UID = os.geteuid() + 1                                    # not owned by root
        self.assertEqual(self.status()["system"], "mismatch")
        setup_wizard.ROOT_UID = os.geteuid()
        self.root_config.unlink()                                                   # receipt without settings
        self.assertEqual(self.status()["system"], "mismatch")
        self.receipt.unlink()
        self.assertEqual((self.status()["system"], self.status()["complete"]), ("pending", False))

    def test_a_receipt_for_different_settings_does_not_count_after_the_owner_settings_change(self):
        self.resume()
        self.install_root_config()
        data = json.loads(self.paths["proposed"].read_text())
        os.chmod(self.paths["proposed"], 0o600)
        self.paths["proposed"].write_text(json.dumps(dict(data, device="dtdev_other")))
        os.chmod(self.paths["config"], 0o600)
        cfg = json.loads(self.paths["config"].read_text())
        self.paths["config"].write_text(json.dumps(dict(cfg, device="dtdev_other")))
        self.assertEqual(self.status()["system"], "mismatch")                       # hash of the old settings != the new ones

    def test_an_unrelated_settings_file_without_a_receipt_is_never_adopted_and_never_replaced(self):
        self.resume()
        self.root_config.write_text("{}")                                           # someone else's / unrelated file
        os.chmod(self.root_config, 0o600)
        status = self.status()
        self.assertEqual((status["system"], status["complete"]), ("pending", False))   # not done
        with self.assertRaises(ConfigError) as refused:
            self.install_root_config()
        self.assertIn("different_system_settings_file", str(refused.exception))
        self.assertEqual(self.root_config.read_text(), "{}")                         # untouched
        self.assertFalse(self.receipt.exists())

    def test_an_interrupted_root_step_is_finished_only_for_identical_settings(self):
        self.resume()
        self.install_root_config()
        self.receipt.unlink()                                                       # died between the two writes
        self.assertEqual(self.status()["system"], "pending")
        self.install_root_config()                                                  # finishes; settings are identical
        self.assertEqual(self.status()["system"], "done")
        with self.assertRaises(FileExistsError):                                    # a finished setup is never redone
            self.install_root_config()

    def test_real_root_writes_and_a_different_unprivileged_user_verifies(self):
        """The actual Linux situation: root-owned 0600 settings, a normal account checking completion."""
        if os.geteuid() != 0 or shutil.which("setpriv") is None:
            self.skipTest("needs root (run as root in the disposable sandbox / the acceptance script)")
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        os.chmod(base, 0o755)
        nobody = 65534
        home = base / "home"
        home.mkdir()
        os.chown(home, nobody, nobody)
        os.chmod(home, 0o700)
        make_pairing_db(base / "pair", [(ts.DEVICE, ts.OWNER, time.time() + 3600, None, ["workspace.propose"])])
        pairing = next((base / "pair").iterdir())
        for path in ((base / "pair"), pairing):
            os.chown(path, nobody, nobody)
        os.chmod(base / "pair", 0o700)
        os.chmod(pairing, 0o600)
        form = dict(self.form, pairing_db=str(pairing))
        config = base / "etc" / "installer.json"
        code = (
            "import sys, json\nsys.path[:0] = [%r, %r]\nfrom pathlib import Path\nfrom stynpilot import setup_wizard\n"
            "home = Path(%r); form = json.loads(%r)\n"
            "step = sys.argv[1]\n"
            "if step == 'prepare': setup_wizard.resume_setup(form, home, %d, Path(%r))\n"
            "else:\n s = setup_wizard.setup_status(home, %d, Path(%r)); print(s['system'], s['complete'])\n"
        ) % (str(ROOT / "src"), str(ROOT / "tests"), str(home), json.dumps(form), nobody, str(config), nobody, str(config))

        def as_nobody(step):
            return subprocess.run(["setpriv", "--reuid=%d" % nobody, "--regid=65534", "--clear-groups", "env",
                                   "HOME=%s" % home, "python3", "-I", "-c", code, step],
                                  capture_output=True, text=True, cwd="/")
        prepared = as_nobody("prepare")
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        proposed = home / ".config/stynpilot/installer.proposed.json"
        self.assertEqual(as_nobody("check").stdout.split(), ["pending", "False"])
        setup_wizard.root_setup(proposed, dest=config, geteuid=os.geteuid, invoking_uid=nobody)   # root writes
        info = config.stat()
        self.assertEqual((info.st_uid, info.st_mode & 0o777), (0, 0o600))
        unreadable = subprocess.run(["setpriv", "--reuid=%d" % nobody, "--regid=65534", "--clear-groups", "cat", str(config)],
                                    capture_output=True)
        self.assertNotEqual(unreadable.returncode, 0)                                # the user really can't read it
        self.assertEqual(as_nobody("check").stdout.split(), ["done", "True"])
        record = json.loads(config.with_name(setup_wizard.RECEIPT_NAME).read_text())
        record["config_sha256"] = "1" * 64                                           # root-side tamper
        config.with_name(setup_wizard.RECEIPT_NAME).write_text(json.dumps(record))
        self.assertEqual(as_nobody("check").stdout.split(), ["mismatch", "False"])
        os.chmod(config, 0o644)
        os.unlink(config.with_name(setup_wizard.RECEIPT_NAME))
        self.assertEqual(as_nobody("check").stdout.split(), ["pending", "False"])

    def test_the_page_for_a_refused_system_step_shows_why_and_offers_another_try(self):
        self.resume()
        self.root_config.write_text("{}")
        os.chmod(self.root_config, 0o600)
        refusal = SimpleNamespace(returncode=1, stderr="stynpilot-root-helper: ConfigError: a_different_system_settings_file_is_already_there")
        c = self.client(lambda src: refusal)
        c.get("/setup/tok123", headers=self.H)
        page = c.post("/setup/system", data={"go": "1"}, headers=self.HP)
        self.assertIn("did not finish", page.text)
        self.assertIn("a_different_system_settings_file", page.text)
        self.assertNotIn("Setup is finished", page.text)

    def test_the_password_prompt_texts_name_exactly_what_is_being_approved(self):
        import xml.dom.minidom as minidom
        doc = minidom.parse(str(ROOT / "packaging/org.stynpilot.policy"))
        actions = {a.getAttribute("id"): a for a in doc.getElementsByTagName("action")}
        self.assertEqual(set(actions), {"org.stynpilot.root-setup", "org.stynpilot.root-backup", "org.stynpilot.root-restore"})
        for job, words in (("root-setup", ("/etc/stynpilot/installer.json", "installs nothing")),
                           ("root-backup", ("READ", "Nothing is changed")),
                           ("root-restore", ("WRITE", "never overwrites"))):
            action = actions["org.stynpilot." + job]
            message = action.getElementsByTagName("message")[0].firstChild.data
            annotations = {n.getAttribute("key"): n.firstChild.data for n in action.getElementsByTagName("annotate")}
            self.assertEqual(annotations["org.freedesktop.policykit.exec.argv1"], job)          # one action per job
            self.assertEqual(annotations["org.freedesktop.policykit.exec.path"], "/usr/libexec/stynpilot/root-helper")
            for w in words:
                self.assertIn(w, message)
        self.resume()
        c = self.client(lambda s: None)
        c.get("/setup/tok123", headers=self.H)
        text = c.get("/setup", headers=self.H).text
        self.assertIn("approves ONE thing", text)
        self.assertIn("/etc/stynpilot/installer.json", text)

    def test_bad_form_or_no_pairing_writes_nothing(self):
        for bad in (dict(self.form, issuer=""), dict(self.form, approval_public_host="10.0.0.1:8444"),
                    dict(self.form, pairing_db=str(self.home / "missing.db"))):
            with self.assertRaises(Exception):
                self.resume(bad)
        self.assertFalse(self.paths["config"].exists())
        with self.assertRaises(ConfigError):
            self.resume(None)                                                       # nothing to resume

    def write_proposal(self, uid=None):
        self.uid = uid if uid is not None else os.geteuid()
        self.resume()
        return self.paths["proposed"]

    def root(self, source, **kw):
        return setup_wizard.root_setup(source, dest=self.home / "etc/installer.json", geteuid=lambda: 0,
                                       invoking_uid=kw.pop("uid", os.geteuid()), **kw)

    def test_root_step_installs_the_config_for_exactly_the_caller_and_never_replaces_one(self):
        source = self.write_proposal()
        if os.geteuid() < 1000:
            with self.assertRaises(ConfigError):
                self.root(source)
            return
        self.root(source)
        self.assertEqual((self.home / "etc/installer.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.root(source)

    def test_root_step_refuses_wrong_caller_loose_files_and_non_root(self):
        source = self.write_proposal()
        with self.assertRaises(ConfigError):
            setup_wizard.root_setup(source, dest=self.home / "e.json", geteuid=lambda: 1000, invoking_uid=1000)
        with self.assertRaises(ConfigError):
            self.root(source, uid=os.geteuid() + 1)
        os.chmod(source, 0o644)
        with self.assertRaises(ConfigError):
            self.root(source)
        link = self.home / "link.json"
        link.symlink_to(source)
        with self.assertRaises(OSError):
            self.root(link)
        with self.assertRaises(ConfigError):
            setup_wizard.root_setup(source, dest=self.home / "e.json", geteuid=lambda: 0, environ={})

    def test_root_step_pins_the_packaged_paths_and_fields(self):
        source = self.write_proposal()
        data = json.loads(source.read_text())
        for field, value in (("state_dir", "/etc"), ("socket_path", "/tmp/x.sock")):
            os.chmod(source, 0o600)
            source.write_text(json.dumps(dict(data, **{field: value})))
            with self.assertRaises(ConfigError):
                self.root(source)
        source.write_text(json.dumps(dict(data, extra=1)))
        with self.assertRaises(ConfigError):
            self.root(source)

    # --- the browser page: one-time link, resume after cancel/close ------------------------------------
    def client(self, runner):
        from starlette.testclient import TestClient
        app = setup_wizard.build_app(home=self.home, uid=self.uid, token="tok123", port=5555, root_runner=runner,
                                     root_config=self.root_config)
        return TestClient(app, base_url="http://127.0.0.1:5555", follow_redirects=False)

    H = {"host": "127.0.0.1:5555"}
    HP = {"host": "127.0.0.1:5555", "origin": "http://127.0.0.1:5555"}

    def test_the_setup_link_works_once_then_a_session_cookie_is_required(self):
        c = self.client(lambda src: SimpleNamespace(returncode=0))
        self.assertEqual(c.get("/setup/wrong", headers=self.H).status_code, 404)
        self.assertEqual(c.get("/setup/tok123", headers={"host": "evil.example"}).status_code, 404)
        self.assertEqual(c.get("/setup", headers=self.H).status_code, 404)             # no session yet
        first = c.get("/setup/tok123", headers=self.H)
        self.assertEqual((first.status_code, first.headers["location"]), (303, "/setup"))
        self.assertIn("httponly", first.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", first.headers["set-cookie"].lower())
        self.assertEqual(c.get("/setup/tok123", headers=self.H).status_code, 404)      # the link is spent
        from starlette.testclient import TestClient
        stranger = TestClient(c.app, base_url="http://127.0.0.1:5555")
        self.assertEqual(stranger.get("/setup", headers=self.H).status_code, 404)      # no cookie, no page
        page = c.get("/setup", headers=self.H)
        self.assertEqual(page.status_code, 200)
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertIn(str(self.pairing), page.text)                                    # prefilled from discovery
        self.assertEqual(c.post("/setup/save", data=self.form, headers=self.H).status_code, 404)   # post needs Origin

    def test_cancelled_password_prompt_then_browser_restart_shows_resume_and_finishes(self):
        calls = []
        outcome = {"ok": False}

        def runner(src):
            calls.append(src)
            if outcome["ok"]:
                self.install_root_config()
            return SimpleNamespace(returncode=0 if outcome["ok"] else 126)
        c = self.client(runner)
        c.get("/setup/tok123", headers=self.H)
        saved = c.post("/setup/save", data=self.form, headers=self.HP)
        self.assertEqual(saved.status_code, 200)
        self.assertIn("One step left", saved.text)
        self.assertEqual(calls, [])                                                    # nothing privileged yet
        cancelled = c.post("/setup/system", data={"go": "1"}, headers=self.HP)
        self.assertIn("did not finish", cancelled.text)
        self.assertIn("Allow system part", cancelled.text)                             # offered again
        self.assertFalse(self.paths["done"].exists())
        # browser closed; the owner starts Setup again from the menu: a NEW wizard, same files on disk
        again = self.client(runner)
        again.get("/setup/tok123", headers=self.H)
        reopened = again.get("/setup", headers=self.H)
        self.assertIn("One step left", reopened.text)                                  # resumes, no blank form
        self.assertNotIn("<form method=post action=/setup/save>", reopened.text)
        outcome["ok"] = True
        done = again.post("/setup/system", data={"go": "1"}, headers=self.HP)
        self.assertIn("Setup is finished", done.text)
        self.assertTrue(self.paths["done"].exists())
        self.assertEqual(len(calls), 2)

    def test_resume_button_after_an_interrupted_save_and_a_refused_resume_changes_nothing(self):
        c = self.client(lambda src: SimpleNamespace(returncode=0))
        self.resume()
        (self.paths["state"] / "provisioned.json").unlink()                            # interrupted provisioning
        c.get("/setup/tok123", headers=self.H)
        page = c.get("/setup", headers=self.H)
        self.assertIn("Continue where I left off", page.text)
        ok = c.post("/setup/resume", data={}, headers=self.HP)
        self.assertIn("One step left", ok.text)
        os.chmod(self.paths["config"], 0o644)                                          # tampered: must stop
        bad = c.post("/setup/resume", data={}, headers=self.HP)
        self.assertEqual(bad.status_code, 400)
        self.assertIn("nothing was changed", bad.text.lower())

    def test_system_step_is_refused_until_the_earlier_stages_are_done(self):
        calls = []
        c = self.client(lambda src: calls.append(src) or SimpleNamespace(returncode=0))
        c.get("/setup/tok123", headers=self.H)
        self.assertEqual(c.post("/setup/system", data={}, headers=self.HP).status_code, 400)
        self.assertEqual(calls, [])


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class ScriptAndPolicyTests(unittest.TestCase):
    """The acceptance script must be able to fail, and polkit must authorise only the fixed helper."""

    def test_acceptance_script_has_no_silent_failure_patterns(self):
        text = (ROOT / "tools/isolated_install_check.sh").read_text()
        self.assertIn("set -eu", text)
        for bad in ("|| true", "&& echo", "|| echo", "tail -1 ||"):
            self.assertNotIn(bad, text, bad)
        self.assertIn("RESULT: PASS", text)
        for name in ("enable_unit", "etc_created", "allow_overwrite", "keep_state", "remove_config", "no_lock", "receipt_private"):
            self.assertIn("inject %s" % name, text)                                   # each invariant has a self-test hook
        r = subprocess.run(["sh", "-n", str(ROOT / "tools/isolated_install_check.sh")], capture_output=True)
        self.assertEqual(r.returncode, 0)

    def test_polkit_runs_only_the_fixed_root_helper(self):
        policy = (ROOT / "packaging/org.stynpilot.policy").read_text()
        self.assertIn("/usr/libexec/stynpilot/root-helper", policy)
        self.assertNotIn(">/usr/bin/stynpilot<", policy)
        from stynpilot import root_helper
        with self.assertRaises(SystemExit):
            root_helper.main(["run-anything", "--cmd", "id"])


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cache = ROOT / ".build-cache"
        if not shutil.which("dpkg-deb") or not list(cache.glob("mcp-*.whl")):
            raise unittest.SkipTest("dpkg-deb or the pinned wheel cache is missing (build once with network)")
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_deb", ROOT / "tools/build_deb.py")
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)
        cls.deb = cls.mod.build(Path(cls.tmp.name) / "out", cache)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def listing(self):
        out = subprocess.run(["dpkg-deb", "-c", str(self.deb)], capture_output=True, text=True, check=True).stdout
        return [line.split()[-1] for line in out.splitlines()]

    def test_every_module_is_in_the_package(self):
        packaged = {n for n in self.listing() if n.endswith(".py") and "/lib/stynpilot/stynpilot/" in n.replace("./usr", "/usr") + "/"
                    or n.startswith("./usr/lib/stynpilot/lib/stynpilot/") and n.endswith(".py")}
        want = {"./usr/lib/stynpilot/lib/stynpilot/" + str(p.relative_to(ROOT / "src/stynpilot"))
                for p in (ROOT / "src/stynpilot").rglob("*.py")}
        self.assertEqual(want - set(packaged), set())

    def test_package_changes_nothing_when_installed_and_has_no_secrets(self):
        names = self.listing()
        self.assertFalse([n for n in names if "DEBIAN" in n or n.endswith(("postinst", "preinst", "prerm", "postrm"))])
        info = subprocess.run(["dpkg-deb", "-I", str(self.deb)], capture_output=True, text=True, check=True).stdout
        self.assertNotIn("postinst", info)
        self.assertIn("polkitd", info)
        self.assertIn("./usr/libexec/stynpilot/root-helper", names)
        self.assertIn("./usr/lib/systemd/system/stynpilot-installer.service", names)
        self.assertIn("./usr/lib/systemd/user/stynpilot-owner.service", names)
        self.assertFalse([n for n in names if "/etc/" in n and "systemd" not in n])   # no /etc files, nothing enabled
        self.assertFalse([n for n in names if "wants" in n])
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["dpkg-deb", "-x", str(self.deb), d], check=True)
            text = (Path(d) / "usr/lib/stynpilot/lib/stynpilot/service.py").read_text()
            for bad in ("dtdev_", "auth0|", "BEGIN PRIVATE"):
                self.assertNotIn(bad, text)
            launcher = (Path(d) / "usr/bin/stynpilot").read_text()
            self.assertTrue(launcher.startswith("#!/usr/bin/python3 -I"))
            for unit in ("usr/lib/systemd/system/stynpilot-installer.service", "usr/lib/systemd/user/stynpilot-owner.service"):
                self.assertTrue((Path(d) / unit).read_bytes() == (ROOT / "deploy/systemd" / Path(unit).name).read_bytes())

    def test_build_is_reproducible_and_the_vendored_wheel_is_hash_pinned(self):
        again = self.mod.build(Path(self.tmp.name) / "out2", ROOT / ".build-cache")
        self.assertEqual(hashlib.sha256(self.deb.read_bytes()).hexdigest(), hashlib.sha256(again.read_bytes()).hexdigest())
        name, version, digest = next(self.mod.read_lock())
        wheel = next((ROOT / ".build-cache").glob("%s-%s-*.whl" % (name, version)))
        self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
