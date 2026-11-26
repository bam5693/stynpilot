"""Offline Stage 3 recovery with real encrypted archives, SQLite and file locks in temporary directories."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stynpilot import root_restore as rr
from stynpilot import statelock, vault
from stynpilot.broker.executor import Runs
from stynpilot.broker.passkeys import PasskeyStore
from stynpilot.ledger import InstallLedger
from stynpilot.requests import request_id
from stynpilot.restore_service import complete_checks
from stynpilot.broker import selftest


class PowerLoss(BaseException):
    pass


class Services:
    def __init__(self, state, health):
        self.state, self.health = state, iter(health)

    def stop(self):
        assert rr.held(self.state)

    def start(self):
        assert rr.start_allowed(self.state)

    def start_safe(self):
        assert rr.held(self.state)

    def healthy(self, probe):
        assert rr.probe_allowed(self.state, probe)
        return next(self.health)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        self.runs = Runs(self.state / "runs.sqlite3")
        self.keys = PasskeyStore(self.state / "passkeys.sqlite3", rp_id="example.test", origin="https://example.test")
        self.ledger = InstallLedger(self.state / "installs.sqlite3")
        for name in rr.MEMBERS[1:]:
            (self.state / name).mkdir(mode=0o700)
        self.record = self.state / "attention" / "old.json"
        self.record.write_text('{"example":true}')
        self.config = self.state / "installer.json"
        self.config.write_text('{"setting":"old"}')
        self.v = vault.Vault(side="root", state_dir=self.state, folder=self.state / "vault",
                             extras=[("installer.json", self.config, "json", True, {"setting"})], version="test")
        old = self.v.backup_now()
        self.assertTrue(old["ok"], old)
        self.archive = old["backup"]
        self.record.unlink()
        self.config.write_text('{"setting":"current"}')

    def approve(self):
        details = self.v._run("restore_preview", args={"archive": self.archive})
        self.assertIn("settings_differences", details)
        payload = dict(details, kind="backup", side="root", action="restore_root", owner="owner", device="test",
                       expires_at="2099-01-01T00:00:00Z")
        self.rid = request_id(payload)[0]
        challenge = self.runs.issue(self.rid, "approve")
        self.runs.consume(challenge=challenge, request_id=self.rid, decision="approve", proof="synthetic-" + self.rid,
                          kind=rr.KIND, restore_payload=payload)
        rr.wake(self.state, self.rid, payload)
        self.tx = rr.control(self.state) / self.rid
        return payload

    def work(self, health=(True,), checkpoint=lambda step: None):
        rr.worker(self.v, Services(self.state, health), checkpoint)

    def test_archive_restored_safety_retained_settings_unchanged(self):
        self.assertEqual(self.approve()["settings_differences"], ["installer.json"])
        self.work()
        self.assertEqual(self.record.read_text(), '{"example":true}')
        self.assertEqual(self.config.read_text(), '{"setting":"current"}')
        safety = rr._read(self.tx / "safety.json")
        self.assertEqual(vault._file_sha(self.tx / safety["archive"]), safety["sha256"])
        self.assertTrue((self.tx / "original" / "installs.sqlite3").exists())
        self.assertFalse(rr.held(self.state))
        self.assertEqual(self.runs.status(self.rid)["state"], "done")
        self.assertEqual(rr._generation(self.state), 1)

    def test_failed_health_rolls_back_before_gate_opens(self):
        self.approve()
        self.work((False, True))
        self.assertFalse(self.record.exists())
        self.assertTrue((self.tx / "failed" / "attention" / "old.json").exists())
        self.assertFalse(rr.held(self.state))
        self.assertEqual(self.runs.status(self.rid)["result"]["restore"], "rolled_back")

    def test_failed_rollback_health_holds_gate(self):
        self.approve()
        with self.assertRaises(rr.ERROR):
            self.work((False, False))
        self.assertTrue(rr.held(self.state))
        reply = rr.safe_reply(self.state, {"op": "status", "request_id": self.rid})
        self.assertEqual(reply["status"]["state"], "needs_owner_intervention")

    def test_safe_socket_start_failure_keeps_durable_trigger(self):
        self.approve()
        services = Services(self.state, (False, False))
        with mock.patch.object(services, "start_safe", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                rr.worker(self.v, services)
        control = rr.control(self.state)
        self.assertTrue((control / "pending.json").exists())
        self.assertTrue((control / "safe.json").exists())
        self.work()
        self.assertTrue((control / "stalled.json").exists())
        self.assertFalse((control / "pending.json").exists())
        self.assertTrue(rr.held(self.state))

    def test_tampered_archive_refused_before_switch(self):
        self.approve()
        with (self.v.folder / self.archive).open("ab") as out:
            out.write(b"changed")
        self.work()
        self.assertFalse(self.record.exists())
        self.assertFalse((self.tx / "original").exists())
        self.assertEqual(self.runs.status(self.rid)["state"], "failed")

    def test_incomplete_safety_never_switches(self):
        self.approve()
        self.config.unlink()
        self.work()
        self.assertFalse(self.record.exists())
        self.assertFalse((self.tx / "original").exists())

    def test_authority_and_settings_change_after_approval_refused(self):
        self.approve()
        with self.runs._tx() as db:
            db.execute("INSERT INTO runs VALUES ('other','proof','install','done',NULL,1,2)")
        self.work()
        self.assertEqual(self.runs.status(self.rid)["result"]["stopped"], "approved_restore_changed")
        self.assertFalse(self.record.exists())

    def test_power_loss_at_each_forward_phase(self):
        self.approve()
        reached = []
        for expected in ("prepare", "secure", "switch", "verify", "done"):
            def crash(step):
                reached.append(step)
                self.assertEqual(expected, step)
                raise PowerLoss()
            with self.assertRaises(PowerLoss):
                self.work(checkpoint=crash)
            self.assertTrue(rr.held(self.state))
        self.work()
        self.assertTrue(self.record.exists())
        self.assertEqual(self.runs.status(self.rid)["state"], "done")
        self.assertEqual(len(reached), 5)

    def test_interruption_between_every_rename_and_rollback_phase(self):
        self.approve()
        real_move = rr._rename
        for step in ("switch", "rollback"):
            def halt(s):
                if s == step:
                    raise PowerLoss()
            with self.assertRaises(PowerLoss):
                self.work((False,), halt)
            for _ in range(6):
                def move_then_crash(source, dest):
                    real_move(source, dest)
                    raise PowerLoss()
                with mock.patch.object(rr, "_rename", move_then_crash), self.assertRaises(PowerLoss):
                    self.work()
        with self.assertRaises(PowerLoss):
            self.work(checkpoint=lambda s: (_ for _ in ()).throw(PowerLoss()))
        self.work()
        self.assertFalse(self.record.exists())
        self.assertFalse(rr.held(self.state))

    def test_replay_security_tables_are_monotonic(self):
        with self.runs._tx() as db:
            db.execute("INSERT INTO runs VALUES ('spent','old-proof','install','done',NULL,1,2)")
        with rr._db(self.state / "passkeys.sqlite3", True) as db:
            for cid in ("a", "b", "c"):
                db.execute("INSERT INTO passkeys VALUES (?,?,?,'phone',0,0,'',7,1,1,?,'owner','hash',1,0)",
                           (cid, cid, "public", 2 if cid == "a" else None))
        self.archive = self.v.backup_now()["backup"]
        with self.runs._tx() as db:
            db.execute("DELETE FROM runs WHERE request_id='spent'")
        with rr._db(self.state / "passkeys.sqlite3", True) as db:
            db.execute("UPDATE passkeys SET revoked=NULL,sign_count=4 WHERE credential_id='a'")
            db.execute("UPDATE passkeys SET revoked=9,sign_count=8 WHERE credential_id='b'")
            db.execute("DELETE FROM passkeys WHERE credential_id='c'")
        self.keys.open_window("ab"*32, "pending", "owner")
        self.runs.issue("cd"*32, "approve")
        self.approve()
        self.work((False, True))
        self.assertEqual(self.runs.status("spent")["result"]["stopped"], "historical_approval_spent")
        with rr._db(self.state / "passkeys.sqlite3") as db:
            self.assertEqual(db.execute("SELECT revoked,sign_count,quarantined FROM passkeys ORDER BY credential_id").fetchall(),
                             [(2, 7, 0), (9, 8, 0), (None, 7, 1)])
            self.assertFalse(db.execute("SELECT 1 FROM windows WHERE closed IS NULL").fetchone())
        self.assertTrue(self.keys.audit_ok())
        with self.runs._tx() as db:
            self.assertFalse(db.execute("SELECT 1 FROM challenges WHERE used IS NULL").fetchone())

    def test_backup_and_restore_admission_conflict(self):
        with rr.admission(self.state):
            with self.assertRaises(statelock.Busy):
                with rr.admission(self.state, exclusive=True):
                    self.fail()
        self.approve()
        self.assertEqual(self.v.backup_now()["error"], "root_restore_in_progress")
        self.assertEqual(self.v.recheck()["error"], "root_restore_in_progress")

    def test_rollback_after_safety_creation_fails(self):
        self.approve()
        with mock.patch.object(self.v, "_create", side_effect=OSError("full")):
            self.work()
        self.assertFalse(self.record.exists())
        self.assertFalse((self.tx / "original").exists())

    def test_confinement_requires_full_current_results(self):
        from stynpilot import __version__
        result = dict(ok=True, ran=True, version=__version__, passed=list(selftest.REQUIRED + selftest.OPTIONAL + selftest.STRICT_REQUIRED),
                      failed=[], unverified=[])
        self.assertTrue(complete_checks(result, __version__.replace(".dev", "~dev")))
        self.assertFalse(complete_checks(result, "0.1.0~dev22"))
        self.assertFalse(complete_checks(result, None))
        for changes in ({"version": "old"}, {"passed": result["passed"][:-1]}, {"unverified": ["limit_io"]}, {"failed": ["identity"]}):
            self.assertFalse(complete_checks(dict(result, **changes), __version__.replace(".dev", "~dev")))


class ApprovalBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_broker
        if test_broker.jwt is None:
            raise unittest.SkipTest("needs PyJWT and cryptography")
        test_broker.BrokerTests.setUpClass()

    def setUp(self):
        import test_broker
        from types import SimpleNamespace
        from test_passkey_integration import Enrolling
        from stynpilot.broker.service import BrokerService
        fixture = test_broker.BrokerTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.ex = fixture.executor
        self.addCleanup(self.close_executor)
        keys = Enrolling()
        self.ex.passkeys = keys.new_store(self.ex.dir)
        self.phone = keys.enroll(self.ex.passkeys)
        self.ex.jobs = SimpleNamespace(enabled=lambda: True, _live={})
        self.ex.restore_available = lambda: True
        self.v = self.ex.vault = vault.Vault(side="root", state_dir=self.ex.dir, folder=self.ex.dir / "vault", isolate=True)
        self.door = BrokerService(socket_path=fixture.tmp / "sock", executor=self.ex, allowed_uid=os.getuid())
        archive = self.v.backup_now()["backup"]
        self.payload = dict(self.door.handle({"op": "restore_preview", "archive": archive})["result"],
                            kind="backup", action="restore_root", side="root", owner=self.ex.owner,
                            device=self.ex.device, expires_at="2099-01-01T00:00:00Z")
        self.rid = request_id(self.payload)[0]
        self.challenge = self.door.handle({"op": "challenge", "payload": self.payload, "decision": "approve"})["challenge"]["challenge"]
        self.oidc = fixture.proof(self.payload, self.challenge)

    def close_executor(self):
        if self.ex._alive is not None:
            os.close(self.ex._alive)
            self.ex._alive = None

    def decide(self, payload=None, proof=None):
        from test_passkey_integration import proof_for
        return self.door.handle({"op": "backup_admin", "payload": self.payload if payload is None else payload,
                                 "proof": proof or proof_for(self.phone, self.payload, self.challenge), "challenge": self.challenge})

    def test_exact_passkey_then_restart_settles_real_request(self):
        self.assertFalse(self.decide(proof=self.oidc)["ok"])
        for edits in ({"sha256": "0"*64}, {"scope": "settings"}, {"generation": 20}, {"side": "owner"}):
            self.assertFalse(self.decide(dict(self.payload, **edits))["ok"])
        self.assertTrue(self.decide()["result"]["pending"])
        self.assertFalse(self.decide()["ok"])
        self.assertEqual(self.ex.status(self.rid)["state"], "running")
        for op in ("release_resume", "passkey_complete", "release_prepare", "vault_backup", "install"):
            self.assertEqual(self.door.handle({"op": op})["error"], "root_restore_in_progress")
        self.assertFalse(self.door.handle({"op": "runner", "call": "selftest"})["ok"])

        class Restart(Services):
            def stop(inner):
                super().stop()
                if self.ex._alive is not None:
                    os.close(self.ex._alive)
                    self.ex._alive = None

            def start(inner):
                from stynpilot.broker.executor import Executor
                super().start()
                self.ex = Executor(state_dir=self.v.state_dir, owner=self.ex.owner, device=self.ex.device,
                                   verifier=self.ex.verifier, require_root=False, root_vault=self.v)

        rr.worker(self.v, Restart(self.ex.dir, [True]))
        self.assertEqual(self.ex.status(self.rid)["state"], "done")
        self.assertFalse(rr.held(self.ex.dir))

    def test_owner_decision_refused_if_watcher_or_idle_runner_unavailable(self):
        self.ex.restore_available = lambda: False
        self.assertEqual(self.decide()["error"], "independent_restore_worker_unavailable")
        self.ex.restore_available = lambda: True
        self.ex.jobs._live["test"] = True
        self.assertEqual(self.decide()["error"], "restore_requires_idle_installer_and_runner")
        self.assertFalse(rr.held(self.ex.dir))

    def enable_inference_fixture(self):
        self.ex.jobs.projects_dir = str(self.ex.dir / "projects")
        self.ex.jobs.version = "test"
        self.ex.jobs.selftest_state = lambda: {"ran": True, "ok": True, "version": "test"}
        self.ex.jobs.workspaces = lambda: [{"path": self.ex.jobs.projects_dir + "/local-ai-pilot"}]

    def inference_call(self, name, job="a"*32):
        return self.door.handle({"op": "runner", "call": name, "args": {"job_id": job}})

    def test_managed_inference_claim_blocks_restore_before_proof_is_spent(self):
        from stynpilot.broker.service import BrokerService
        self.enable_inference_fixture()
        self.assertTrue(self.inference_call("inference_claim")["ok"])
        self.assertFalse(self.inference_call("inference_claim", "b"*32)["ok"])
        self.assertFalse(self.inference_call("inference_finish", "b"*32)["ok"])
        self.assertEqual(self.decide()["error"], "restore_requires_idle_managed_activity")
        self.assertEqual(self.ex.status(self.rid)["state"], "not_started")
        self.assertFalse(rr.held(self.ex.dir))
        self.door = BrokerService(socket_path=self.door.path, executor=self.ex, allowed_uid=os.getuid())
        self.assertEqual(self.decide()["error"], "restore_requires_idle_managed_activity")
        self.assertTrue(self.inference_call("inference_finish")["ok"])
        self.assertTrue(self.decide()["result"]["pending"])
        self.assertFalse(self.inference_call("inference_claim")["ok"])

    def test_inference_and_recovery_admission_race(self):
        import threading
        from test_passkey_integration import proof_for
        self.enable_inference_fixture()
        proof = proof_for(self.phone, self.payload, self.challenge)
        barrier = threading.Barrier(3)
        replies = {}
        def inference():
            barrier.wait()
            replies["inference"] = self.inference_call("inference_claim")
        def restore():
            barrier.wait()
            replies["restore"] = self.decide(proof=proof)
        threads = [threading.Thread(target=fn) for fn in (inference, restore)]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join(10)
        self.assertEqual(set(replies), {"inference", "restore"})
        self.assertEqual(sum(x["ok"] for x in replies.values()), 1, replies)
        from stynpilot import managed_activity
        self.assertNotEqual(managed_activity.held(self.ex.dir), rr.held(self.ex.dir))

    def test_unspent_intent_recovers_without_stopping_installer(self):
        with mock.patch.object(self.ex.runs, "consume", side_effect=PowerLoss()), self.assertRaises(PowerLoss):
            self.decide()
        self.assertTrue(rr.held(self.ex.dir))
        services = mock.Mock()
        rr.worker(self.v, services)
        services.stop.assert_not_called()
        self.assertFalse(rr.held(self.ex.dir))
        self.assertEqual(self.ex.status(self.rid)["state"], "not_started")


class ProcessRecoveryTests(unittest.TestCase):
    def test_worker_killed_after_first_rename_resumes_from_disk(self):
        import multiprocessing
        fixture = RestoreTests("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.approve()

        def kill_worker():
            original = rr._rename
            def interrupted(source, dest):
                original(source, dest)
                if dest.parent.name == "original":
                    os._exit(73)
            with mock.patch.object(rr, "_rename", interrupted):
                fixture.work()

        proc = multiprocessing.get_context("fork").Process(target=kill_worker)
        proc.start()
        proc.join(15)
        self.assertEqual(proc.exitcode, 73)
        self.assertFalse((fixture.state / rr.MEMBERS[0]).exists())
        self.assertFalse(rr.start_allowed(fixture.state))
        fixture.work()
        self.assertEqual(fixture.runs.status(fixture.rid)["state"], "done")
        self.assertTrue(fixture.record.exists())

    def test_power_loss_before_proof_spend_allows_original_service_to_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            root = rr._folder(rr.control(state))
            rr._write(root / "pending.json", {"phase": "approved", "rid": "a"*64})
            self.assertTrue(rr.start_allowed(state))
            Runs(state / "runs.sqlite3")
            rr.worker(vault.Vault(side="root", state_dir=state, folder=state / "vault"), mock.Mock())
            self.assertFalse(rr.held(state))


class RecoveryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = RestoreTests("runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_incomplete_missing_key_and_wrong_side_refused(self):
        v = self.f.v
        for name in ("../" + self.f.archive, self.f.archive.replace("root-", "owner-")):
            self.assertEqual(v._run("restore_preview", args={"archive": name})["error"], "invalid_root_archive")
        self.f.config.unlink()
        new = v.backup_now()
        self.assertFalse(new["complete"])
        self.assertEqual(v._run("restore_preview", args={"archive": new["backup"]})["error"], "complete_verified_archive_required")
        v.key_file.rename(v.folder / "unavailable-test-key")
        self.assertIn("error", v._run("restore_preview", args={"archive": self.f.archive}))
        self.assertFalse(rr.held(self.f.state))

    def test_pinned_safety_corruption_detected_on_worker_resume(self):
        f = self.f
        f.approve()
        def halt(phase):
            if phase == "secure":
                raise PowerLoss()
        with self.assertRaises(PowerLoss):
            f.work(checkpoint=halt)
        safety = rr._read(f.tx / "safety.json")
        (f.tx / safety["archive"]).write_bytes(b"damaged synthetic backup")
        f.work()
        self.assertFalse(f.record.exists())
        self.assertEqual(f.runs.status(f.rid)["result"]["stopped"], "verified_safety_backup_changed")

    def test_missing_generation_history_cannot_reuse_first_generation(self):
        self.f.approve()
        self.f.work()
        (rr.control(self.f.state) / "generation.json").unlink()
        result = self.f.v._run("restore_preview", args={"archive": self.f.archive})
        self.assertEqual(result["error"], "restore_generation_missing")

    def test_failed_rollback_reports_through_read_only_socket(self):
        f = self.f
        f.approve()
        with self.assertRaises(rr.ERROR):
            f.work((False, False))
        status = rr.safe_reply(f.state, {"op": "status", "request_id": f.rid})
        self.assertEqual(status["status"]["result"]["restore"], "safe_recovery")
        self.assertFalse(rr.safe_reply(f.state, {"op": "runner", "call": "status"})["result"]["gate_open"])
        self.assertFalse(rr.safe_reply(f.state, {"op": "backup_admin"})["ok"])
        self.assertFalse((rr.control(f.state) / "pending.json").exists())


class OwnerReceiptTests(unittest.TestCase):
    def test_exact_terminal_evidence_corrects_uncertain_restore_only(self):
        from types import SimpleNamespace
        from stynpilot.requests import RequestStore
        with tempfile.TemporaryDirectory() as tmp:
            store = RequestStore(Path(tmp) / "requests.sqlite3", clock=lambda: 1)
            payload = dict(kind="backup", action="restore_root", side="root", generation=3)
            row, _ = store.submit(kind="backup", software="restore", device="test", owner="owner",
                                  proposer=SimpleNamespace(client="client", name="client"), payload=payload, summary=[], expires=100)
            rid = row["request_id"]
            store.transition(rid, "pending", "approved")
            store.transition(rid, "approved", "needs_owner_intervention")
            result = dict(action="restore_root", side="root", ok=True, restore="done", generation=3)
            for changes in ({"generation": 4}, {"side": "owner"}, {"action": "rotate_key"}):
                self.assertFalse(store.settle_restore(rid, dict(state="done", result=dict(result, **changes))))
            self.assertTrue(store.settle_restore(rid, dict(state="done", result=result)))
            self.assertEqual(store.status(rid, owner="owner", device="test")["result"]["generation"], 3)


class OwnerExclusionTests(unittest.TestCase):
    def test_durable_root_handoff_excludes_owner_rotation_until_verified_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            def fresh():
                return vault.Vault(side="owner", state_dir=state, folder=state / "vault", clock=lambda: 100)
            rid, other = "a"*64, "b"*64
            fresh().reserve_root_restore(rid, 101)
            for record in ({"state": "not_started"}, {"state": "running"}, {"state": "done", "result": {"action": "rotate_key"}}):
                fresh().reconcile_restore_intent(lambda _: record)
                self.assertEqual(fresh().prepare_rotation("normal", other, 105)["error"], "root_restore_in_progress")
            fresh().reconcile_restore_intent(lambda _: {"state": "done", "result": {"action": "restore_root"}})
            self.assertTrue(fresh().prepare_rotation("normal", other, 105)["ok"])
            with self.assertRaisesRegex(vault.VaultError, "owner_key_rotation_in_progress"):
                fresh().reserve_root_restore(rid, 101)



class RestoreCapacityAndVersionTests(unittest.TestCase):
    def test_combined_capacity_checks_precede_archive_decode(self):
        fixture = RestoreTests("runTest")
        fixture.setUp()
        try:
            size = (fixture.v.folder / fixture.archive).stat().st_size
            live, _ = vault._state_sizes(fixture.state, "root")
            fixture.v.limits["gather"] = size + live - 1
            with mock.patch.object(fixture.v, "_verify") as decode:
                result = fixture.v._run("restore_preview", args={"archive": fixture.archive})
                assert result["error"] == "combined_restore_too_large"
                decode.assert_not_called()
            fixture.v.limits["gather"] = vault.MAX_GATHER
            with mock.patch.object(fixture.v, "space", return_value=type("Space", (), {"free": vault.SPACE_MARGIN})()):
                result = fixture.v._run("restore_preview", args={"archive": fixture.archive})
                assert result["error"] == "insufficient_combined_restore_storage"
        finally:
            fixture.doCleanups()


    def test_fresh_package_launcher_ignores_equal_size_equal_mtime_legacy_bytecode(self):
        import subprocess
        import sys
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tmp_path = Path(directory.name)
        package = tmp_path / "stynpilot"
        package.mkdir()
        version = package / "__init__.py"
        (package / "cli.py").write_text("def main():\n    from . import __version__\n    print(__version__)\n")
        version.write_text('__version__ = "0.1.0.dev22"\n')
        os.utime(version, (1763769600, 1763769600))
        subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import stynpilot",
                        str(tmp_path)], check=True)
        version.write_text(version.read_text().replace("dev22", "dev25"))
        os.utime(version, (1763769600, 1763769600))
        launcher = (Path(__file__).resolve().parents[1] / "packaging" / "stynpilot-launcher").read_text()
        launcher = launcher.replace("/usr/lib/stynpilot/lib", str(tmp_path))
        output = subprocess.check_output([sys.executable, "-IB", "-c", launcher], text=True)
        assert output.strip() == "0.1.0.dev25"
