"""Dev23 stage 2: owner-approved backup key rotation (vault.py), interrupted at every durable step."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

from stynpilot import vault  # noqa: E402
from stynpilot.vault import VaultError  # noqa: E402

try:
    import test_vault as tv
    import cryptography  # noqa: F401
except Exception:                                    # pragma: no cover
    tv = None

DAY = 86400
RID = "ab" * 32


class PowerLoss(BaseException):
    """Stands for the machine losing power: nothing after it runs, nothing catches it."""


@unittest.skipIf(tv is None, "needs cryptography")
class KeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.folder = self.o.tmp / "vault"
        self.vault = self.o.vault
        for _ in range(3):
            self.assertTrue(self.vault.backup_now()["ok"])
            self.o.clock.t += DAY

    # helpers ------------------------------------------------------------------------------------------------------------------
    def fresh(self):
        return self.o.make()

    def key_id(self):
        return (self.folder / "backup-key").read_bytes()[8:16].hex()

    def headers(self):
        out = {}
        for p in sorted(self.folder.glob("*.stynvault")):
            out[p.name] = self.vault._header_of(p.name)
        return out

    def contents(self, v=None):
        v = v or self.fresh()
        result = {}
        for name in self.headers():
            _, meta, blobs = v.open_backup(name)
            result[name] = sorted((k, len(b)) for k, b in blobs.items())
        return result

    def all_nonces(self):
        seen = []
        for path in [self.folder / "nonces.log"] + list((self.folder / "keys").glob("*.nonces")):
            if path.exists():
                seen += path.read_text().split()
        return seen

    # normal rotation -----------------------------------------------------------------------------------------------------------
    def test_a_rotation_reencrypts_every_backup_verifies_it_and_destroys_the_old_key(self):
        before, old = self.contents(), self.key_id()
        result = self.vault.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 3)
        self.assertTrue(result["old_key_destroyed"])
        self.assertNotEqual(self.key_id(), old)
        self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()})
        self.assertEqual(self.contents(), before)                           # same backups, same contents, new key
        self.assertFalse((self.folder / "keys" / (old + ".key")).exists())
        self.assertTrue((self.folder / "keys" / (old + ".nonces")).exists())   # the old generation's nonce log is kept
        self.assertFalse((self.folder / "rotation.json").exists())
        self.assertEqual(list(self.folder.glob(".rotate-*")), [])
        status = self.vault.status()
        self.assertNotIn("key_rotation_incomplete", status["problems"])
        self.assertEqual(status["keys"]["active"], self.key_id())
        self.assertNotIn("request_id", json.dumps(status["keys"]))
        # life goes on with the new key: backups, drills, rechecks
        self.assertTrue(self.vault.backup_now()["ok"])
        self.assertTrue(self.vault.drill()["ok"])
        self.assertTrue(self.vault.recheck_all()["ok"])
        nonces = self.all_nonces()
        self.assertEqual(len(nonces), len(set(nonces)))

    def test_each_key_generation_has_its_own_id_and_nonce_log_and_nonces_never_repeat(self):
        ids = {self.key_id()}
        for i in range(3):
            self.assertTrue(self.vault.rotate_key("normal", "%02x" % i * 32)["ok"])
            ids.add(self.key_id())
            self.assertTrue(self.vault.backup_now()["ok"])
        self.assertEqual(len(ids), 4)
        log = (self.folder / "nonces.log").read_text().split()
        current = [h["nonce"] for h in self.headers().values() if h["key_id"] == self.key_id()]
        self.assertTrue(set(current) <= set(log))                           # every nonce in use is in the active log
        for h in self.headers().values():
            self.assertEqual(h["key_id"], self.key_id())
        nonces = self.all_nonces()
        self.assertEqual(len(nonces), len(set(nonces)))

    def test_an_approval_is_used_once(self):
        self.assertTrue(self.vault.rotate_key("normal", RID)["ok"])
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")
        self.assertEqual(self.vault.rotate_key("normal", "not hex")["error"], "key_rotation_request_invalid")
        self.assertEqual(self.vault.rotate_key("sideways", "cd" * 32)["error"], "key_rotation_request_invalid")
        self.assertEqual(self.vault.rotate_key(None, None), {"ok": True, "nothing_to_resume": True})

    def test_a_backup_the_old_key_cannot_open_keeps_the_old_key_alive_and_is_never_deleted(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        data = bytearray(damaged.read_bytes())
        data[-5] ^= 1
        damaged.write_bytes(bytes(data))
        old = self.key_id()
        result = self.vault.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 2)
        self.assertFalse(result["old_key_destroyed"])
        self.assertTrue(damaged.exists())
        self.assertEqual(self.vault._header_of(names[0])["key_id"], old)
        self.assertTrue((self.folder / "keys" / (old + ".key")).exists())   # never destroyed while a retained backup needs it
        # and once that backup is gone, a later rotation is free to destroy the retired generation
        os.unlink(damaged)
        self.vault.rotate_key("normal", "cd" * 32)
        self.assertFalse((self.folder / "keys" / (old + ".key")).exists())

    def test_a_retired_generation_still_opens_its_backups(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        keep = damaged.read_bytes()
        data = bytearray(keep)
        data[-5] ^= 1
        damaged.write_bytes(bytes(data))
        old = self.key_id()
        self.vault.rotate_key("normal", RID)
        damaged.write_bytes(keep)                                            # the damage was temporary (e.g. a bad read)
        os.chmod(damaged, 0o600)
        header, meta, blobs = self.vault.open_backup(names[0])
        self.assertEqual(header["key_id"], old)
        self.assertIn("state.tar", blobs)

    def test_a_reencrypted_copy_that_fails_verification_never_replaces_the_original(self):
        original = {n: (self.folder / n).read_bytes() for n in self.headers()}
        real = vault.Vault._cipher

        class Liar:
            def __init__(self, inner):
                self.inner = inner

            def encrypt(self, nonce, data, aad):
                return self.inner.encrypt(nonce, data[:-1] + bytes([data[-1] ^ 1]), aad)

            def decrypt(self, *a):
                return self.inner.decrypt(*a)

        def cipher(this, key):
            inner = real(this, key)
            return Liar(inner) if key != this._key_for(this._index(), this._journal()["old_key_id"]) else inner

        with mock.patch.object(vault.Vault, "_cipher", cipher):
            result = self.vault.rotate_key("normal", RID)
        self.assertEqual(result["error"], "reencrypted_backup_failed_verification")
        self.assertEqual({n: (self.folder / n).read_bytes() for n in self.headers()}, original)
        self.assertEqual(list(self.folder.glob(".rotate-*")), [])
        self.assertIn("key_rotation_incomplete", self.vault.status()["problems"])
        self.assertEqual(self.vault.backup_now()["error"], "key_rotation_in_progress")   # nothing else runs meanwhile
        result = self.vault.tick()["rotate"]                                 # the fault is gone: it resumes and finishes
        self.assertTrue(result["ok"], result)
        self.assertTrue(set(original) <= set(self.contents()))

    def test_running_out_of_space_stops_safely_and_resumes(self):
        self.o.space.free = 10
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "insufficient_storage")
        self.assertEqual(len(self.headers()), 3)
        self.o.space.free = 10 ** 12
        self.assertTrue(self.vault.rotate_key(None, None)["ok"])
        self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()})

    def test_a_lost_nonce_log_is_resolved_by_an_approved_new_key(self):
        os.unlink(self.folder / "nonces.log")
        self.assertEqual(self.vault.backup_now()["error"], "nonce_log_missing")
        before = self.contents()
        self.assertTrue(self.vault.rotate_key("normal", RID)["ok"])
        self.assertEqual(self.contents(), before)
        self.assertNotIn("nonce_log_missing", self.vault.status()["problems"])
        self.assertTrue(self.vault.backup_now()["ok"])

    def test_a_swapped_key_is_never_trusted(self):
        self.vault.rotate_key("normal", RID)
        other = vault.KEY_MAGIC + b"\x01" * 8 + b"\x02" * 32
        (self.folder / "backup-key").write_bytes(other)
        os.chmod(self.folder / "backup-key", 0o600)
        name = next(iter(self.headers()))
        with self.assertRaises(VaultError) as e:
            self.vault.open_backup(name)
        self.assertEqual(e.exception.code, "backup_key_does_not_match_the_vault")
        self.assertFalse(self.vault.rotate_key("normal", "cd" * 32)["ok"])
        self.assertEqual(len(self.headers()), 3)

    def test_rotation_runs_in_the_memory_limited_worker_and_resumes_there(self):
        isolated = vault.Vault(side="owner", state_dir=self.o.config.state_dir, folder=self.folder, extras=self.vault.extras,
                               isolate=True)
        before = self.contents()
        result = isolated.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.contents(), before)
        self.assertEqual(isolated.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")

    # lost key ------------------------------------------------------------------------------------------------------------------
    def test_a_lost_key_moves_unreadable_backups_aside_and_never_deletes_them(self):
        names = set(self.headers())
        sizes = {n: (self.folder / n).stat().st_size for n in names}
        os.unlink(self.folder / "backup-key")
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "backup_key_missing_use_lost_key_mode")
        result = self.vault.rotate_key("lost_key", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["moved_unreadable"], 3)
        self.assertEqual({p.name: p.stat().st_size for p in (self.folder / "unreadable").glob("*.stynvault")}, sizes)
        self.assertEqual(self.headers(), {})
        status = self.vault.status()
        self.assertIn("unreadable_backups_kept:3", status["problems"])
        self.assertNotIn("backup_key_missing", status["problems"])
        self.assertTrue(self.vault.backup_now()["ok"])                       # a fresh start with a fresh key
        self.vault.tick()
        self.vault.recheck_all()
        self.assertEqual(len(list((self.folder / "unreadable").glob("*.stynvault"))), 3)   # retention never touches them

    def test_lost_key_mode_is_refused_while_the_key_is_present(self):
        self.assertEqual(self.vault.rotate_key("lost_key", RID)["error"], "key_is_present_use_normal_mode")
        self.assertEqual(len(self.headers()), 3)

    def test_lost_key_mode_keeps_backups_of_a_retired_generation_that_is_still_here(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        keep = damaged.read_bytes()
        data = bytearray(keep)
        data[-5] ^= 1
        damaged.write_bytes(bytes(data))
        self.vault.rotate_key("normal", RID)                                  # names[0] still needs the retired key
        damaged.write_bytes(keep)
        os.chmod(damaged, 0o600)
        os.unlink(self.folder / "backup-key")                                 # now the ACTIVE key is lost
        result = self.vault.rotate_key("lost_key", "cd" * 32)
        self.assertEqual(result["moved_unreadable"], 2)
        self.assertTrue(damaged.exists())
        self.vault.open_backup(names[0])                                      # still readable with its kept generation

    # interruption / power loss at every durable step -------------------------------------------------------------------------
    def _crash_matrix(self, mode, prepare):
        """Run the rotation once counting durable steps, then for each step k: rebuild, lose power at step k, resume, check."""
        def durable_calls():
            return [(vault, "_write_atomic"), (vault.os, "replace"), (vault.os, "unlink"), (vault.os, "fsync")]

        def run(fail_at):
            counter = {"n": 0}
            patches = []
            for owner, name in durable_calls():
                real = getattr(owner, name)

                def wrapped(*a, _real=real, **k):
                    counter["n"] += 1
                    if counter["n"] == fail_at:
                        raise PowerLoss()
                    return _real(*a, **k)
                patches.append(mock.patch.object(owner, name, wrapped))
            for p in patches:
                p.start()
            try:
                try:
                    self.vault.rotate_key(mode, RID)
                    return counter["n"], False
                except PowerLoss:
                    return counter["n"], True
            finally:
                for p in patches:
                    p.stop()

        expect = prepare()
        total, _ = run(0)
        self.assertGreater(total, 10)
        for k in range(1, total + 1):
            with self.subTest(step=k):
                self.setUp()
                expect = prepare()
                _, crashed = run(k)
                self.assertTrue(crashed)
                self.vault = self.fresh()                                     # the service restarts after the power loss
                done = self.vault.tick()
                if "rotate" in done:
                    self.assertTrue(done["rotate"]["ok"], (k, done))
                elif (self.vault._index().get("last_rotation") or {}).get("request_id") == RID:
                    pass                                                      # it had finished; only the last flush was lost
                else:                                                         # crashed before the approval was spent
                    self.assertFalse((self.folder / "rotation.json").exists())
                    again = self.vault.rotate_key(mode, "ee" * 32)
                    self.assertTrue(again["ok"], (k, again))
                expect(k)

    def test_power_loss_at_every_step_of_a_normal_rotation_loses_nothing(self):
        def prepare():
            before = self.contents()

            def expect(k):
                self.assertFalse((self.folder / "rotation.json").exists(), k)
                after = self.contents()
                self.assertEqual({n: after[n] for n in before}, before, k)       # (a due backup may have been added since)
                self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()}, k)
                self.assertEqual(len(list((self.folder / "keys").glob("*.key"))), 0, k)   # old key gone only when unneeded
                self.assertEqual(list(self.folder.glob(".rotate-*")), [], k)
                nonces = self.all_nonces()
                self.assertEqual(len(nonces), len(set(nonces)), k)
                self.assertNotIn("key_rotation_incomplete", self.vault.status()["problems"], k)
                self.assertTrue(self.vault.backup_now()["ok"], k)
            return expect
        self._crash_matrix("normal", prepare)

    def test_power_loss_at_every_step_of_a_lost_key_recovery_loses_nothing(self):
        def prepare():
            sizes = {n: (self.folder / n).stat().st_size for n in self.headers()}
            os.unlink(self.folder / "backup-key")

            def expect(k):
                self.assertFalse((self.folder / "rotation.json").exists(), k)
                kept = {p.name: p.stat().st_size for p in (self.folder / "unreadable").glob("*.stynvault")}
                self.assertEqual(kept, sizes, k)                              # every archive preserved, byte count intact
                self.assertTrue((self.folder / "backup-key").exists(), k)
                self.assertTrue(self.vault.backup_now()["ok"], k)
            return expect
        self._crash_matrix("lost_key", prepare)


if __name__ == "__main__":
    unittest.main()


try:
    import test_runner_door as door
    import test_dev23_retention as ret
    from datetime import datetime, timedelta, timezone
    import jwt  # noqa: F401
except Exception:                                    # pragma: no cover
    door = None


@unittest.skipIf(door is None or tv is None, "needs PyJWT, cryptography")
class RotationApprovalTests(unittest.TestCase):
    """Rotation is YELLOW: only with the owner's single-use proof for exactly that request."""

    @classmethod
    def setUpClass(cls):
        door.Door.setUpClass()

    def setUp(self):
        self.a = ret.ApprovalTests("test_the_owner_reads_what_changes_and_one_proof_changes_it_once")
        self.a.setUp()
        self.addCleanup(self.a.doCleanups)
        self.executor, self.v = self.a.executor, self.a.v
        from stynpilot.broker.executor import Runs
        from stynpilot.ledger import InstallLedger
        state = self.a.tmp / "inst"
        state.mkdir(mode=0o700)
        Runs(state / "runs.sqlite3")
        InstallLedger(state / "installs.sqlite3")
        for tree in ("snapshots", "attention"):
            (state / tree).mkdir()
        self.v = self.executor.vault = vault.Vault(side="root", state_dir=state, folder=self.a.tmp / "rootvault")

    def rpayload(self, side="root", mode="normal", minutes=60, **kw):
        p = {"kind": "backup", "action": "rotate_key", "side": side, "mode": mode, "owner": door.OWNER, "device": door.DEVICE,
             "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        p.update(kw)
        return p

    def approve(self, payload):
        out = self.executor.challenge(payload, "approve")
        return out, self.executor.backup_admin(payload, self.a.proof(payload, out["challenge"]), out["challenge"])

    def test_root_rotation_runs_once_with_the_owners_proof(self):
        made = self.v.backup_now()
        self.assertTrue(made["ok"], made)
        old = (self.a.tmp / "rootvault" / "backup-key").read_bytes()
        payload = self.rpayload()
        out, result = self.approve(payload)
        text = "\n".join(out["summary"])
        self.assertIn("re-encrypted with the new key and checked", text)
        self.assertIn("root installer side", text)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 1)
        self.assertNotEqual((self.a.tmp / "rootvault" / "backup-key").read_bytes(), old)
        self.a.denied("already_decided_or_used", self.executor.challenge, payload, "approve")

    def test_owner_rotation_is_only_authorized_here_and_run_by_the_owner_side(self):
        payload = self.rpayload(side="owner")
        out, result = self.approve(payload)
        self.assertIn("your own side", "\n".join(out["summary"]))
        rid = door.request_id(payload)[0]
        self.assertEqual(result, {"ok": True, "action": "rotate_key", "side": "owner", "mode": "normal", "owner_side_authorized": rid})
        self.assertFalse((self.a.tmp / "rootvault" / "keys").exists())         # the root vault was not touched

    def test_lost_key_summary_warns_and_bad_requests_change_nothing(self):
        out = self.executor.challenge(self.rpayload(mode="lost_key"), "approve")
        self.assertIn("unreadable", "\n".join(out["summary"]))
        self.assertIn("nothing is deleted", "\n".join(out["summary"]))
        for bad in (self.rpayload(side="pi"), self.rpayload(mode="wipe"), dict(self.rpayload(), daily=7),
                    self.rpayload(owner="someone-else"), self.rpayload(action="rotate")):
            self.a.denied("backup_request_invalid", self.executor.challenge, bad, "approve")
        self.a.denied("plan_invalid_or_expired", self.executor.challenge, self.rpayload(minutes=-1), "approve")
        payload = self.rpayload()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        with self.assertRaises(door.ExecutionDenied):
            self.executor.backup_admin(payload, self.a.proof(self.rpayload(side="owner"), challenge), challenge)

    def test_the_owner_side_hook_rotates_only_for_its_own_authorized_request(self):
        from stynpilot import service
        o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        o.setUp()
        self.addCleanup(o.doCleanups)
        self.assertTrue(o.vault.backup_now()["ok"])
        hook = service._owner_after_approval(lambda: o.vault)
        payload = self.rpayload(side="owner")
        rid = "cd" * 32
        self.assertIsNone(hook(payload, rid, {"ok": True, "owner_side_authorized": "ef" * 32}))   # not this request
        self.assertIsNone(hook(dict(payload, side="root"), rid, {"ok": True, "owner_side_authorized": rid}))
        self.assertIsNone(hook({"kind": "upgrade"}, rid, {"ok": True}))
        result = hook(payload, rid, {"ok": True, "action": "rotate_key", "side": "owner", "owner_side_authorized": rid})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 1)
        busy = iter([{"ok": False, "error": "another_backup_operation_is_running"}, {"ok": True, "reencrypted": 0}])
        waits = []
        fake = type("V", (), {"rotate_key": lambda self, mode, r: next(busy)})()
        waited = service._owner_after_approval(lambda: fake, sleep=waits.append)(payload, rid, {"ok": True, "owner_side_authorized": rid})
        self.assertEqual((waited["ok"], waits), (True, [30]))                 # waits for a running backup, then rotates
        again = hook(payload, rid, {"ok": True, "owner_side_authorized": rid})
        self.assertEqual((again["ok"], again["stopped"]), (False, "key_rotation_request_already_used"))


@unittest.skipIf(door is None or tv is None, "needs PyJWT, cryptography")
class RotationToolTests(unittest.TestCase):
    def setUp(self):
        t = tv.BackupToolTests("test_backup_tools_work_and_writes_need_the_write_gate")
        t.setUp()
        self.addCleanup(t.doCleanups)
        self.h = t.h

    def test_the_request_is_filed_for_the_owner_and_bad_values_are_refused(self):
        out = self.h.call("commander_request_backup_key_rotation", self.h.d(side="owner", mode="normal"))
        self.assertTrue(out["ok"], out)
        result = out["result"]
        self.assertEqual((result["kind"], result["state"], result["approved_by_ai"]), ("backup", "pending", False))
        self.assertIn("re-encrypted", "\n".join(result["summary"]))
        self.assertEqual(self.h.call("commander_request_backup_key_rotation", self.h.d(side="pi"))["error"],
                         "side_root_or_owner_and_mode_normal_or_lost_key")
        self.assertFalse(self.h.call("commander_request_backup_key_rotation", self.h.d(side="root"), "readonly").get("ok"))
