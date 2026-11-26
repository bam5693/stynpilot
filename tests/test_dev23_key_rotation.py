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

    def sha_map(self, folder=None):
        import hashlib
        folder = folder or self.folder
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(folder.glob("*.stynvault"))}

    # normal rotation -----------------------------------------------------------------------------------------------------------
    def test_a_rotation_reencrypts_every_backup_verifies_it_and_keeps_the_old_generation(self):
        before, old = self.contents(), self.key_id()
        old_log = (self.folder / "nonces.log").read_bytes()
        result = self.vault.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["reencrypted"], result["rotation"]), (3, "completed"))
        self.assertNotEqual(self.key_id(), old)
        self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()})
        self.assertEqual(self.contents(), before)                           # same backups, same contents, new key
        kept = self.folder / "keys" / (old + ".key")
        self.assertTrue(kept.exists())                                      # never destroyed automatically (this stage)
        self.assertEqual((self.folder / "keys" / (old + ".nonces")).read_bytes(), old_log)   # and its history is kept whole
        self.assertEqual(kept.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.folder / "keys").stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.folder / "keys" / (self.key_id() + ".key")).exists())   # staging copy of the active key removed
        self.assertFalse((self.folder / "rotation.json").exists())
        self.assertEqual(list(self.folder.glob(".rotate-*")), [])
        status = self.vault.status()
        self.assertNotIn("key_rotation_incomplete", status["problems"])
        self.assertEqual(status["keys"]["active"], self.key_id())
        self.assertEqual(status["keys"]["kept_generations"], [{"key_id": old, "nonce_history": True}])
        text = json.dumps(status)
        self.assertNotIn(RID, text)
        self.assertNotIn(kept.read_bytes()[16:].hex(), text)                  # never key material
        self.assertTrue(self.vault.backup_now()["ok"])
        self.assertTrue(self.vault.drill()["ok"])
        self.assertTrue(self.vault.recheck_all()["ok"])
        nonces = self.all_nonces()
        self.assertEqual(len(nonces), len(set(nonces)))

    def test_each_key_generation_has_its_own_id_and_nonce_log_and_nonces_never_repeat(self):
        ids = [self.key_id()]
        for i in range(3):
            self.assertTrue(self.vault.rotate_key("normal", "%02x" % i * 32)["ok"])
            ids.append(self.key_id())
            self.assertTrue(self.vault.backup_now()["ok"])
        self.assertEqual(len(set(ids)), 4)
        self.assertEqual([g["key_id"] for g in self.vault.generations()], sorted(ids[:3]))   # every earlier generation kept
        log = (self.folder / "nonces.log").read_text().split()
        for h in self.headers().values():
            self.assertEqual(h["key_id"], self.key_id())
            self.assertIn(h["nonce"], log)
        nonces = self.all_nonces()
        self.assertEqual(len(nonces), len(set(nonces)))

    def test_an_approval_is_used_once_and_the_spent_record_is_unbounded(self):
        self.assertTrue(self.vault.rotate_key("normal", RID)["ok"])
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")
        for i in range(200):                                                  # far beyond any bounded list
            self.assertTrue(self.vault.rotate_key("normal", "%064x" % (i + 1))["ok"])
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")
        self.assertEqual(self.vault.rotate_key("normal", "not hex")["error"], "key_rotation_request_invalid")
        self.assertEqual(self.vault.rotate_key("sideways", "cd" * 32)["error"], "key_rotation_request_invalid")
        self.assertEqual(self.vault.rotate_key(None, None), {"ok": True, "nothing_to_resume": True})
        self.assertEqual(len(self.vault.generations()), 201)

    def test_a_backup_with_an_unreadable_header_is_left_alone_and_its_key_is_kept(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        data = bytearray(damaged.read_bytes())
        data[0] ^= 0xFF                                                        # header unreadable: key dependency UNKNOWN
        damaged.write_bytes(bytes(data))
        old = self.key_id()
        result = self.vault.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 2)
        self.assertEqual(damaged.read_bytes(), bytes(data))                   # untouched, never deleted
        self.assertTrue((self.folder / "keys" / (old + ".key")).exists())     # never judged unnecessary from an unreadable header

    def test_a_backup_the_old_key_cannot_open_is_left_alone_and_still_opens_once_repaired(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        keep = damaged.read_bytes()
        data = bytearray(keep)
        data[-5] ^= 1
        damaged.write_bytes(bytes(data))
        old = self.key_id()
        result = self.vault.rotate_key("normal", RID)
        self.assertEqual((result["reencrypted"], result["left_with_old_key"]), (2, 1))
        self.assertEqual(self.vault._header_of(names[0])["key_id"], old)
        damaged.write_bytes(keep)                                            # the damage was temporary (e.g. a bad read)
        os.chmod(damaged, 0o600)
        header, meta, blobs = self.vault.open_backup(names[0])
        self.assertEqual(header["key_id"], old)
        self.assertIn("state.tar", blobs)

    def test_a_reencrypted_copy_that_fails_verification_never_replaces_the_original(self):
        original = self.sha_map()
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
        self.assertEqual((result["error"], result["rotation"]), ("reencrypted_backup_failed_verification", "in_progress"))
        self.assertEqual(result["progress"], {"mode": "normal", "state": "reencrypt", "reencrypted": 0, "left_with_old_key": 0})
        self.assertEqual(self.sha_map(), original)
        self.assertEqual(list(self.folder.glob(".rotate-*")), [])
        self.assertIn("key_rotation_incomplete", self.vault.status()["problems"])
        self.assertEqual(self.vault.backup_now()["error"], "key_rotation_in_progress")   # nothing else runs meanwhile
        result = self.vault.tick()["rotate"]                                 # the fault is gone: it resumes and finishes
        self.assertTrue(result["ok"], result)
        self.assertTrue(set(original) <= set(self.contents()))

    def test_running_out_of_space_stops_safely_and_resumes(self):
        self.o.space.free = 10
        result = self.vault.rotate_key("normal", RID)
        self.assertEqual((result["error"], result["rotation"]), ("insufficient_storage", "in_progress"))
        self.assertEqual(len(self.headers()), 3)
        self.o.space.free = 10 ** 12
        self.assertTrue(self.vault.rotate_key(None, None)["ok"])
        self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()})

    def test_a_damaged_or_forged_journal_stops_everything_and_is_never_acted_on(self):
        self.o.space.free = 10
        self.vault.rotate_key("normal", RID)                                 # leaves a real journal
        self.o.space.free = 10 ** 12
        good = json.loads((self.folder / "rotation.json").read_text())
        for bad in (dict(good, state="destroy"), dict(good, extra=1), dict(good, new_key_id=good["old_key_id"]),
                    dict(good, done=["../x"]), dict(good, request_id="x"), dict(good, mode="lost_key"), "[]"):
            (self.folder / "rotation.json").write_text(bad if isinstance(bad, str) else json.dumps(bad))
            os.chmod(self.folder / "rotation.json", 0o600)
            before = self.sha_map()
            self.assertEqual(self.vault.rotate_key(None, None)["error"], "key_rotation_journal_damaged")
            self.assertEqual(self.vault.backup_now()["error"], "key_rotation_in_progress")
            self.assertEqual(self.sha_map(), before)
            self.assertIn("key_rotation_incomplete", self.vault.status()["problems"])
        (self.folder / "rotation.json").write_text(json.dumps(good))
        os.chmod(self.folder / "rotation.json", 0o600)
        self.assertTrue(self.vault.rotate_key(None, None)["ok"])

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

    # lost or uncertain nonce history -------------------------------------------------------------------------------------------
    def test_a_lost_nonce_log_gets_a_fresh_generation_and_existing_backups_stay_as_they_are(self):
        os.unlink(self.folder / "nonces.log")
        self.assertEqual(self.vault.backup_now()["error"], "nonce_log_missing")
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "nonce_log_missing_use_fresh_key_mode")
        before, old = self.sha_map(), self.key_id()
        result = self.vault.rotate_key("fresh_key", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reencrypted"], 0)
        self.assertEqual(self.sha_map(), before)                              # NOT re-encrypted
        self.assertEqual(self.vault.generations(), [{"key_id": old, "nonce_history": False}])   # kept, history marked missing
        self.assertNotIn("nonce_log_missing", self.vault.status()["problems"])
        made = self.vault.backup_now()
        self.assertTrue(made["ok"], made)
        self.assertEqual(self.vault._header_of(made["backup"])["key_id"], self.key_id())   # new material: new generation only
        for name in before:
            self.assertEqual(self.vault._header_of(name)["key_id"], old)
            self.vault.open_backup(name)                                     # still readable with the kept generation
        self.assertTrue(self.vault.recheck_all()["ok"])

    def test_fresh_key_mode_is_refused_while_the_nonce_log_is_fine(self):
        self.assertEqual(self.vault.rotate_key("fresh_key", RID)["error"], "nonce_log_is_fine_use_normal_mode")
        self.assertEqual(self.vault.generations(), [])

    def test_an_uncertain_nonce_history_stops_new_backups_and_a_fresh_generation_fixes_it(self):
        with open(self.folder / "nonces.log", "a") as log:
            log.write("zz-not-a-nonce\n")
        self.assertEqual(self.vault.backup_now()["error"], "nonce_log_uncertain")
        before = self.sha_map()
        self.assertTrue(self.vault.rotate_key("fresh_key", RID)["ok"])
        self.assertEqual(self.sha_map(), before)
        self.assertTrue(self.vault.backup_now()["ok"])

    def test_an_unfinished_last_nonce_line_is_tolerated_and_closed_before_the_next_one(self):
        with open(self.folder / "nonces.log", "a") as log:
            log.write("abcdef")                                               # power cut mid-write: never used
        self.assertTrue(self.vault.backup_now()["ok"])
        lines = (self.folder / "nonces.log").read_text().split("\n")
        self.assertIn("abcdef!", lines)                                       # closed and marked; never counted as a nonce
        self.assertTrue(all(len(x) in (0, 7, 24) for x in lines))
        self.assertTrue(self.vault.backup_now()["ok"])

    def test_a_short_nonce_write_is_detected(self):
        real = vault.os.write
        with mock.patch.object(vault.os, "write", lambda fd, data: real(fd, bytes(data)[:3]) if len(data) > 20 else real(fd, data)), \
                mock.patch.object(vault, "_write_all", lambda fd, data: real(fd, bytes(data)[:3])):
            self.assertEqual(self.vault.backup_now()["error"], "log_write_incomplete")

    # isolation / overlap -------------------------------------------------------------------------------------------------------
    def test_rotation_runs_in_the_memory_limited_worker(self):
        isolated = vault.Vault(side="owner", state_dir=self.o.config.state_dir, folder=self.folder, extras=self.vault.extras,
                               isolate=True)
        before = self.contents()
        result = isolated.rotate_key("normal", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.contents(), before)
        self.assertEqual(isolated.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")

    # lost key ------------------------------------------------------------------------------------------------------------------
    def test_a_lost_key_preserves_every_archive_byte_for_byte_and_never_deletes_them(self):
        before = self.sha_map()
        log = (self.folder / "nonces.log").read_bytes()
        old = self.key_id()
        os.unlink(self.folder / "backup-key")
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "backup_key_missing_use_lost_key_mode")
        result = self.vault.rotate_key("lost_key", RID)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["moved_unreadable"], 3)
        unreadable = self.folder / "unreadable"
        self.assertEqual(self.sha_map(unreadable), before)
        self.assertEqual((unreadable / ("nonces-%s.log" % old)).read_bytes(), log)   # its nonce history preserved too
        self.assertEqual(unreadable.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.headers(), {})
        status = self.vault.status()
        self.assertIn("unreadable_backups_kept:3", status["problems"])
        self.assertNotIn("backup_key_missing", status["problems"])
        self.assertTrue(self.vault.backup_now()["ok"])                       # a fresh start with a fresh key
        self.vault.tick()
        self.vault.recheck_all()
        self.assertEqual(self.sha_map(unreadable), before)                   # retention never touches them

    def test_lost_key_recovery_never_overwrites_an_already_preserved_archive(self):
        unreadable = self.folder / "unreadable"
        unreadable.mkdir(mode=0o700)
        names = list(self.headers())
        (unreadable / names[0]).write_bytes(b"an earlier, different preserved archive")
        os.chmod(unreadable / names[0], 0o600)
        identical = self.folder / names[1]
        os.link(identical, unreadable / names[1])                             # an interrupted earlier move left a copy
        before = self.sha_map()
        os.unlink(self.folder / "backup-key")
        self.assertTrue(self.vault.rotate_key("lost_key", RID)["ok"])
        self.assertEqual((unreadable / names[0]).read_bytes(), b"an earlier, different preserved archive")
        import hashlib
        self.assertEqual(hashlib.sha256((unreadable / (names[0] + ".1")).read_bytes()).hexdigest(), before[names[0]])
        self.assertEqual(hashlib.sha256((unreadable / names[1]).read_bytes()).hexdigest(), before[names[1]])
        self.assertFalse((unreadable / (names[1] + ".1")).exists())
        self.assertEqual(self.headers(), {})

    def test_lost_key_mode_is_refused_while_the_key_is_present(self):
        self.assertEqual(self.vault.rotate_key("lost_key", RID)["error"], "key_is_present_use_normal_mode")
        self.assertEqual(len(self.headers()), 3)

    def test_lost_key_mode_keeps_backups_of_a_kept_generation_in_place(self):
        names = list(self.headers())
        damaged = self.folder / names[0]
        keep = damaged.read_bytes()
        data = bytearray(keep)
        data[-5] ^= 1
        damaged.write_bytes(bytes(data))
        self.vault.rotate_key("normal", RID)                                  # names[0] still needs the kept older key
        damaged.write_bytes(keep)
        os.chmod(damaged, 0o600)
        os.unlink(self.folder / "backup-key")                                 # now the ACTIVE key is lost
        result = self.vault.rotate_key("lost_key", "cd" * 32)
        self.assertEqual(result["moved_unreadable"], 2)
        self.assertTrue(damaged.exists())
        self.vault.open_backup(names[0])                                      # still readable with its kept generation

    # owner side: the durable hand-off ------------------------------------------------------------------------------------------
    def test_the_authorization_marker_changes_nothing_and_binds_the_request(self):
        before = self.sha_map()
        self.assertEqual(self.vault.prepare_rotation("normal", RID, int(self.o.clock()) + 3600)["state"], "awaiting_authorization")
        self.assertEqual(self.sha_map(), before)
        self.assertTrue(self.vault.backup_now()["ok"])                       # backups continue while it awaits
        self.assertIn("key_rotation_awaiting_installer_authorization", self.vault.status()["problems"])
        self.assertEqual(self.vault.prepare_rotation("normal", "cd" * 32, 1)["error"], "another_key_rotation_is_in_progress")
        self.assertEqual(self.vault.rotate_key("normal", "cd" * 32)["error"], "another_key_rotation_is_in_progress")
        self.assertEqual(self.vault.rotate_key("lost_key", RID)["error"], "another_key_rotation_is_in_progress")
        self.assertTrue(self.vault.rotate_key("normal", RID)["ok"])

    def _interrupted_handoff(self, verdict):
        finished = []
        self.vault.on_rotation_finished = lambda rid, result: finished.append((rid, result["rotation"]))
        self.vault.authorization_source = lambda rid: verdict
        self.vault.prepare_rotation("normal", RID, int(self.o.clock()) + 3600)
        # ... the installer authorized it, and the owner service died before rotating (power loss): a new service starts
        self.vault = self.fresh()
        self.vault.on_rotation_finished = lambda rid, result: finished.append((rid, result["rotation"]))
        self.vault.authorization_source = lambda rid: verdict
        self.assertNotIn("rotate", self.vault.tick())                         # inside the grace period: left to the approval flow
        self.o.clock.t += vault.AWAIT_GRACE
        return finished, self.vault.tick()

    def test_an_interrupted_hand_off_is_finished_when_the_installer_record_shows_the_authorization(self):
        old = self.key_id()
        finished, done = self._interrupted_handoff("authorized")
        self.assertTrue(done["rotate"]["ok"], done)
        self.assertNotEqual(self.key_id(), old)
        self.assertEqual(finished, [(RID, "completed")])                     # completion reported from the owner vault itself
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")

    def test_an_interrupted_hand_off_the_installer_did_not_authorize_is_dropped_and_spent(self):
        old, before = self.key_id(), self.sha_map()
        finished, done = self._interrupted_handoff("refused")
        self.assertEqual(done["rotate"], {"ok": True, "cancelled": True})
        self.assertEqual(self.key_id(), old)
        self.assertEqual({n: h for n, h in self.sha_map().items() if n in before}, before)
        self.assertFalse((self.folder / "rotation.json").exists())
        self.assertEqual(finished, [(RID, "failed")])
        self.assertEqual(self.vault.rotate_key("normal", RID)["error"], "key_rotation_request_already_used")

    def test_an_interrupted_hand_off_waits_while_the_installer_cannot_say(self):
        finished, done = self._interrupted_handoff("unknown")
        self.assertEqual(done["rotate"], {"ok": None, "waiting_for_installer": True})
        self.assertTrue((self.folder / "rotation.json").exists())
        self.assertEqual(finished, [])

    # interruption / power loss at every durable step -------------------------------------------------------------------------
    def _crash_matrix(self, mode, prepare, check_crashed=None):
        """Run once counting durable steps, then for each step k: rebuild, lose power at step k, (check), restart, resume, check."""
        def durable_calls():
            return [(vault, "_write_atomic"), (vault.os, "replace"), (vault.os, "unlink"), (vault.os, "fsync"), (vault.os, "link")]

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
                if check_crashed:
                    check_crashed(k)
                self.vault = self.fresh()                                     # the service restarts after the power loss
                done = self.vault.tick()
                if "rotate" in done:
                    self.assertTrue(done["rotate"]["ok"], (k, done))
                elif (self.vault._index().get("last_rotation") or {}).get("request_id") == RID:
                    pass                                                      # it had finished; only the last flush was lost
                else:                                                         # crashed before the journal existed
                    self.assertFalse((self.folder / "rotation.json").exists())
                    again = self.vault.rotate_key(mode, "ee" * 32)
                    self.assertTrue(again["ok"], (k, again))
                expect(k)

    def test_power_loss_at_every_step_of_a_normal_rotation_loses_nothing(self):
        state = {}

        def prepare():
            before = self.contents()
            state["old"] = self.key_id()
            state["old_nonces"] = set((self.folder / "nonces.log").read_text().split())

            def expect(k):
                self.assertFalse((self.folder / "rotation.json").exists(), k)
                after = self.contents()
                self.assertEqual({n: after[n] for n in before}, before, k)       # (a due backup may have been added since)
                self.assertEqual({h["key_id"] for h in self.headers().values()}, {self.key_id()}, k)
                self.assertTrue((self.folder / "keys" / (state["old"] + ".key")).exists(), k)    # the old key is never lost
                self.assertEqual(list(self.folder.glob(".rotate-*")), [], k)
                nonces = self.all_nonces()
                self.assertEqual(len(nonces), len(set(nonces)), k)
                self.assertNotIn("key_rotation_incomplete", self.vault.status()["problems"], k)
                self.assertTrue(self.vault.backup_now()["ok"], k)
            return expect

        def older_reader_is_safe(k):
            # what an OLDER StyNpilot (after a rollback) would do with the vault as the power cut left it: it pairs backup-key with
            # nonces.log only when the index agrees with the key; that pairing must never be old key + new log.
            index = json.loads((self.folder / "index.json").read_text())
            key = self.key_id()
            if index.get("key_id") in (None, key) and key == state["old"]:
                log = set((self.folder / "nonces.log").read_text().split())
                self.assertTrue(state["old_nonces"] <= log, k)
        self._crash_matrix("normal", prepare, older_reader_is_safe)

    def test_power_loss_at_every_step_of_a_fresh_key_rotation_loses_nothing(self):
        def prepare():
            os.unlink(self.folder / "nonces.log")
            before = self.sha_map()

            def expect(k):
                self.assertFalse((self.folder / "rotation.json").exists(), k)
                after = self.sha_map()
                self.assertEqual({n: after[n] for n in before}, before, k)
                self.assertTrue(self.vault.backup_now()["ok"], k)
                for name in before:
                    self.vault.open_backup(name)
            return expect
        self._crash_matrix("fresh_key", prepare)

    def test_power_loss_at_every_step_of_a_lost_key_recovery_loses_nothing(self):
        def prepare():
            before = set(self.sha_map().values())
            log = (self.folder / "nonces.log").read_bytes()
            os.unlink(self.folder / "backup-key")

            def expect(k):
                self.assertFalse((self.folder / "rotation.json").exists(), k)
                unreadable = self.folder / "unreadable"
                self.assertEqual(set(self.sha_map(unreadable).values()), before, k)   # every archive preserved, byte for byte
                self.assertIn(log, [p.read_bytes() for p in unreadable.glob("nonces-*")], k)
                self.assertEqual(len(self.vault._index().get("unreadable", {})), 3, k)   # and the index reconciled
                self.assertTrue((self.folder / "backup-key").exists(), k)
                self.assertTrue(self.vault.backup_now()["ok"], k)
            return expect
        self._crash_matrix("lost_key", prepare)


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
        self.assertEqual(result, {"ok": True, "action": "rotate_key", "side": "owner", "mode": "normal", "owner_side_authorized": rid,
                                  "rotation": "authorized_owner_side_runs_it"})
        self.assertFalse((self.a.tmp / "rootvault" / "keys").exists())         # the root vault was not touched

    def test_lost_key_summary_warns_and_bad_requests_change_nothing(self):
        out = self.executor.challenge(self.rpayload(mode="lost_key"), "approve")
        self.assertIn("unreadable", "\n".join(out["summary"]))
        self.assertIn("nothing is deleted", "\n".join(out["summary"]))
        fresh = "\n".join(self.executor.challenge(self.rpayload(mode="fresh_key"), "approve")["summary"])
        self.assertIn("Existing backups are not changed", fresh)
        normal = "\n".join(self.executor.challenge(self.rpayload(), "approve")["summary"])
        self.assertIn("The old key is KEPT", normal)
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
                         "side_root_or_owner_and_mode_normal_fresh_key_or_lost_key")
        self.assertFalse(self.h.call("commander_request_backup_key_rotation", self.h.d(side="root"), "readonly").get("ok"))


try:
    import test_approval as tapp
except Exception:                                    # pragma: no cover
    tapp = None


class _Crash(BaseException):
    pass


@unittest.skipIf(tapp is None or tv is None or tapp.jwt is None, "needs PyJWT, cryptography")
class OwnerHandOffEndToEndTests(unittest.TestCase):
    """Real approval flow + real installer executor + real owner vault: completion only from the owner vault."""
    @classmethod
    def setUpClass(cls):
        tapp.ApprovalTests.setUpClass()

    def setUp(self):
        from stynpilot import service
        self.service = service
        self.a = tapp.ApprovalTests("test_page_shows_the_root_written_summary_with_the_backup_limits")
        self.a.setUp()
        self.addCleanup(self.a.doCleanups)
        self.o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.addCleanup(self.o.doCleanups)
        self.vault = self.o.vault
        self.assertTrue(self.vault.backup_now()["ok"])
        self.old = (self.o.tmp / "vault" / "backup-key").read_bytes()[8:16].hex()
        self.a.executor.vault = type("RootVaultStub", (), {"_rotation_active": lambda self: False})()
        self.flow = self.wire(self.a.make_flow())

    def wire(self, flow):
        flow.before_run = self.service._owner_before_run(self.o.tmp, lambda: self.vault)
        flow.after_run = self.service._owner_after_approval(lambda: self.vault)
        self.vault.authorization_source = self.service._rotation_authorization(self.a.executor)
        self.vault.on_rotation_finished = self.service._settle_request(self.a.store, flow)
        return flow

    def payload(self):
        from datetime import datetime, timedelta, timezone
        return {"kind": "backup", "action": "rotate_key", "side": "owner", "mode": "normal", "owner": tapp.OWNER,
                "device": tapp.DEVICE, "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def file_and_approve(self):
        payload, rid = self.a.file(kind="backup", payload=self.payload())
        self.a.flow = self.flow
        _, _, finish = self.a.decide(rid, "approve")
        return rid, finish

    def key(self):
        return (self.o.tmp / "vault" / "backup-key").read_bytes()[8:16].hex()

    def test_approved_owner_rotation_completes_and_only_then_is_done(self):
        rid, finish = self.file_and_approve()
        outcome = finish()
        self.assertEqual(outcome["state"], "done", outcome)
        self.assertNotEqual(self.key(), self.old)
        status = self.a.store.status(rid, owner=tapp.OWNER, device=tapp.DEVICE)
        self.assertEqual(status["state"], "done")
        self.assertEqual(self.a.executor.status(rid)["result"]["rotation"], "authorized_owner_side_runs_it")

    def test_a_crash_between_the_installers_authorization_and_the_owner_rotation_is_finished_later(self):
        rid, finish = self.file_and_approve()

        def die(*a):
            raise _Crash()
        self.flow.after_run = die                                             # the owner service dies right here
        with self.assertRaises(_Crash):
            finish()
        self.assertEqual(self.key(), self.old)                                # nothing rotated yet
        self.assertEqual(self.a.executor.status(rid)["state"], "done")       # the installer's AUTHORIZATION is recorded
        # restart: a new flow recovers; the request must NOT be reported done from the installer's authorization alone
        flow = self.wire(self.a.make_flow())
        settled, waiting = flow.recover(patient=True)
        self.assertNotIn(rid, settled)
        self.assertEqual(self.a.store.status(rid, owner=tapp.OWNER, device=tapp.DEVICE)["state"], "running")
        self.o.clock.t += 10 ** 6                                             # past the hand-off grace period
        done = self.vault.tick()
        self.assertTrue(done["rotate"]["ok"], done)
        self.assertNotEqual(self.key(), self.old)
        record = self.a.store.status(rid, owner=tapp.OWNER, device=tapp.DEVICE)
        self.assertEqual(record["state"], "done")                              # settled by the owner vault on completion

    def test_a_crash_before_the_installer_received_it_never_rotates(self):
        rid, finish = self.file_and_approve()
        real = self.a.executor.backup_admin

        def die(*a):
            raise _Crash()
        self.a.executor.backup_admin = die
        with self.assertRaises(_Crash):
            finish()
        self.a.executor.backup_admin = real
        self.assertEqual(self.a.executor.status(rid)["state"], "not_started")
        self.o.clock.t += 10 ** 6
        done = self.vault.tick()
        self.assertEqual(done["rotate"], {"ok": True, "cancelled": True})
        self.assertEqual(self.key(), self.old)
        self.assertFalse((self.o.tmp / "vault" / "rotation.json").exists())
        self.assertEqual(self.vault.rotate_key("normal", rid)["error"], "key_rotation_request_already_used")


@unittest.skipIf(door is None or tv is None, "needs PyJWT, cryptography")
class RotationOverlapTests(unittest.TestCase):
    def setUp(self):
        self.k = KeyRotationTests("test_a_swapped_key_is_never_trusted")
        self.k.setUp()

    def test_the_installer_refuses_other_changes_while_a_rotation_is_active(self):
        r = RotationApprovalTests("test_root_rotation_runs_once_with_the_owners_proof")
        RotationApprovalTests.setUpClass()
        r.setUp()
        self.addCleanup(r.doCleanups)
        self.assertTrue(r.v.backup_now()["ok"])
        r.o_space = None
        with mock.patch.object(vault.Vault, "_reencrypt_one", side_effect=VaultError("insufficient_storage")):
            out, result = r.approve(r.rpayload())
        self.assertEqual((result["ok"], result["rotation"]), (False, "in_progress"))
        self.assertEqual(result["progress"]["state"], "reencrypt")
        with self.assertRaises(door.ExecutionDenied) as e:
            r.executor._no_other_change()                                     # no install/rollback/upgrade/second rotation
        self.assertEqual(e.exception.code, "key_rotation_in_progress")
        self.assertTrue(r.v.tick()["rotate"]["ok"])                           # resumes and finishes
        r.executor._no_other_change()

    def test_a_root_rotation_never_runs_during_an_install_or_rollback(self):
        from stynpilot import statelock
        r = RotationApprovalTests("test_root_rotation_runs_once_with_the_owners_proof")
        RotationApprovalTests.setUpClass()
        r.setUp()
        self.addCleanup(r.doCleanups)
        self.assertTrue(r.v.backup_now()["ok"])
        old = (r.a.tmp / "rootvault" / "backup-key").read_bytes()
        with statelock.operation(r.v.state_dir):                              # an install/rollback holds the installer lock
            result = r.v.rotate_key("normal", "ab" * 32)
        self.assertEqual((result["ok"], result["error"]), (False, "an_install_or_rollback_is_running_try_again_when_it_finishes"))
        self.assertEqual((r.a.tmp / "rootvault" / "backup-key").read_bytes(), old)
        self.assertTrue(r.v.tick()["rotate"]["ok"])
