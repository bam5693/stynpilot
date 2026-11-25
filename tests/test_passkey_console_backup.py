"""dev15 pre-live concerns: (1) activation only at the computer's console by default; (2) passkey backup that never resurrects
a revoked passkey and never gives a restored one approval power until the owner re-confirms it at the console."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
try:
    from stynpilot import backup, passkey_console
    from stynpilot.broker.executor import ExecutionDenied, Executor, Runs
    from stynpilot.broker.passkeys import PasskeyError, PasskeyStore
    from stynpilot.ledger import InstallLedger
    from softauth import SoftAuthenticator
except ImportError:          # pragma: no cover
    backup = None

RP = "deckplayhq.tail4bc147.ts.net"
ORIGIN = "https://deckplayhq.tail4bc147.ts.net:8443"


def pending_key(store, label="Pixel"):
    rid = "%064x" % (abs(hash((label, os.urandom(4)))) % (1 << 60))
    store.open_window(rid, label, "auth0")
    info = store.begin(rid)
    return store.complete(rid, SoftAuthenticator(ORIGIN, RP).register(bytes.fromhex(info["challenge"])))


@unittest.skipIf(backup is None, "needs the project dependencies")
class ConsoleActivation(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.store = PasskeyStore(self.tmp / "p.sqlite3", rp_id=RP, origin=ORIGIN)
        self.out = []

    def run_activate(self, kid, typed, tty=True):
        return passkey_console.activate(self.store, kid, input_fn=lambda _p: typed, is_tty=tty, out=self.out.append)

    def test_remote_activation_is_off_by_default(self):
        executor = Executor(state_dir=self.tmp / "b", owner="o", device="d", verifier=None, passkeys=self.store) \
            if (self.tmp / "b").mkdir(mode=0o700) is None else None
        self.assertFalse(executor.allow_remote_activation)
        with self.assertRaises(ExecutionDenied) as refused:
            executor._check_passkey_payload({"kind": "passkey", "action": "activate", "label": "x", "kid": "a" * 16,
                                             "pub": "b" * 64, "owner": "o", "device": "d", "expires_at": 1})
        self.assertIn("activation_needs_the_console", str(refused.exception))

    def test_console_activates_with_the_typed_fingerprint(self):
        key = pending_key(self.store)
        self.assertEqual(self.store.active(), [])
        self.assertEqual(self.run_activate(key["kid"], key["pub"][:8]), 0)
        self.assertEqual([k["kid"] for k in self.store.active()], [key["kid"]])
        self.assertTrue(self.store.audit_ok())

    def test_wrong_text_or_blank_changes_nothing(self):
        key = pending_key(self.store)
        for typed in ("", "00000000", key["pub"][:7]):
            self.assertEqual(self.run_activate(key["kid"], typed), 1)
        self.assertEqual(self.store.active(), [])

    def test_needs_a_terminal(self):
        key = pending_key(self.store)
        self.assertEqual(self.run_activate(key["kid"], key["pub"][:8], tty=False), 2)
        self.assertEqual(self.store.active(), [])

    def test_unknown_id_and_extra_pending_keys_are_called_out(self):
        first, second = pending_key(self.store, "One"), pending_key(self.store, "Two")
        self.assertEqual(self.run_activate("f" * 16, "x"), 1)
        self.run_activate(first["kid"], "")
        self.assertTrue(any("WARNING" in line for line in self.out))
        self.assertEqual(self.run_activate(first["kid"], first["pub"][:8]), 0)
        self.assertEqual(len(self.store.active()), 1)


@unittest.skipIf(backup is None, "needs the project dependencies")
class PasskeyBackup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.state = self.tmp / "inst"
        self.state.mkdir(mode=0o700)
        Runs(self.state / "runs.sqlite3")
        InstallLedger(self.state / "installs.sqlite3")
        (self.state / "snapshots").mkdir()
        (self.state / "attention").mkdir()
        self.store = PasskeyStore(self.state / "passkeys.sqlite3", rp_id=RP, origin=ORIGIN)

    def add_active(self, label):
        key = pending_key(self.store, label)
        self.store.activate(key["kid"], key["label"], key["pub"], "console", "console")
        return key

    @staticmethod
    def credential_id(store, kid):
        import sqlite3
        db = sqlite3.connect(str(store.path))
        try:
            return db.execute("SELECT credential_id FROM passkeys WHERE kid=?", (kid,)).fetchone()[0]
        finally:
            db.close()

    def test_the_database_only_ever_appears_on_disk_already_quarantined(self):
        key = self.add_active("Pixel")
        archive = self.tmp / "q.tar"
        backup.make_backup(self.state, archive, kind="root")
        seen = []
        real = backup._write_all

        def spy(state_dir, files, ignore):
            import sqlite3
            import tempfile
            with tempfile.TemporaryDirectory() as t:
                image = Path(t) / "i.sqlite3"
                image.write_bytes(files["passkeys.sqlite3"])
                db = sqlite3.connect(str(image))
                seen.append(db.execute("SELECT quarantined FROM passkeys WHERE kid=?", (key["kid"],)).fetchone()[0])
                db.close()
            return real(state_dir, files, ignore)
        backup._write_all = spy
        try:
            backup.restore_backup(archive, self.tmp / "rs", kind="root")
        finally:
            backup._write_all = real
        self.assertEqual(seen, [1])

    def test_an_interrupted_restore_never_leaves_an_unquarantined_passkey_database(self):
        key = self.add_active("Pixel")
        archive = self.tmp / "i.tar"
        backup.make_backup(self.state, archive, kind="root")
        # (a) quarantining fails: nothing at all is written
        from stynpilot.broker import passkeys as pk
        real = pk.quarantine_bytes

        def boom(*_a, **_k):
            raise RuntimeError("disk full")
        pk.quarantine_bytes = boom
        try:
            with self.assertRaises(backup.BackupError) as refused:
                backup.restore_backup(archive, self.tmp / "ra", kind="root")
        finally:
            pk.quarantine_bytes = real
        self.assertIn("nothing_was_restored", str(refused.exception))
        self.assertFalse((self.tmp / "ra").exists())                    # not even the folder was created
        # (b) the process dies part-way through writing: whatever passkey file exists is already quarantined
        real_fsync, calls = os.fsync, []

        def dying(fd):
            calls.append(fd)
            if len(calls) == 3:
                raise OSError("power cut")
            return real_fsync(fd)
        os.fsync = dying
        try:
            with self.assertRaises(OSError):
                backup.restore_backup(archive, self.tmp / "rb", kind="root")
        finally:
            os.fsync = real_fsync
        left = self.tmp / "rb" / "passkeys.sqlite3"
        if left.exists() and left.stat().st_size:
            half = PasskeyStore(left, rp_id=RP, origin=ORIGIN)
            self.assertEqual(half.active(), [])
        # and the half-written folder cannot be reused as a restore target
        with self.assertRaises(backup.BackupError) as again:
            backup.restore_backup(archive, self.tmp / "rb", kind="root")
        self.assertIn("not_empty", str(again.exception))

    def restore(self):
        archive = self.tmp / ("b%d.tar" % len(list(self.tmp.glob("b*.tar"))))
        manifest = backup.make_backup(self.state, archive, kind="root")
        dest = self.tmp / ("r%d" % len(list(self.tmp.glob("r*"))))
        backup.restore_backup(archive, dest, kind="root")
        return manifest, PasskeyStore(dest / "passkeys.sqlite3", rp_id=RP, origin=ORIGIN)

    def test_passkey_database_is_included_when_present_and_optional_when_absent(self):
        self.add_active("Pixel")
        manifest, _ = self.restore()
        self.assertIn("passkeys.sqlite3", manifest["files"])
        (self.state / "passkeys.sqlite3").unlink()
        manifest, _ = None, None
        archive = self.tmp / "none.tar"
        self.assertNotIn("passkeys.sqlite3", backup.make_backup(self.state, archive, kind="root")["files"])
        backup.restore_backup(archive, self.tmp / "rn", kind="root")
        self.assertFalse((self.tmp / "rn" / "passkeys.sqlite3").exists())

    def test_restored_passkeys_are_quarantined_and_cannot_approve(self):
        key = self.add_active("Pixel")
        _, restored = self.restore()
        self.assertEqual(restored.active(), [])
        self.assertEqual([k["kid"] for k in restored.quarantined()], [key["kid"]])
        cred = self.credential_id(self.store, key["kid"])
        self.assertIsNotNone(self.store.lookup(cred))                         # the original still works...
        self.assertIsNone(restored.lookup(cred))                              # ...the restored copy cannot approve anything
        passkey_console.confirm_restored(restored, key["kid"], input_fn=lambda _p: key["pub"][:8], is_tty=True, out=lambda _l: None)
        self.assertEqual(restored.lookup(cred)["kid"], key["kid"])            # until the owner re-confirms it at the console
        self.assertFalse(restored.retirement_ready())
        self.assertTrue(restored.audit_ok())

    def test_a_passkey_revoked_after_the_backup_does_not_come_back_by_itself(self):
        key = self.add_active("Pixel")
        archive = self.tmp / "old.tar"
        backup.make_backup(self.state, archive, kind="root")
        self.store.revoke(key["kid"], "r" * 64)                       # revoked AFTER the backup was taken
        # the restore brings the old file back: the key is NOT active, only quarantined until the owner re-confirms
        backup.restore_backup(archive, self.tmp / "r", kind="root")
        restored = PasskeyStore(self.tmp / "r" / "passkeys.sqlite3", rp_id=RP, origin=ORIGIN)
        self.assertEqual(restored.active(), [])
        out = []
        code = passkey_console.confirm_restored(restored, key["kid"], input_fn=lambda _p: "", is_tty=True, out=out.append)
        self.assertEqual((code, restored.active()), (1, []))        # declining (blank) leaves it dead
        passkey_console.confirm_restored(restored, key["kid"], input_fn=lambda _p: key["pub"][:8], is_tty=True, out=out.append)
        self.assertEqual([k["kid"] for k in restored.active()], [key["kid"]])
        self.assertTrue(restored.audit_ok())

    def test_a_key_revoked_before_the_backup_stays_revoked(self):
        key = self.add_active("Gone")
        self.store.revoke(key["kid"], "r" * 64)
        _, restored = self.restore()
        self.assertEqual((restored.active(), restored.quarantined()), ([], []))
        self.assertEqual(passkey_console.confirm_restored(restored, key["kid"], input_fn=lambda _p: key["pub"][:8],
                                                          is_tty=True, out=lambda _l: None), 1)
        self.assertEqual(restored.active(), [])

    def test_restore_is_recorded_in_the_audit_and_needs_a_terminal_to_confirm(self):
        key = self.add_active("Pixel")
        _, restored = self.restore()
        self.assertTrue(any("restored" in str(row) for row in restored.audit_tail(50)))
        self.assertEqual(passkey_console.confirm_restored(restored, key["kid"], input_fn=lambda _p: key["pub"][:8],
                                                          is_tty=False, out=lambda _l: None), 2)
        self.assertEqual(restored.active(), [])

    def test_a_damaged_passkey_database_makes_the_backup_refused(self):
        self.add_active("Pixel")
        (self.state / "passkeys.sqlite3").write_bytes(b"not a database" * 100)
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.state, self.tmp / "bad.tar", kind="root")


if __name__ == "__main__":
    unittest.main()
