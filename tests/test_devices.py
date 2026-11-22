"""The new grant reader gives the prototype's answers on the prototype's own database file."""
import os
import tempfile
import time
import unittest
from pathlib import Path

from legacy_pairing import make_pairing_db
from stynpilot.devices import DeviceStoreError, PairingDeviceGrants
from stynpilot.identity import account_id

OWNER = account_id(verified_issuer="https://issuer.example.test/", verified_subject="auth0|test-owner")
OTHER = account_id(verified_issuer="https://issuer.example.test/", verified_subject="auth0|someone-else")
LIVE, REVOKED, EXPIRED = "dtdev_TESTONLYliveDevice", "dtdev_TESTONLYrevokedDev", "dtdev_TESTONLYexpiredDev"


class DeviceGrantTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name) / "state"
        future = time.time() + 3600
        self.path = make_pairing_db(self.folder, [
            (LIVE, OWNER, future, None, ["workspace.propose"]),
            (REVOKED, OWNER, future, 123.0, ["workspace.propose"]),
            (EXPIRED, OWNER, time.time() - 5, None, []),
        ])

    def open(self):
        store = PairingDeviceGrants(self.path)
        self.addCleanup(store.close)
        return store

    def test_live_device_gets_health_plus_consented_scopes(self):
        grant = self.open().get(owner_id=OWNER, device_id=LIVE)
        self.assertEqual(grant.scopes, frozenset({"health.read", "workspace.propose"}))
        self.assertFalse(grant.revoked)

    def test_revoked_is_reported_revoked_and_health_only(self):
        grant = self.open().get(owner_id=OWNER, device_id=REVOKED)
        self.assertTrue(grant.revoked)
        self.assertEqual(grant.scopes, frozenset({"health.read"}))

    def test_expired_wrong_owner_and_bad_ids_get_nothing(self):
        store = self.open()
        self.assertIsNone(store.get(owner_id=OWNER, device_id=EXPIRED))
        self.assertIsNone(store.get(owner_id=OTHER, device_id=LIVE))
        self.assertIsNone(store.get(owner_id="auth0|raw-subject", device_id=LIVE))
        self.assertIsNone(store.get(owner_id=OWNER, device_id="../../etc"))

    def test_only_the_one_live_device_is_offered_for_binding(self):
        self.assertEqual(self.open().paired_devices(), [(OWNER, LIVE)])

    def test_reader_never_writes(self):
        before = self.path.read_bytes()
        store = self.open()
        for _ in range(3):
            store.get(owner_id=OWNER, device_id=LIVE)
        self.assertEqual(self.path.read_bytes(), before)

    def test_refuses_unsafe_or_unknown_files(self):
        os.chmod(self.path, 0o644)
        with self.assertRaises(DeviceStoreError):
            PairingDeviceGrants(self.path)
        os.chmod(self.path, 0o600)
        os.chmod(self.folder, 0o755)
        with self.assertRaises(DeviceStoreError):
            PairingDeviceGrants(self.path)
        os.chmod(self.folder, 0o700)
        with self.assertRaises(DeviceStoreError):
            PairingDeviceGrants("relative/pairing.sqlite3")
        newer = make_pairing_db(self.folder / "newer", [], version=3)
        with self.assertRaises(DeviceStoreError):
            PairingDeviceGrants(newer)

    def test_unknown_scope_in_file_fails_closed(self):
        import sqlite3
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA ignore_check_constraints = ON")
        db.execute("INSERT INTO device_permission_consent VALUES (?, 'root.everything')", (LIVE,))
        db.commit()
        db.close()
        self.assertIsNone(self.open().get(owner_id=OWNER, device_id=LIVE))


if __name__ == "__main__":
    unittest.main()
