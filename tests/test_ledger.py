"""Install ledger: rollback only for real, owned, verified-backup installs."""
import os
import tempfile
import unittest
from pathlib import Path

from stynpilot.ledger import InstallLedger, LedgerError

OWNER, DEVICE = "acct_" + "a" * 40, "dtdev_TESTONLYliveDevice"


class LedgerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "state" / "installs.sqlite3"
        self.ledger = InstallLedger(self.path)
        self.ledger.record(rollback_id="ab" * 16, software="htop", owner=OWNER, device=DEVICE,
                           request_id="c" * 64, snapshot_id="snap-1", snapshot_verified=True)

    def test_valid_entry(self):
        entry = self.ledger.rollbackable("ab" * 16, software="htop", owner=OWNER, device=DEVICE)
        self.assertEqual((entry["snapshot_id"], entry["request_id"]), ("snap-1", "c" * 64))
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_wrong_device_owner_software_and_rolled_back(self):
        with self.assertRaises(LedgerError) as c:
            self.ledger.rollbackable("ab" * 16, software="htop", owner=OWNER, device="dtdev_TESTONLYother000")
        self.assertEqual(c.exception.code, "unknown_rollback_id")
        with self.assertRaises(LedgerError) as c:
            self.ledger.rollbackable("ab" * 16, software="forgejo", owner=OWNER, device=DEVICE)
        self.assertEqual(c.exception.code, "rollback_id_is_for_other_software")
        import sqlite3
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE installs SET rolled_back=1")
        with self.assertRaises(LedgerError) as c:
            self.ledger.rollbackable("ab" * 16, software="htop", owner=OWNER, device=DEVICE)
        self.assertEqual(c.exception.code, "already_rolled_back")

    def test_record_rejects_bad_entries_and_shared_files_are_refused(self):
        with self.assertRaises(LedgerError):
            self.ledger.record(rollback_id="nope", software="htop", owner=OWNER, device=DEVICE,
                               request_id="x", snapshot_id="s", snapshot_verified=True)
        with self.assertRaises(LedgerError):
            self.ledger.record(rollback_id="ee" * 16, software="htop", owner=OWNER, device=DEVICE,
                               request_id="x", snapshot_id="s", snapshot_verified="yes")
        os.chmod(self.path, 0o644)
        with self.assertRaises(LedgerError):
            InstallLedger(self.path)


if __name__ == "__main__":
    unittest.main()
