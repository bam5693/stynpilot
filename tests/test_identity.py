"""Pseudonymous account IDs and fail-closed revocation stores."""
import os
import tempfile
import unittest
from pathlib import Path

from stynpilot.identity import MemoryRevocations, RevocationError, SQLiteRevocations, account_id

ISS = "https://issuer.example.test/"


class IdentityTests(unittest.TestCase):
    def test_account_id_is_stable_and_hides_the_subject(self):
        a = account_id(verified_issuer=ISS, verified_subject="auth0|owner")
        self.assertEqual(a, account_id(verified_issuer=ISS, verified_subject="auth0|owner"))
        self.assertRegex(a, r"^acct_[a-f0-9]{40}$")
        self.assertNotIn("owner", a)
        self.assertNotEqual(a, account_id(verified_issuer="https://other.test/", verified_subject="auth0|owner"))

    def test_account_id_rejects_unverified_shapes(self):
        for issuer, subject in (("http://plain.test/", "x"), (ISS, ""), (ISS, "a\x00b"), (ISS, "x" * 300), (None, "x")):
            with self.assertRaises(ValueError):
                account_id(verified_issuer=issuer, verified_subject=subject)

    def test_revocation_only_moves_forward(self):
        for store in (MemoryRevocations(), self.sqlite()):
            acct = account_id(verified_issuer=ISS, verified_subject="s")
            self.assertIsNone(store.revoked_before(ISS, acct))
            store.revoke_before(ISS, acct, 200)
            store.revoke_before(ISS, acct, 100)
            self.assertEqual(store.revoked_before(ISS, acct), 200)
            with self.assertRaises(RevocationError):
                store.revoke_before(ISS, "acct_bad", 1)

    def sqlite(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder = Path(tmp.name) / "state"
        store = SQLiteRevocations(folder / "revocations.db")
        self.addCleanup(store.close)
        self.assertEqual(os.stat(folder / "revocations.db").st_mode & 0o777, 0o600)
        return store

    def test_sqlite_survives_restart_and_refuses_shared_files(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "private" / "r.db"
        acct = account_id(verified_issuer=ISS, verified_subject="s")
        first = SQLiteRevocations(path)
        first.revoke_before(ISS, acct, 5)
        first.close()
        again = SQLiteRevocations(path)
        self.assertEqual(again.revoked_before(ISS, acct), 5)
        again.close()
        os.chmod(path, 0o644)
        with self.assertRaises(RevocationError):
            SQLiteRevocations(path)
        with self.assertRaises(RevocationError):
            SQLiteRevocations(":memory:")


if __name__ == "__main__":
    unittest.main()
