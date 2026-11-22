"""The compatibility check on a fake home folder: right answers, no identifiers printed, no writes."""
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from legacy_pairing import make_pairing_db
from stynpilot import compat_check
from stynpilot.identity import account_id

OWNER = account_id(verified_issuer="https://issuer.example.test/", verified_subject="auth0|test-owner")
DEVICE = "dtdev_TESTONLYliveDevice"
HEALTH = (200, json.dumps({"status": "pass", "checks": {"cache:ping": []}}).encode())


def forgejo_down(host, port, path):
    return None


class CompatCheckTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.base = self.home / compat_check.STATE_DIR
        os.makedirs(self.base.parent, mode=0o700)
        self.db = make_pairing_db(self.base, [(DEVICE, OWNER, time.time() + 3600, None, ["workspace.propose"])])
        self.settings(DEVICE)

    def settings(self, device):
        path = self.base / "controller-runtime.json"
        path.write_text(json.dumps({"issuer": "https://issuer.example.test/", "workspaces": [{"device_id": device}]}))
        os.chmod(path, 0o600)

    def output(self, get=forgejo_down):
        out = io.StringIO()
        with patch.object(compat_check, "service_status",
                          lambda s, get=None: compat_check.__dict__["_real_status"](s, get=get or forgejo_down, root=str(self.home))):
            code = None
            results = compat_check.run(self.home, get=get)
        for ok, title, detail in results:
            out.write("%s %s %s\n" % (ok, title, detail))
        return results, out.getvalue()

    @classmethod
    def setUpClass(cls):
        compat_check._real_status = compat_check.service_status

    def test_compatible_pairing_and_nothing_identifying_is_printed(self):
        before = self.db.read_bytes()
        results, text = self.output()
        titles = {title: ok for ok, title, _ in results}
        self.assertTrue(titles["Pairing database opens read-only"])
        self.assertTrue(titles["Exactly one live paired device"])
        self.assertTrue(titles["Owner ID format matches the new sign-in code"])
        self.assertTrue(titles["Same device as the current build's settings"])
        self.assertTrue(titles["Device grant"])
        self.assertTrue(titles["Pairing database unchanged afterwards"])
        self.assertIn("health.read, workspace.propose", text)
        for secret in (DEVICE, OWNER, "TESTONLY", "acct_" + OWNER[5:12], "hash-0", "issuer.example.test"):
            self.assertNotIn(secret, text)
        self.assertEqual(self.db.read_bytes(), before)

    def test_mismatched_settings_device_is_reported_without_printing_either_id(self):
        self.settings("dtdev_TESTONLYotherDevice")
        results, text = self.output()
        self.assertIn((False, "Same device as the current build's settings", "NO, they differ"), results)
        self.assertNotIn("otherDevice", text)

    def test_unsafe_database_stops_early(self):
        os.chmod(self.db, 0o644)
        results, _ = self.output()
        self.assertEqual(results[0][:2], (False, "Pairing database opens read-only"))
        self.assertEqual(len(results), 1)

    def test_forgejo_not_installed_is_reported_not_crashed(self):
        results, _ = self.output()
        forgejo = next(r for r in results if r[1] == "Forgejo status (new checker)")
        self.assertFalse(forgejo[0])
        self.assertIn("state=not_installed", forgejo[2])

    def test_refuses_root(self):
        with patch.object(compat_check.os, "geteuid", return_value=0):
            out = io.StringIO()
            self.assertEqual(compat_check.main(out=out), 2)
            self.assertIn("without sudo", out.getvalue())


if __name__ == "__main__":
    unittest.main()
