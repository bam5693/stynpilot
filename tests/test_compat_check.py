"""Compatibility check on a fake home folder: strict verdicts, every check reported, no identifiers."""
import io
import json
import os
import sqlite3
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


def forgejo(state="running"):
    return lambda software: {"state": state, "version": "15.0.3" if state == "running" else None,
                             "service_enabled_at_boot": True, "listener_owned_by_service_account": True,
                             "listening_beyond_loopback": False}


class CompatCheckTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.base = self.home / compat_check.STATE_DIR
        os.makedirs(self.base.parent, mode=0o700)
        self.devices = [(DEVICE, OWNER, time.time() + 3600, None, ["workspace.propose"])]
        self.db = make_pairing_db(self.base, self.devices)
        self.settings(DEVICE)

    def settings(self, device):
        path = self.base / "controller-runtime.json"
        path.write_text(json.dumps({"issuer": "https://issuer.example.test/", "workspaces": [{"device_id": device}]}))
        os.chmod(path, 0o600)

    def check(self, status=None):
        out = io.StringIO()
        code = compat_check.main(out=out, home=self.home, status=status or forgejo())
        text = out.getvalue()
        results = compat_check.run(self.home, status=status or forgejo())
        return code, text, {title: ok for ok, title, _ in results}

    # --- a clean pass ---------------------------------------------------------------------
    def test_compatible_only_when_every_required_check_passed(self):
        before = self.db.read_bytes()
        code, text, checks = self.check()
        self.assertEqual(code, 0)
        self.assertTrue(all(checks[title] is True for title in compat_check.REQUIRED))
        self.assertIn("PAIRING: COMPATIBLE.", text)
        self.assertIn("FORGEJO: verified running.", text)
        self.assertIn("pairing database is confirmed unchanged", text)
        self.assertIn("health.read, workspace.propose", text)
        for secret in (DEVICE, OWNER, "TESTONLY", OWNER[5:14], "hash-0", "issuer.example.test"):
            self.assertNotIn(secret, text)
        self.assertEqual(self.db.read_bytes(), before)

    # --- regression 1: unreadable settings can never pass (PR #9 review) -------------------
    def test_missing_or_unreadable_settings_is_inconclusive_not_compatible(self):
        settings = self.base / "controller-runtime.json"
        for breakage in ("missing", "world-readable", "not json"):
            with self.subTest(breakage):
                self.settings(DEVICE)
                if breakage == "missing":
                    settings.unlink()
                elif breakage == "world-readable":
                    os.chmod(settings, 0o644)
                else:
                    settings.write_text("{oops")
                code, text, checks = self.check()
                self.assertIsNone(checks["Same device as the current build's settings"])
                self.assertIn("PAIRING: INCONCLUSIVE.", text)
                self.assertNotIn("PAIRING: COMPATIBLE", text)
                self.assertEqual(code, 3)

    def test_different_device_in_settings_is_not_compatible_and_prints_neither_id(self):
        self.settings("dtdev_TESTONLYotherDevice")
        code, text, checks = self.check()
        self.assertIs(checks["Same device as the current build's settings"], False)
        self.assertIn("PAIRING: NOT COMPATIBLE.", text)
        self.assertNotIn("otherDevice", text)
        self.assertEqual(code, 1)

    # --- regression 2: early failures still report every check (PR #9 review) --------------
    def test_early_failures_report_every_required_check_and_still_fingerprint(self):
        cases = {
            "unsafe permissions": lambda: os.chmod(self.db, 0o644),
            "no live device": lambda: self._set_devices([]),
            "two live devices": lambda: self._set_devices(self.devices + [
                ("dtdev_TESTONLYsecondDev", OWNER, time.time() + 3600, None, [])]),
        }
        for label, breakage in cases.items():
            with self.subTest(label):
                breakage()
                code, text, checks = self.check()
                for title in compat_check.REQUIRED + (compat_check.FORGEJO,):
                    self.assertIn(title, checks, title)
                self.assertIn("PAIRING: NOT COMPATIBLE.", text)
                self.assertIn("not checked", text)
                self.assertIn("FORGEJO: verified running.", text)   # Forgejo is still checked
                self.setUp()

    def _set_devices(self, devices):
        for suffix in ("", "-journal"):
            Path(str(self.db) + suffix).unlink(missing_ok=True)
        self.db = make_pairing_db(self.base, devices)

    # --- regression 3: a changed database is never reported as unchanged (PR #9 review) ----
    def test_changed_database_is_reported_truthfully(self):
        real = compat_check._pairing_checks

        def other_program_writes(db_path, base):
            yield from real(db_path, base)
            db = sqlite3.connect(db_path)
            db.execute("UPDATE devices SET device_name='renamed by the live service'")
            db.commit()
            db.close()
        with patch.object(compat_check, "_pairing_checks", other_program_writes):
            out = io.StringIO()
            code = compat_check.main(out=out, home=self.home, status=forgejo())
        text = out.getvalue()
        self.assertIn("CHANGED while this ran", text)
        self.assertIn("PAIRING: INCONCLUSIVE.", text)
        self.assertIn("could not be confirmed unchanged", text)
        self.assertNotIn("confirmed unchanged.", text.replace("could not be confirmed unchanged", ""))
        self.assertEqual(code, 3)

    def test_side_file_change_counts_as_a_change(self):
        wal = Path(str(self.db) + "-wal")
        before = compat_check._fingerprint(self.db)
        wal.write_bytes(b"wal frames")
        self.assertNotEqual(before, compat_check._fingerprint(self.db))

    # --- Forgejo is reported separately and never decides the pairing verdict --------------
    def test_forgejo_problem_is_its_own_line(self):
        code, text, checks = self.check(status=forgejo("unverified"))
        self.assertIs(checks[compat_check.FORGEJO], False)
        self.assertIn("PAIRING: COMPATIBLE.", text)
        self.assertIn("FORGEJO: not verified running", text)

    def test_refuses_root(self):
        with patch.object(compat_check.os, "geteuid", return_value=0):
            out = io.StringIO()
            self.assertEqual(compat_check.main(out=out, home=self.home), 2)
            self.assertIn("without sudo", out.getvalue())

    def test_docstring_states_up_to_three_requests(self):
        self.assertIn("up to three GET requests", compat_check.__doc__)


if __name__ == "__main__":
    unittest.main()
