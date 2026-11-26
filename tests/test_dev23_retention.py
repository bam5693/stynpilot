"""Dev23 stage 1: owner-approved retention settings (YELLOW) and periodic re-verification."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from stynpilot import vault  # noqa: E402

try:
    import test_runner_door as door
    import test_vault as tv
    import jwt  # noqa: F401
except Exception:                                    # pragma: no cover
    door = None


@unittest.skipIf(door is None, "needs PyJWT, cryptography")
class RetentionSettingTests(unittest.TestCase):
    def setUp(self):
        self.o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.vault = self.o.vault

    def test_bounds_hold_everywhere(self):
        for daily, weekly, ok in ((1, 0, True), (30, 12, True), (0, 4, False), (31, 4, False), (7, 13, False), (7, -1, False),
                                  (True, 4, False), (7.0, 4, False), ("7", 4, False)):
            self.assertEqual(vault.valid_retention(daily, weekly), ok, (daily, weekly))
        with self.assertRaises(vault.VaultError):
            self.vault.set_retention(0, 4, "a" * 64)
        with self.assertRaises(vault.VaultError):
            self.vault.set_retention(7, 4, "not a request id")

    def test_an_approved_setting_is_used_and_a_bad_settings_file_falls_back_to_the_default(self):
        self.assertEqual(self.vault.effective_retention()["daily"], 7)
        self.vault.set_retention(2, 1, "b" * 64)
        self.assertEqual({k: self.vault.effective_retention()[k] for k in ("daily", "weekly", "approved")},
                         {"daily": 2, "weekly": 1, "approved": "b" * 64})
        for _ in range(10):
            self.o.clock.t += tv.DAY
            self.assertTrue(self.vault.backup_now()["ok"])
        self.assertLessEqual(len(list((self.o.tmp / "vault").glob("*.stynvault"))), 3)
        settings = self.o.tmp / "vault" / vault.SETTINGS
        settings.write_text(json.dumps({"schema": 1, "daily": 0, "weekly": 0, "request_id": "c" * 64}))
        os.chmod(settings, 0o600)
        self.assertFalse(self.vault.effective_retention()["trusted"])            # out of range on disk -> NOT trusted
        os.chmod(settings, 0o644)
        self.assertFalse(self.vault.effective_retention()["trusted"])            # a loose file is not trusted either

    def test_the_owner_side_follows_the_installers_approved_setting(self):
        self.vault.retention_source = lambda: {"daily": 3, "weekly": 2, "approved": "d" * 64}
        self.vault.backup_now()
        self.assertEqual(self.vault.effective_retention()["daily"], 3)
        self.vault.retention_source = lambda: (_ for _ in ()).throw(OSError("installer down"))
        self.o.clock.t += tv.DAY
        self.assertTrue(self.vault.backup_now()["ok"])                           # unreachable installer: last setting stays
        self.assertEqual(self.vault.effective_retention()["daily"], 3)
        self.vault.retention_source = lambda: {"daily": 0, "weekly": 99, "approved": "e" * 64}
        self.vault.backup_now()
        self.assertEqual(self.vault.effective_retention()["daily"], 3)           # an out-of-range answer is ignored


@unittest.skipIf(door is None, "needs PyJWT, cryptography")
class PruneFailClosedTests(unittest.TestCase):
    """Review BLOCKER: a policy we cannot trust or confirm, or a stale check of the last good point, never leads to deletion."""

    def setUp(self):
        self.o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.vault = self.o.vault

    def count(self):
        return len(list((self.o.tmp / "vault").glob("*.stynvault")))

    def daily(self, n):
        for _ in range(n):
            self.o.clock.t += tv.DAY
            self.assertTrue(self.vault.backup_now()["ok"])

    def test_a_damaged_approved_settings_file_holds_all_pruning_but_backups_continue(self):
        self.vault.set_retention(1, 0, "a" * 64)
        self.daily(3)
        self.assertEqual(self.count(), 1)                                        # the approved 1 daily works
        (self.o.tmp / "vault" / vault.SETTINGS).write_text("{damaged")
        self.daily(12)
        self.assertEqual(self.count(), 13)                                       # nothing deleted, every day backed up
        problems = self.vault.status()["problems"]
        self.assertIn("retention_settings_untrusted", problems)
        self.assertIn("pruning_on_hold:retention_settings_untrusted", problems)

    def test_owner_side_pruning_is_disabled_and_reported_while_backups_continue(self):
        from stynpilot import service
        owner = service.owner_vault(self.o.config, settings_path=self.o.settings, isolate=False, clock=self.o.clock,
                                    space=self.o.space, retention_source=lambda: {"daily": 1, "weekly": 0, "approved": "b" * 64,
                                                                                    "trusted": True})
        owner.extras = self.vault.extras
        for _ in range(12):
            self.o.clock.t += tv.DAY
            self.assertTrue(owner.backup_now()["ok"])
        self.assertEqual(len(list((self.o.config.state_dir / "vault").glob("*.stynvault"))), 12)      # nothing deleted
        status = owner.status()
        self.assertIn("pruning_on_hold:owner_side_pruning_disabled_until_safe_coordination", status["problems"])
        self.assertEqual(status["retention"]["daily"], 1)                        # the installer's policy is still shown
        self.assertTrue(status["newest_complete_verified"])

    def test_a_crash_between_the_two_policy_writes_holds_pruning(self):
        self.vault.set_retention(5, 2, "a" * 64)
        self.assertTrue(self.vault.effective_retention()["trusted"])
        log = self.o.tmp / "vault" / vault.POLICY_LOG
        with open(log, "a") as handle:                                          # a newer approval was logged, then power was lost
            handle.write("%s 1 0\n" % ("f" * 64))                              # before settings.json changed
        self.assertFalse(self.vault.effective_retention()["trusted"])            # settings no longer match the latest approval
        self.vault.retention = {"daily": 1, "weekly": 0}
        self.daily(6)
        self.assertEqual(self.count(), 6)
        self.assertIn("pruning_on_hold:retention_settings_untrusted", self.vault.status()["problems"])
        with open(log, "a") as handle:
            handle.write("garbage line\n")                                     # a damaged last entry is uncertain evidence
        self.assertFalse(self.vault.effective_retention()["trusted"])
        self.vault.set_retention(3, 0, "1" * 64)                                # a proper new approval restores trust
        self.assertTrue(self.vault.effective_retention()["trusted"])
        self.daily(1)
        self.assertEqual(self.count(), 3)

    def test_a_settings_file_matching_an_older_approval_is_not_trusted(self):
        self.vault.set_retention(10, 4, "a" * 64)
        old = (self.o.tmp / "vault" / vault.SETTINGS).read_bytes()
        self.vault.set_retention(2, 0, "b" * 64)
        (self.o.tmp / "vault" / vault.SETTINGS).write_bytes(old)                 # an older, different setting put back
        os.chmod(self.o.tmp / "vault" / vault.SETTINGS, 0o600)
        self.assertFalse(self.vault.effective_retention()["trusted"])

    def test_a_missing_settings_file_after_an_approval_holds_pruning(self):
        self.vault.set_retention(2, 0, "e" * 64)
        self.daily(3)
        self.assertEqual(self.count(), 2)
        os.unlink(self.o.tmp / "vault" / vault.SETTINGS)                         # the approved policy is LOST
        self.assertFalse(self.vault.effective_retention()["trusted"])
        self.daily(6)
        self.assertEqual(self.count(), 8)                                        # nothing deleted under the default 7+4
        self.assertIn("retention_settings_untrusted", self.vault.status()["problems"])
        fresh = vault.Vault(side="owner", state_dir=self.o.config.state_dir, folder=self.o.tmp / "fresh")
        self.assertTrue(fresh.effective_retention()["trusted"])                  # first-time default (no approval ever) is fine

    def test_a_stale_verification_flag_is_rechecked_before_anything_is_pruned(self):
        from stynpilot import service
        self.vault.extras = [("owner.json", self.o.settings, "json", True, service.OWNER_KEYS)]
        good = self.vault.backup_now()["backup"]
        self.o.settings.write_text(json.dumps({"mcp_port": 8000, "github_token": "x"}))  # later backups are incomplete
        self.vault.retention = {"daily": 1, "weekly": 0}
        self.daily(2)
        path = self.o.tmp / "vault" / good
        data = bytearray(path.read_bytes())
        data[-3] ^= 1
        path.write_bytes(bytes(data))                                           # the last good point went bad since its check
        self.daily(3)
        names = {p.name for p in (self.o.tmp / "vault").glob("*.stynvault")}
        self.assertIn(good, names)                                              # kept (check_failed), never pruned
        self.assertTrue(any(p.startswith("backups_failed_a_recheck") for p in self.vault.status()["problems"]))

    def test_monthly_full_checks_happen_under_normal_retention_over_60_days(self):
        starts = []
        real = self.vault.recheck_all
        self.vault.recheck_all = lambda: starts.append(self.o.clock.t) or real()
        for _ in range(65):
            self.o.clock.t += tv.DAY
            self.vault.tick()
        self.assertGreaterEqual(len(starts), 2)                                  # due from the first backup, not the oldest kept one
        self.assertLessEqual(self.count(), 2 + 7 + 4)


@unittest.skipIf(door is None, "needs PyJWT, cryptography")
class ApprovalTests(unittest.TestCase):
    """The retention change is YELLOW: it only happens with the owner's single-use proof for exactly that request."""

    @classmethod
    def setUpClass(cls):
        door.Door.setUpClass()

    def setUp(self):
        d = door.Door("test_the_owner_reads_exactly_what_each_request_does")
        d.setUp()
        self.addCleanup(d.doCleanups)
        self.tmp, self.executor, self.proof, self.denied = d.tmp, d.executor, d.proof, d.denied
        self.v = vault.Vault(side="root", state_dir=self.tmp / "state", folder=self.tmp / "rootvault")
        self.executor.vault = self.v

    def bpayload(self, daily=10, weekly=6, minutes=60, **kw):
        p = {"kind": "backup", "action": "retention", "daily": daily, "weekly": weekly, "owner": door.OWNER, "device": door.DEVICE,
             "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        p.update(kw)
        return p

    def test_the_owner_reads_what_changes_and_one_proof_changes_it_once(self):
        payload = self.bpayload()
        out = self.executor.challenge(payload, "approve")
        text = "\n".join(out["summary"])
        for want in ("10 daily and 6 weekly", "newest complete, verified backup is always kept", "Nothing is backed up, restored"):
            self.assertIn(want, text)
        result = self.executor.backup_admin(payload, self.proof(payload, out["challenge"]), out["challenge"])
        self.assertEqual((result["ok"], result["daily"], result["weekly"]), (True, 10, 6))
        self.assertEqual(self.v.effective_retention()["approved"], door.request_id(payload)[0])
        self.denied("already_decided_or_used", self.executor.challenge, payload, "approve")      # never replayable

    def test_out_of_range_forged_or_expired_requests_change_nothing(self):
        for bad in (self.bpayload(daily=0), self.bpayload(weekly=13), self.bpayload(daily="7"), self.bpayload(action="restore"),
                    self.bpayload(owner="someone-else"), dict(self.bpayload(), extra=1)):
            self.denied("backup_request_invalid", self.executor.challenge, bad, "approve")
        self.denied("plan_invalid_or_expired", self.executor.challenge, self.bpayload(minutes=-1), "approve")
        payload = self.bpayload()
        challenge = self.executor.challenge(payload, "approve")["challenge"]
        other = self.bpayload(daily=11)
        with self.assertRaises(door.ExecutionDenied):
            self.executor.backup_admin(payload, self.proof(other, challenge), challenge)        # a proof for another request
        self.assertIsNone(self.v.effective_retention()["approved"])

    def test_without_a_vault_the_request_is_refused(self):
        self.executor.vault = None
        self.denied("backups_not_available", self.executor.challenge, self.bpayload(), "approve")


@unittest.skipIf(door is None, "needs PyJWT, cryptography")
class PeriodicVerificationTests(unittest.TestCase):
    def setUp(self):
        self.o = tv.OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.vault = self.o.vault
        self.vault.extras = [("owner.json", self.o.settings, "json", True, None)]

    def corrupt(self, name):
        path = self.o.tmp / "vault" / name
        data = bytearray(path.read_bytes())
        data[-4] ^= 1
        path.write_bytes(bytes(data))

    def test_the_newest_complete_backup_is_rechecked_daily_even_behind_newer_incomplete_ones(self):
        complete = self.vault.backup_now()["backup"]
        self.o.settings.write_text("-----BEGIN PRIVATE KEY-----")               # later backups are incomplete
        for _ in range(2):
            self.o.clock.t += tv.DAY
            self.assertFalse(self.vault.backup_now()["complete"])
        self.corrupt(complete)
        self.o.clock.t += tv.DAY + 1
        done = self.vault.tick()
        self.assertIn(complete, done["recheck"]["failed"])
        self.assertTrue((self.o.tmp / "vault" / complete).exists())               # a failed check never deletes it
        problems = self.vault.status()["problems"]
        self.assertIn("no_complete_verified_backup", problems)
        self.assertIn("backups_failed_a_recheck:1", problems)
        self.vault.retention = {"daily": 1, "weekly": 0}
        self.o.settings.write_text(json.dumps({"mcp_port": 1}))
        os.chmod(self.o.settings, 0o600)
        self.o.clock.t += tv.DAY
        self.assertTrue(self.vault.backup_now()["complete"])
        self.assertTrue((self.o.tmp / "vault" / complete).exists())               # still kept for inspection after retention

    def test_every_retained_backup_is_rechecked_monthly(self):
        first = self.vault.backup_now()["backup"]
        for _ in range(3):
            self.o.clock.t += tv.DAY
            self.vault.backup_now()
        self.corrupt(first)                                                      # an OLD retained backup goes bad
        self.o.clock.t += 31 * tv.DAY
        done = self.vault.tick()
        self.assertIn("recheck_all", done)
        self.assertIn(first, done["recheck_all"]["failed"])
        self.assertTrue(self.vault.status()["last_full_check"])
        self.assertIn("backups_failed_a_recheck:1", self.vault.status()["problems"])
        self.assertTrue((self.o.tmp / "vault" / first).exists())


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(door is None, "needs PyJWT, cryptography")
class RequestToolTests(unittest.TestCase):
    def setUp(self):
        t = tv.BackupToolTests("test_backup_tools_work_and_writes_need_the_write_gate")
        t.setUp()
        self.h = t.h
        self.h.broker.vault_settings = lambda: {"daily": 7, "weekly": 4, "approved": None}

    def test_the_request_is_filed_for_the_owner_and_bad_values_are_refused(self):
        out = self.h.call("commander_request_backup_retention", self.h.d(daily=14, weekly=8))
        self.assertTrue(out["ok"], out)
        result = out["result"]
        self.assertEqual((result["kind"], result["state"], result["approved_by_ai"]), ("backup", "pending", False))
        self.assertIn("14 daily and 8 weekly", "\n".join(result["summary"]))
        self.assertEqual(self.h.call("commander_request_backup_retention", self.h.d(daily=31, weekly=4))["error"],
                         "retention_out_of_range_daily_1_to_30_weekly_0_to_12")
        self.assertEqual(self.h.call("commander_request_backup_retention", self.h.d(daily=7, weekly=4))["error"], "retention_already_set")
        self.assertFalse(self.h.call("commander_request_backup_retention", self.h.d(daily=14, weekly=8), "readonly").get("ok"))
