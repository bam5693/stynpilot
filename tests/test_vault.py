"""Dev22: encrypted automatic backups (stynpilot/vault.py)."""
import asyncio
import json
import os
import sqlite3
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from stynpilot import service, vault  # noqa: E402
from stynpilot.vault import Vault, VaultError  # noqa: E402

try:
    import cryptography  # noqa: F401
    from test_g7 import owner_data, tmpdir  # noqa: E402
except Exception:                                   # pragma: no cover
    cryptography = None

DAY = 86400


class Clock:
    def __init__(self, t=1_770_000_000):
        self.t = t

    def __call__(self):
        return self.t


class Space:
    def __init__(self, free=10 ** 12):
        self.free = free

    def __call__(self, path):
        return type("U", (), {"free": self.free})()


@unittest.skipIf(cryptography is None, "needs cryptography")
class OwnerVaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp))
        service.provision_owner_state(self.config)
        from stynpilot.server.clients import RevocationFile
        RevocationFile(self.config.state_dir / "revoked-clients.json").set_revoked("claude-connector", True)
        self.settings = self.tmp / "owner.json"
        self.settings.write_text(json.dumps({"mcp_port": 8000, "approval_client_id": "app"}))
        os.chmod(self.settings, 0o600)
        self.pairing = self.tmp / "pairing.sqlite3"
        db = sqlite3.connect(self.pairing)
        db.execute("CREATE TABLE devices(id TEXT)")
        db.execute("INSERT INTO devices VALUES ('dtdev_x')")
        db.commit()
        db.close()
        self.clock, self.space = Clock(), Space()
        self.vault = self.make()

    def make(self, **kw):
        extras = [("owner.json", self.settings, "json"), ("pairing.sqlite3", self.pairing, "sqlite"),
                  ("read-roots.json", self.config.state_dir / "read-roots.json", "json")]
        return Vault(side="owner", state_dir=self.config.state_dir, folder=self.tmp / "vault", extras=extras, version="0.1.0.dev22",
                     clock=self.clock, space=self.space, **kw)

    def names(self):
        return sorted(p.name for p in (self.tmp / "vault").glob("*.stynvault"))

    # -- creation, encryption, verification -------------------------------------------------------------------------------------
    def test_the_first_tick_creates_and_verifies_a_backup_at_once(self):
        done = self.vault.tick()
        self.assertTrue(done["backup"]["ok"], done)
        self.assertTrue(done["drill"]["ok"], done)                           # and the first drill runs straight away too
        status = self.vault.status()
        self.assertTrue(status["healthy"], status)
        self.assertEqual(status["count"], 1)
        for path in (self.tmp / "vault").iterdir():
            if path.name in (".work",):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            elif path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)
        self.assertEqual((self.tmp / "vault").stat().st_mode & 0o777, 0o700)
        blob = (self.tmp / "vault" / self.names()[0]).read_bytes()
        for plain in (b"claude-connector", b"dtdev_x", b"mcp_port", b"requests.sqlite3"):
            self.assertNotIn(plain, blob)                                   # encrypted: nothing readable in the file
        header, meta, blobs = self.vault.open_backup(self.names()[0])
        self.assertEqual(set(blobs), {"state.tar", "extra/owner.json", "extra/pairing.sqlite3"})
        self.assertEqual(json.loads(blobs["extra/owner.json"]), {"mcp_port": 8000, "approval_client_id": "app"})

    def test_nothing_is_due_again_within_a_day_and_a_missed_day_is_caught_up(self):
        self.vault.tick()
        self.clock.t += 3600
        self.assertEqual(self.vault.tick(), {})
        self.clock.t += 3 * DAY                                             # the machine was off for three days
        self.assertTrue(self.vault.tick()["backup"]["ok"])
        self.assertEqual(len(self.names()), 2)

    def test_secret_looking_settings_are_left_out_and_reported(self):
        self.settings.write_text(json.dumps({"mcp_port": 1, "github_token": "x"}))
        result = self.vault.backup_now()
        self.assertTrue(result["ok"])
        self.assertIn("owner.json:looks_like_a_secret", result["excluded"])
        _, _, blobs = self.vault.open_backup(result["backup"])
        self.assertNotIn("extra/owner.json", blobs)
        self.settings.write_text("-----BEGIN PRIVATE KEY-----\n")
        self.clock.t += DAY
        self.assertIn("owner.json:looks_like_a_secret", self.vault.backup_now()["excluded"])

    def test_nonces_are_unique_and_recorded_before_the_backup_exists(self):
        seen = set()
        for _ in range(5):
            self.clock.t += DAY
            name = self.vault.backup_now()["backup"]
            header, _, _ = self.vault.open_backup(name)
            self.assertNotIn(header["nonce"], seen)
            seen.add(header["nonce"])
        logged = set((self.tmp / "vault" / vault.NONCE_LOG).read_text().split())
        self.assertTrue(seen <= logged)
        real = vault.secrets.token_bytes
        calls = []
        vault.secrets.token_bytes = lambda n: calls.append(n) or (bytes.fromhex(sorted(seen)[0]) if n == 12 else real(n))
        try:
            self.clock.t += DAY
            self.assertEqual(self.vault.backup_now(), {"ok": False, "error": "nonce_generation_failed"})
        finally:
            vault.secrets.token_bytes = real

    # -- tampering, keys ----------------------------------------------------------------------------------------------------------
    def test_any_changed_byte_header_or_body_is_detected(self):
        name = self.vault.backup_now()["backup"]
        path = self.tmp / "vault" / name
        good = path.read_bytes()
        for at in (12, 40, len(good) // 2, len(good) - 1):
            bad = bytearray(good)
            bad[at] ^= 1
            path.write_bytes(bytes(bad))
            with self.assertRaises(VaultError):
                self.vault.open_backup(name)
        path.write_bytes(good[:-10])
        with self.assertRaises(VaultError):
            self.vault.open_backup(name)
        path.write_bytes(good)
        self.vault.open_backup(name)

    def test_a_wrong_or_missing_key_is_reported_and_never_silently_replaced(self):
        name = self.vault.backup_now()["backup"]
        key = (self.tmp / "vault/backup-key").read_bytes()
        os.unlink(self.tmp / "vault/backup-key")
        self.clock.t += 2 * DAY
        self.assertEqual(self.vault.backup_now(), {"ok": False, "error": "backup_key_missing"})
        self.assertFalse((self.tmp / "vault/backup-key").exists())          # NOT regenerated
        self.assertIn("backup_key_missing", self.vault.status()["problems"])
        other = vault.KEY_MAGIC + b"\x01" * 8 + b"\x02" * 32
        (self.tmp / "vault/backup-key").write_bytes(other)
        os.chmod(self.tmp / "vault/backup-key", 0o600)
        with self.assertRaises(VaultError) as e:
            self.vault.open_backup(name)
        self.assertEqual(e.exception.code, "backup_key_does_not_match_the_vault")
        (self.tmp / "vault/backup-key").write_bytes(key)
        self.vault.open_backup(name)

    def test_a_loose_key_or_index_file_is_refused(self):
        self.vault.backup_now()
        os.chmod(self.tmp / "vault/backup-key", 0o644)
        self.clock.t += DAY
        self.assertEqual(self.vault.backup_now()["error"], "file_not_private_or_not_ours")

    # -- retention ----------------------------------------------------------------------------------------------------------------
    def test_retention_keeps_7_daily_4_weekly_and_always_the_newest_verified(self):
        for _ in range(40):
            self.clock.t += DAY
            self.assertTrue(self.vault.backup_now()["ok"])
        kept = self.names()
        self.assertLessEqual(len(kept), 7 + 4)
        self.assertGreaterEqual(len(kept), 7)
        newest = max(json.loads((self.tmp / "vault/index.json").read_text())["backups"].items(), key=lambda kv: kv[1]["created"])[0]
        self.assertIn(newest, kept)

    def test_a_failed_backup_never_costs_the_last_verified_one_even_when_space_is_low(self):
        good = self.vault.backup_now()["backup"]
        self.space.free = 1000                                              # the disk is nearly full
        for _ in range(3):
            self.clock.t += DAY
            self.assertEqual(self.vault.backup_now()["error"], "insufficient_storage")
        self.assertEqual(self.names(), [good])
        status = self.vault.status()
        self.assertIn("insufficient_storage", status["problems"])
        self.assertIn("backup_overdue", status["problems"])
        self.space.free = 10 ** 12
        self.vault.retention = {"daily": 0, "weekly": 0}
        self.clock.t += DAY
        self.assertTrue(self.vault.backup_now()["ok"])
        self.assertEqual(len(self.names()), 1)                               # even with retention 0, the newest verified stays

    def test_files_the_vault_did_not_create_are_never_touched(self):
        self.vault.backup_now()
        legacy = self.tmp / "vault" / "stynpilot-backup-20260101-000000.tar"
        legacy.write_bytes(b"legacy")
        other_side = self.tmp / "vault" / "root-20260101-000000-abcdef01.stynvault"
        other_side.write_bytes(b"x")
        self.vault.retention = {"daily": 0, "weekly": 0}
        for _ in range(3):
            self.clock.t += DAY
            self.vault.backup_now()
        self.assertTrue(legacy.exists() and other_side.exists())

    # -- drills --------------------------------------------------------------------------------------------------------------------
    def test_a_drill_restores_into_a_private_scratch_folder_and_live_state_is_untouched(self):
        self.vault.backup_now()
        before = {p.name: p.read_bytes() for p in self.config.state_dir.iterdir() if p.is_file()}
        result = self.vault.drill()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["files"], 4)
        self.assertEqual({p.name: p.read_bytes() for p in self.config.state_dir.iterdir() if p.is_file()}, before)
        self.assertEqual(list((self.tmp / "vault/.work").iterdir()), [])     # nothing left behind

    def test_a_drill_opens_no_connection_of_any_kind(self):
        import socket
        self.vault.backup_now()
        real = socket.socket
        socket.socket = lambda *a, **k: self.fail("a drill tried to open a socket")
        try:
            self.assertTrue(self.vault.drill()["ok"])
        finally:
            socket.socket = real

    def test_a_drill_of_a_corrupted_backup_fails_and_is_reported(self):
        name = self.vault.backup_now()["backup"]
        path = self.tmp / "vault" / name
        data = bytearray(path.read_bytes())
        data[-5] ^= 0xFF
        path.write_bytes(bytes(data))
        result = self.vault.drill()
        self.assertFalse(result["ok"])
        self.assertIn("authentication", result["error"])
        self.assertTrue(any(p.startswith("last_recovery_drill_failed") for p in self.vault.status()["problems"]))

    def test_manual_requests_are_rate_limited(self):
        self.assertTrue(self.vault.backup_now(manual=True)["ok"])
        again = self.vault.backup_now(manual=True)
        self.assertEqual(again["error"], "rate_limited")
        self.assertTrue(self.vault.drill(manual=True)["ok"])
        self.assertEqual(self.vault.drill(manual=True)["error"], "rate_limited")
        self.clock.t += 3601
        self.assertTrue(self.vault.drill(manual=True)["ok"])

    # -- concurrency, interruption, paths -----------------------------------------------------------------------------------------
    def test_two_operations_never_run_at_once(self):
        import fcntl
        folder = self.tmp / "vault"
        folder.mkdir(mode=0o700)
        lock = os.open(folder / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)                                     # another process holds the vault
        try:
            self.assertEqual(self.vault.backup_now()["error"], "another_backup_operation_is_running")
        finally:
            os.close(lock)
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.vault.backup_now())) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(r["ok"] or r["error"] == "another_backup_operation_is_running" for r in results), results)

    def test_an_interrupted_write_leaves_no_partial_backup_and_the_next_run_works(self):
        real = vault.os.replace
        vault.os.replace = lambda *a: (_ for _ in ()).throw(OSError("power cut"))
        try:
            self.assertFalse(self.vault.backup_now()["ok"])
        finally:
            vault.os.replace = real
        self.assertEqual(self.names(), [])
        self.clock.t += 3601
        self.assertTrue(self.vault.tick()["backup"]["ok"])
        self.assertEqual(len(self.names()), 1)

    def test_a_linked_vault_folder_or_backup_is_refused(self):
        real = self.tmp / "elsewhere"
        real.mkdir(mode=0o700)
        os.symlink(real, self.tmp / "vault")
        self.assertEqual(self.vault.backup_now()["error"], "vault_folder_not_private_or_not_ours")
        os.unlink(self.tmp / "vault")
        name = self.vault.backup_now()["backup"]
        target = self.tmp / "copy"
        os.rename(self.tmp / "vault" / name, target)
        os.symlink(target, self.tmp / "vault" / name)
        with self.assertRaises(OSError):
            self.vault.open_backup(name)
        with self.assertRaises(VaultError):
            self.vault.open_backup("../../etc/passwd")

    def test_a_loose_vault_folder_is_refused(self):
        self.vault.backup_now()
        os.chmod(self.tmp / "vault", 0o755)
        self.clock.t += DAY
        self.assertEqual(self.vault.backup_now()["error"], "vault_folder_not_private_or_not_ours")

    def test_status_shows_metadata_only(self):
        self.vault.tick()
        text = json.dumps(self.vault.status())
        for leak in ("claude-connector", "dtdev_x", "STYNKEY1", str(self.config.state_dir)):
            self.assertNotIn(leak, text)
        key = (self.tmp / "vault/backup-key").read_bytes()
        self.assertNotIn(key[16:].hex(), text)


class BundleTests(unittest.TestCase):
    def test_bundles_round_trip_and_refuse_damage(self):
        blob = vault.pack_bundle({"side": "owner"}, {"a": b"1", "b": b"22"})
        meta, blobs = vault.unpack_bundle(blob)
        self.assertEqual(blobs, {"a": b"1", "b": b"22"})
        for bad in (blob[:-1], blob + b"x", blob.replace(b"22", b"23"), b"junk"):
            with self.assertRaises(VaultError):
                vault.unpack_bundle(bad)


if __name__ == "__main__":
    unittest.main()


@unittest.skipIf(cryptography is None, "needs cryptography")
class RootVaultTests(unittest.TestCase):
    """The installer's side: ledgers, snapshots, passkeys (quarantined on every restore), settings, release records; NEVER the
    release signing key or the GitHub token."""

    def setUp(self):
        import hashlib
        from stynpilot import release
        from stynpilot.broker.executor import Runs
        from stynpilot.broker.passkeys import PasskeyStore
        from stynpilot.ledger import InstallLedger
        self.tmp = tmpdir(self)
        self.state = self.tmp / "inst"
        self.state.mkdir(mode=0o700)
        Runs(self.state / "runs.sqlite3")
        InstallLedger(self.state / "installs.sqlite3")
        for tree in ("snapshots", "attention"):
            (self.state / tree).mkdir()
        store = PasskeyStore(self.state / "passkeys.sqlite3", rp_id="example.test", origin="https://example.test")
        db = sqlite3.connect(self.state / "passkeys.sqlite3")
        db.execute("INSERT INTO passkeys (credential_id, kid, public_key, label, backup_eligible, backup_state, aaguid, sign_count, "
                   "created, enrolled_by, pubhash, activated, quarantined) VALUES ('c', 'k1', 'pk', 'phone', 0, 0, 'a', 0, 1, 'x', 'h', 1, 0)")
        db.commit()
        db.close()
        del store
        self.etc = self.tmp / "etc"
        self.etc.mkdir()
        (self.etc / "installer.json").write_text(json.dumps({"issuer": "https://t.example/", "approval_client_id": "app", "owner": "o",
                                                             "device": "d", "owner_uid": 1000, "state_dir": "/x", "socket_path": "/run/x"}))
        (self.etc / "release.json").write_text(json.dumps({"build_user": "stynpilot-build"}))
        (self.state / "release-tx").mkdir()
        (self.state / "release-tx" / ("a" * 64 + ".json")).write_text(json.dumps({"state": "started"}))
        self.release = self.tmp / "var-lib-stynpilot"
        (self.release / "release").mkdir(parents=True)
        self.secret_key = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIQ==\n"
        (self.release / "release" / "release-ed25519.pem").write_bytes(self.secret_key)
        (self.release / "release" / "github-token").write_bytes(b"github_pat_SECRETVALUE")
        (self.release / "trusted-release-keys.json").write_text(json.dumps({"keys": [{"id": "fa3e", "public": "AAAA"}]}))
        real = release.ADDENDUM_FILE
        release.ADDENDUM_FILE = self.release / "trusted-release-keys.json"
        self.addCleanup(setattr, release, "ADDENDUM_FILE", real)
        self.config = type("C", (), {"state_dir": self.state})()
        self.clock = Clock()
        self.vault = service.root_vault(self.etc / "installer.json", self.config, clock=self.clock, space=Space())

    def test_root_backup_includes_records_and_settings_but_never_release_secrets(self):
        result = self.vault.backup_now()
        self.assertTrue(result["ok"], result)
        _, meta, blobs = self.vault.open_backup(result["backup"])
        self.assertEqual(set(blobs), {"state.tar", "extra/installer.json", "extra/release.json", "extra/trusted-release-keys.json",
                                      "extra/release-tx/" + "a" * 64 + ".json"})
        everything = b"".join(blobs.values())
        self.assertNotIn(b"BEGIN PRIVATE KEY", everything)
        self.assertNotIn(b"github_pat_", everything)
        names = [e[0] for e in service.root_vault_extras(self.etc / "installer.json", self.state)]
        self.assertFalse([n for n in names if "release-ed25519" in n or "token" in n])

    def test_a_root_drill_restores_with_every_passkey_quarantined(self):
        self.assertTrue(self.vault.backup_now()["ok"])
        result = self.vault.drill()
        self.assertTrue(result["ok"], result)
        db = sqlite3.connect(self.state / "passkeys.sqlite3")             # the LIVE passkey is untouched by the drill
        self.assertEqual(db.execute("SELECT quarantined FROM passkeys").fetchone()[0], 0)
        db.close()

    def test_a_backup_is_refused_while_an_install_is_running(self):
        from stynpilot import statelock
        with statelock.operation(self.state, "busy"):
            result = self.vault.backup_now()
        self.assertFalse(result["ok"])
        self.assertTrue(self.vault.backup_now()["ok"])                      # and works once it has finished

    def test_owner_and_root_vaults_cannot_read_each_other(self):
        self.vault.backup_now()
        name = next(p.name for p in (self.state / "vault").glob("*.stynvault"))
        owner_side = Vault(side="owner", state_dir=self.state, folder=self.state / "vault", clock=self.clock)
        with self.assertRaises(VaultError):
            owner_side.open_backup(name)


@unittest.skipIf(cryptography is None, "needs cryptography")
class ReviewFindingTests(unittest.TestCase):
    """Dev22 review: limits before gathering, a separate memory-limited process, schema-aware settings, full drills, re-checks,
    damaged-index handling, never touching files the vault does not own."""

    def setUp(self):
        self.o = OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        self.tmp, self.vault = self.o.tmp, self.o.vault
        self.vault.extras = [("owner.json", self.o.settings, "json", True, service.OWNER_KEYS),
                             ("pairing.sqlite3", self.o.pairing, "sqlite", True, None)]
        self.o.settings.write_text(json.dumps({"token_endpoint": "https://t.example/oauth/token", "mcp_port": 8000}))

    def test_limits_are_checked_from_sizes_before_anything_is_read(self):
        from stynpilot import backup
        real = backup.make_backup
        backup.make_backup = lambda *a, **k: self.fail("state was read before the size check")
        self.addCleanup(setattr, backup, "make_backup", real)
        self.vault.limits["gather"] = 100
        self.assertEqual(self.vault.backup_now()["error"], "backup_too_large_for_the_limits")
        self.vault.limits["gather"] = vault.MAX_GATHER
        self.vault.limits["file"] = 10
        self.assertEqual(self.vault.backup_now()["error"], "backup_too_large_for_the_limits")

    def test_the_heavy_work_runs_in_a_separate_memory_limited_process(self):
        isolated = Vault(side="owner", state_dir=self.o.config.state_dir, folder=self.tmp / "vault", extras=self.vault.extras,
                         isolate=True)
        made = isolated.backup_now()
        self.assertTrue(made["ok"], made)
        self.assertTrue(isolated.drill()["ok"])
        starved = Vault(side="owner", state_dir=self.o.config.state_dir, folder=self.tmp / "vault", extras=self.vault.extras,
                        isolate=True, limits={"memory": 40 * 1024 * 1024})
        result = starved.backup_now(manual=True)
        self.assertFalse(result["ok"])                                       # the CHILD ran out of memory; this process is fine
        self.assertNotIn("backup", result)                                   # nothing half-made is reported as a backup
        import subprocess
        real = subprocess.run
        subprocess.run = lambda *a, **k: subprocess.CompletedProcess(a, -9, b"", b"")   # the child is killed (out of memory)
        try:
            self.assertEqual(isolated.backup_now(), {"ok": False, "error": "backup_process_failed_exit_-9"})
        finally:
            subprocess.run = real
        self.assertIn("last_backup_failed:backup_process_failed_exit_-9", isolated.status()["problems"])
        self.assertTrue(isolated.status()["problems"])                       # and the failure is visible

    def test_a_legitimate_token_endpoint_is_backed_up_and_unexpected_fields_are_refused(self):
        made = self.vault.backup_now()
        self.assertTrue(made["ok"] and made["complete"], made)
        _, _, blobs = self.vault.open_backup(made["backup"])
        self.assertIn("extra/owner.json", blobs)
        self.o.settings.write_text(json.dumps({"mcp_port": 8000, "github_token": "x"}))
        self.o.clock.t += DAY
        made = self.vault.backup_now()
        self.assertEqual((made["ok"], made["complete"]), (True, False))      # written, but clearly NOT complete
        self.assertIn("owner.json:unexpected_fields", made["excluded"])
        self.assertIn("incomplete_backup:owner.json", self.vault.status()["problems"])
        os.unlink(self.o.pairing)
        self.o.clock.t += DAY
        made = self.vault.backup_now()
        self.assertIn("pairing.sqlite3:missing", made["excluded"])            # a REQUIRED file that is missing is reported

    def test_a_drill_recovers_the_extras_and_compares_every_restored_file(self):
        self.vault.backup_now()
        result = self.vault.drill()
        self.assertEqual((result["ok"], result["extras"]), (True, 2), result)
        from stynpilot import backup
        real = backup.restore_backup

        def tampered(archive, target, kind):
            manifest = real(archive, target, kind=kind)
            path = Path(target) / "revoked-clients.json"
            path.write_text('{"revoked": []}')                                # the restored copy differs from the backup
            return manifest
        backup.restore_backup = tampered
        self.addCleanup(setattr, backup, "restore_backup", real)
        self.o.clock.t += 3601
        result = self.vault.drill()
        self.assertFalse(result["ok"])
        self.assertIn("drill_restored_file_differs", result["error"])

    def test_the_passkey_check_fails_closed(self):
        self.assertFalse(vault._passkeys_all_quarantined(b"not a database"))
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            db = sqlite3.connect(Path(d) / "p.sqlite3")
            db.execute("CREATE TABLE passkeys (revoked REAL, activated REAL, quarantined INTEGER)")
            db.executemany("INSERT INTO passkeys VALUES (?, ?, ?)", [(None, 1.0, 1), (5.0, 1.0, 0), (None, None, 0)])
            db.commit()
            db.close()
            data = (Path(d) / "p.sqlite3").read_bytes()
            self.assertTrue(vault._passkeys_all_quarantined(data))           # revoked and never-activated ones may stay as they are
            db = sqlite3.connect(Path(d) / "p.sqlite3")
            db.execute("INSERT INTO passkeys VALUES (NULL, 2.0, 0)")
            db.commit()
            db.close()
            self.assertFalse(vault._passkeys_all_quarantined((Path(d) / "p.sqlite3").read_bytes()))

    def test_a_missing_or_corrupted_newest_backup_is_noticed_and_replaced(self):
        first = self.vault.backup_now()["backup"]
        os.unlink(self.tmp / "vault" / first)
        self.o.clock.t += 3600
        done = self.vault.tick()
        self.assertFalse(done["recheck"]["ok"])
        self.assertTrue(done["backup"]["ok"])                                # replaced at once, not after 24 hours
        second = done["backup"]["backup"]
        path = self.tmp / "vault" / second
        data = bytearray(path.read_bytes())
        data[-3] ^= 1
        path.write_bytes(bytes(data))
        self.o.clock.t += DAY + 1
        done = self.vault.tick()
        self.assertIn("failed_recheck", done["recheck"]["error"])
        self.assertTrue(done["backup"]["ok"])

    def test_a_damaged_index_is_kept_aside_rebuilt_from_the_files_and_deletes_nothing(self):
        made = [self.vault.backup_now()["backup"]]
        for _ in range(2):
            self.o.clock.t += DAY
            made.append(self.vault.backup_now()["backup"])
        nonces_before = set((self.tmp / "vault" / vault.NONCE_LOG).read_text().split())
        (self.tmp / "vault/index.json").write_text("{damaged")
        os.chmod(self.tmp / "vault/index.json", 0o600)
        self.vault.retention = {"daily": 0, "weekly": 0}
        self.o.clock.t += DAY
        result = self.vault.backup_now()
        self.assertTrue(result["ok"], result)
        self.assertTrue(list((self.tmp / "vault").glob("index.damaged-*.json")))
        self.assertTrue(nonces_before <= set((self.tmp / "vault" / vault.NONCE_LOG).read_text().split()))
        index = json.loads((self.tmp / "vault/index.json").read_text())
        self.assertTrue(set(made) <= set(index["backups"]))                  # every old backup re-learned and verified
        self.assertTrue(all(index["backups"][n]["verified_at"] for n in made))

    def test_a_lost_nonce_log_is_rebuilt_from_the_backups_present(self):
        name = self.vault.backup_now()["backup"]
        header, _, _ = self.vault.open_backup(name)
        os.unlink(self.tmp / "vault" / vault.NONCE_LOG)
        self.assertIn(header["nonce"], self.vault._nonces())

    def test_files_not_created_by_this_vault_are_never_deleted(self):
        self.vault.backup_now()
        precaution = self.tmp / "vault" / "owner-20261125-000000-deadbeef.stynvault"    # looks like ours, but is NOT in the index
        precaution.write_bytes(b"precautionary archive")
        os.chmod(precaution, 0o600)
        codex = self.tmp / "vault" / "dev21-precaution-1.tar.age"
        codex.write_bytes(b"x")
        self.vault.retention = {"daily": 0, "weekly": 0}
        for _ in range(3):
            self.o.clock.t += DAY
            self.vault.backup_now()
        self.assertTrue(precaution.exists() and codex.exists())


@unittest.skipIf(cryptography is None, "needs cryptography")
class BackupToolTests(unittest.TestCase):
    """backup_status is a READ tool; the two tools that write go through the WRITE gate (workspace.propose + enrolled client)."""

    def setUp(self):
        import test_runner_tools as rt
        from stynpilot.server.app import create_server
        self.rt = rt
        self.o = OwnerVaultTests("test_status_shows_metadata_only")
        self.o.setUp()
        h = rt.RunnerToolTests("test_the_new_tools_are_listed_and_none_can_approve_or_run_a_free_command")
        h.setUp()

        class Broker(rt.FakeBroker):
            def vault_status(self):
                return {"side": "root", "healthy": True, "problems": []}

            def vault_backup(self):
                return {"ok": True}

            def vault_drill(self):
                raise OSError("installer down")
        h.broker = Broker()
        from stynpilot.diagnostics import Diagnostics
        from stynpilot.safefs import Policy
        h.server = create_server(router=h.router, resource_url=rt.AUDIENCE, propose=dict(clients=h.clients, store=h.store,
                                 approval_url="https://ryzen.example.test/app", clock=lambda: h.now[0]),
                                 diag=dict(policy=Policy(home=h.tmp, roots=(), project_roots=[]), diagnostics=Diagnostics(),
                                           vault=self.o.vault, broker=h.broker),
                                 runner=dict(broker=h.broker, projects_dir=str(h.projects), clock=lambda: h.now[0],
                                             limiter=h.limiter, vault=self.o.vault))
        self.h = h

    def test_backup_tools_work_and_writes_need_the_write_gate(self):
        tools = {t.name: t for t in asyncio.run(self.h.server.list_tools())}
        self.assertTrue(tools["backup_status"].annotations.readOnlyHint)
        self.assertFalse(tools["commander_backup_now"].annotations.readOnlyHint)
        from stynpilot.server.propose_tools import RUNNER_WRITE_TOOLS
        self.assertTrue({"commander_backup_now", "commander_backup_drill"} <= RUNNER_WRITE_TOOLS)
        made = self.h.call("commander_backup_now", self.h.d())
        self.assertTrue(made["result"]["owner"]["ok"], made)
        self.assertEqual(made["result"]["root"], {"ok": True})
        status = self.h.call("backup_status", self.h.d())
        self.assertTrue(status["result"]["owner"]["newest_verified"])
        self.assertNotIn("claude-connector", json.dumps(status))
        drill = self.h.call("commander_backup_drill", self.h.d())
        self.assertTrue(drill["result"]["owner"]["ok"])
        self.assertEqual(drill["result"]["root"], {"ok": False, "error": "installer_unreachable"})
        self.assertEqual(self.h.call("commander_backup_now", self.h.d())["result"]["owner"]["error"], "rate_limited")
        readonly = [t for t, who in self.rt.Tokens.valid.items() if "workspace.propose" not in who.scopes]
        if readonly:
            self.assertFalse(self.h.call("commander_backup_now", self.h.d(), readonly[0]).get("ok"))
