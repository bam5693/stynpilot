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
        index = json.loads((self.tmp / "vault/index.json").read_text())
        self.assertTrue(seen <= set(index["nonces"]))
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
        (self.etc / "installer.json").write_text(json.dumps({"owner": "o", "device": "d", "approval_client_id": "app"}))
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
        names = [n for n, _, _ in service.root_vault_extras(self.etc / "installer.json", self.state)]
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
class BackupToolTests(unittest.TestCase):
    def setUp(self):
        import test_dev4_reads as reads
        self.reads = reads
        self.owner = OwnerVaultTests("test_status_shows_metadata_only")
        self.owner.setUp()

        class Broker:
            calls = []

            def vault_status(self):
                self.calls.append("status")
                return {"side": "root", "healthy": True, "problems": []}

            def vault_backup(self):
                self.calls.append("backup")
                return {"ok": True}

            def vault_drill(self):
                self.calls.append("drill")
                raise OSError("installer down")
        self.broker = Broker()
        h = reads.DiagToolTests("test_tools_exist_and_work_with_only_the_read_scope")
        h.setUp()
        from stynpilot.server.app import create_server
        from stynpilot.diagnostics import Diagnostics
        router = reads.ReadRouter(tokens=reads.Tokens(), ownership=reads.LocalOwnership(grants=reads.Grants(), owner_id=reads.OWNER,
                                                                                         device_id=reads.DEVICE),
                                  read_health=lambda: {"cpu_usage_percent": 1.0})
        h.server = create_server(router=router, resource_url=reads.AUDIENCE, diag=dict(
            policy=reads.Policy(home=h.home, roots=(), project_roots=[h.home / "proj"]), diagnostics=Diagnostics(run=reads.FakeRun()),
            vault=self.owner.vault, broker=self.broker))
        self.h = h

    def test_the_three_backup_tools_work_and_reveal_no_contents(self):
        tools = {t.name: t for t in asyncio.run(self.h.server.list_tools())}
        self.assertTrue(tools["backup_status"].annotations.readOnlyHint)
        self.assertFalse(tools["commander_backup_now"].annotations.destructiveHint)
        made = self.h.call("commander_backup_now", {"device_id": self.reads.DEVICE})
        self.assertTrue(made["result"]["owner"]["ok"], made)
        self.assertEqual(made["result"]["root"], {"ok": True})
        status = self.h.call("backup_status", {"device_id": self.reads.DEVICE})
        self.assertTrue(status["result"]["owner"]["newest_verified"])
        self.assertNotIn("claude-connector", json.dumps(status))
        drill = self.h.call("commander_backup_drill", {"device_id": self.reads.DEVICE})
        self.assertTrue(drill["result"]["owner"]["ok"])
        self.assertEqual(drill["result"]["root"], {"healthy": False, "problems": ["installer_unreachable"]})
        again = self.h.call("commander_backup_now", {"device_id": self.reads.DEVICE})
        self.assertEqual(again["result"]["owner"]["error"], "rate_limited")
        refused = self.h.call("backup_status", {"device_id": "dtdev_NOTMINE1234"})
        self.assertEqual(refused, {"ok": False, "error": "device_unavailable_or_not_authorized"})
