"""The pre-install backup must accept the state layout StyNpilot REALLY produces after a (failed) self-upgrade -
including the owner service's own pre-upgrade safety copies - and still refuse anything it does not recognise.
The layout here is made by StyNpilot's own code (service._owner_backup_before_upgrade, the real stores), not typed in.
Root-only (it writes the root-side folder under /var/backups, as the script does); cleans up after itself."""
import glob
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from stynpilot import service
from stynpilot.identity import SQLiteRevocations
from stynpilot.requests import RequestStore
from stynpilot.server.clients import RevocationFile

SCRIPT = str(Path(__file__).resolve().parent.parent / "tools" / "preflight_backup.sh")
SECRET = "SECRET-MARKER-must-never-be-printed"


@unittest.skipUnless(os.geteuid() == 0 and not Path("/etc/stynpilot").exists(), "needs root in a disposable sandbox")
class RealLayout(unittest.TestCase):
    def setUp(self):
        self.before = set(glob.glob("/var/backups/stynpilot-pre-m1-*"))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        os.chmod(self.home, 0o700)
        self.state = self.home / "state"
        self.state.mkdir(mode=0o700)
        RevocationFile(self.state / "revoked-clients.json").provision()
        SQLiteRevocations(self.state / "token-revocations.sqlite3").close()
        RequestStore(self.state / "requests.sqlite3")
        (self.state / "provisioned.json").write_text(json.dumps({"provisioned_at": 1, "version": 1}))
        os.chmod(self.state / "provisioned.json", 0o600)
        db = sqlite3.connect(self.home / "pairing.sqlite3")
        db.execute("create table t(x)")
        db.commit()
        db.close()
        cfg = self.home / ".config/stynpilot"
        cfg.mkdir(parents=True, mode=0o700)
        self.cfg = cfg / "owner.json"
        self.cfg.write_text(json.dumps({"pairing_db": str(self.home / "pairing.sqlite3"), "state_dir": str(self.state)}))
        os.chmod(self.cfg, 0o600)
        os.makedirs("/etc/stynpilot")
        Path("/etc/stynpilot/installer.json").write_text('{"owner":"x"}')
        os.chmod("/etc/stynpilot/installer.json", 0o600)
        self.addCleanup(self.cleanup_root)

    def cleanup_root(self):
        shutil.rmtree("/etc/stynpilot", ignore_errors=True)
        for d in set(glob.glob("/var/backups/stynpilot-pre-m1-*")) - self.before:
            shutil.rmtree(d, ignore_errors=True)

    def run_script(self, *args):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home), "STYNPILOT_OWNER_CONFIG": str(self.cfg)}
        done = subprocess.run(["sh", SCRIPT, *args], capture_output=True, text=True, env=env, timeout=120)
        return done.returncode, done.stdout + done.stderr

    def real_upgrade_safety_copies(self, count=1):
        """What the owner service does when an upgrade is approved (the thing that created the dev5-era folder)."""
        hook = service._owner_backup_before_upgrade(self.state)
        for i in range(count):
            hook({"kind": "upgrade"}, ("%016x" % (0xabc + i)) + "f" * 48)

    def digest(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    # -- the layout StyNpilot really has ------------------------------------------------------------------
    def test_the_original_flat_layout_still_passes(self):
        code, out = self.run_script(str(self.home / "dest"))
        self.assertEqual(code, 0, out)

    def test_the_layout_after_a_real_upgrade_attempt_passes_and_every_file_is_preserved_and_verified(self):
        self.real_upgrade_safety_copies(2)
        (self.state / "read-roots.json").write_text('{"roots": []}')
        os.chmod(self.state / "read-roots.json", 0o600)
        tars = sorted((self.state / "backups").glob("pre-upgrade-*.tar"))
        self.assertEqual(len(tars), 2)                       # made by the real code, not by this test
        want = {t.name: self.digest(t) for t in tars}
        dest = self.home / "dest"
        code, out = self.run_script(str(dest))
        self.assertEqual(code, 0, out)
        self.assertIn("RESULT: PASS", out)
        kept = {t.name: self.digest(t) for t in (dest / "owner/state/backups").glob("*.tar")}
        self.assertEqual(kept, want)                         # byte-identical copies
        self.assertEqual(self.digest(dest / "owner/state/read-roots.json"), self.digest(self.state / "read-roots.json"))
        self.assertEqual({t.name: self.digest(t) for t in tars}, want)        # live files untouched
        for p in dest.rglob("*"):
            self.assertEqual(p.is_symlink(), False)
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o700" if p.is_dir() else "0o600", str(p))
        code, out = self.run_script("--verify", str(dest))
        self.assertEqual(code, 0, out)

    def test_a_damaged_safety_copy_fails_the_verification(self):
        self.real_upgrade_safety_copies()
        dest = self.home / "dest"
        self.assertEqual(self.run_script(str(dest))[0], 0)
        tar = next((dest / "owner/state/backups").glob("*.tar"))
        tar.write_bytes(b"garbage")
        self.assertNotEqual(self.run_script("--verify", str(dest))[0], 0)

    # -- everything unrecognised is still refused, naming the entry but never printing contents -----------
    def refused(self, why):
        dest = self.home / "dest"
        code, out = self.run_script(str(dest))
        self.assertNotEqual(code, 0, why)
        self.assertIn("unexpected layout", out, why)
        self.assertNotIn(SECRET, out, why)
        self.assertFalse(dest.exists(), why)                 # nothing was created
        self.assertEqual(glob.glob("/var/backups/stynpilot-pre-m1-*"), sorted(self.before), why)
        return out

    def test_an_unknown_file_is_refused_and_named_but_not_read(self):
        (self.state / "mystery.key").write_text(SECRET)
        self.assertIn("mystery.key", self.refused("unknown file"))

    def test_an_unknown_subfolder_is_refused(self):
        (self.state / "other").mkdir(mode=0o700)
        self.assertIn("other", self.refused("unknown folder"))

    def test_odd_things_inside_backups_are_refused(self):
        self.real_upgrade_safety_copies()
        folder = self.state / "backups"
        for make, name in ((lambda p: p.write_text(SECRET), "notes.txt"),
                           (lambda p: p.write_text(SECRET), "pre-upgrade-xyz.tar"),
                           (lambda p: p.mkdir(), "pre-upgrade-0123456789abcdef.tar"),
                           (lambda p: p.symlink_to("/etc/passwd"), "pre-upgrade-0123456789abcdef.tar")):
            path = folder / name
            make(path)
            self.assertIn("backups/", self.refused(name))
            shutil.rmtree(path) if path.is_dir() and not path.is_symlink() else path.unlink()

    def test_links_are_refused_for_the_folder_and_the_roots_file(self):
        (self.state / "read-roots.json").symlink_to("/etc/passwd")
        self.refused("roots link")
        (self.state / "read-roots.json").unlink()
        real = self.home / "elsewhere"
        real.mkdir()
        (self.state / "backups").symlink_to(real)
        self.refused("backups link")


if __name__ == "__main__":
    unittest.main()
