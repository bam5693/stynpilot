"""G7: backup/restore, doctor, first-run setup (incl. the polkit root step) and the .deb contents."""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    import jwt
    from stynpilot import backup, doctor, service, setup_wizard
    from stynpilot.service import ConfigError
    import test_service as ts
    from test_service import owner_data
except ImportError:          # pragma: no cover
    jwt = None

import test_broker as tb
from legacy_pairing import make_pairing_db

ROOT = Path(__file__).resolve().parent.parent
HOME_MODE = 0o700


def tmpdir(test):
    t = tempfile.TemporaryDirectory()
    test.addCleanup(t.cleanup)
    path = Path(t.name)
    os.chmod(path, 0o700)
    return path


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp))
        service.provision_owner_state(self.config)
        from stynpilot.server.clients import RevocationFile
        RevocationFile(self.config.state_dir / "revoked-clients.json").set_revoked("claude-connector", True)

    def test_backup_then_restore_into_an_empty_folder_keeps_revocations(self):
        archive = self.tmp / "b" / "backup.tar"
        manifest = backup.make_backup(self.config.state_dir, archive)
        self.assertEqual(set(manifest["files"]), set(backup.OWNER_FILES))
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        restored = self.tmp / "restored"
        backup.restore_backup(archive, restored)
        self.assertEqual(json.loads((restored / "revoked-clients.json").read_text()), {"revoked": ["claude-connector"]})
        self.assertEqual((restored / "requests.sqlite3").stat().st_mode & 0o777, 0o600)

    def test_restore_refuses_to_overwrite_and_a_tampered_archive_is_refused(self):
        archive = self.tmp / "b.tar"
        backup.make_backup(self.config.state_dir, archive)
        with self.assertRaises(backup.BackupError) as refused:
            backup.restore_backup(archive, self.config.state_dir)
        self.assertIn("not_empty", str(refused.exception))
        bad = self.tmp / "bad.tar"
        with tarfile.open(archive) as src, tarfile.open(bad, "w") as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read()
                if member.name == "revoked-clients.json":
                    data = b'{"revoked": []}'                                   # someone un-revokes the client
                member.size = len(data)
                import io
                dst.addfile(member, io.BytesIO(data))
        with self.assertRaises(backup.BackupError) as refused:
            backup.restore_backup(bad, self.tmp / "r2")
        self.assertIn("hash", str(refused.exception))

    def test_odd_archive_members_are_refused(self):
        evil = self.tmp / "evil.tar"
        import io
        with tarfile.open(evil, "w") as tar:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        with self.assertRaises(backup.BackupError):
            backup.read_backup(evil)

    def test_backup_never_overwrites_an_existing_file_and_needs_a_private_folder(self):
        archive = self.tmp / "once.tar"
        backup.make_backup(self.config.state_dir, archive)
        with self.assertRaises(FileExistsError):
            backup.make_backup(self.config.state_dir, archive)
        os.chmod(self.config.state_dir, 0o755)
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.config.state_dir, self.tmp / "x.tar")

    def test_a_missing_state_file_stops_the_backup(self):
        (self.config.state_dir / "revoked-clients.json").unlink()
        with self.assertRaises(backup.BackupError):
            backup.make_backup(self.config.state_dir, self.tmp / "y.tar")


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        make_pairing_db(self.tmp / "pairing", [(ts.DEVICE, ts.OWNER, time.time() + 3600, None, ["workspace.propose"])])
        self.pairing = next((self.tmp / "pairing").iterdir())
        self.config = service.OwnerConfig.from_dict(owner_data(self.tmp, pairing_db=str(self.pairing)))

    def levels(self, **kw):
        return {name: level for name, level, _ in doctor.run_checks(owner_config=self.config, units=False, **kw)}

    def test_unprovisioned_state_is_a_failure_with_the_safe_remedy_and_nothing_is_created(self):
        levels = self.levels(listeners=lambda h, p: [])
        self.assertEqual(levels["owner state folder"], doctor.FAIL)
        self.assertFalse(self.config.state_dir.exists())                            # doctor never creates anything

    def test_healthy_state_and_loopback_listeners_pass(self):
        service.provision_owner_state(self.config)
        checks = doctor.run_checks(owner_config=self.config, units=False, listeners=lambda h, p: [(h, p)],
                                   client=SimpleNamespace(status=lambda rid: {"state": "not_started"}))
        levels = {n: l for n, l, _ in checks}
        self.assertEqual(levels["owner state files"], doctor.OK)
        self.assertEqual(levels["approval page listener"], doctor.OK)
        self.assertEqual(levels["pairing database"], doctor.OK)
        self.assertEqual(levels["installer answers"], doctor.OK)
        self.assertEqual(levels["installer socket"], doctor.WARN)                  # not running here: a warning, not fail
        self.assertEqual(doctor.exit_code(checks), 0)

    def test_loose_permissions_and_missing_state_are_failures(self):
        service.provision_owner_state(self.config)
        os.chmod(self.config.state_dir / "revoked-clients.json", 0o644)
        (self.config.state_dir / "provisioned.json").unlink()
        checks = doctor.run_checks(owner_config=self.config, units=False)
        by = {n: (l, d) for n, l, d in checks}
        self.assertEqual(by["state file revoked-clients.json"][0], doctor.FAIL)
        self.assertEqual(by["owner state files"][0], doctor.FAIL)
        self.assertIn("never recreate by hand", by["owner state files"][1])
        self.assertEqual(doctor.exit_code(checks), 1)

    def test_missing_dependency_and_unreadable_pairing_are_reported(self):
        def importer(name):
            if name == "mcp":
                raise ImportError(name)
        self.assertEqual(doctor.check_modules(importer)[1], doctor.FAIL)
        self.assertEqual(doctor.check_pairing(self.tmp / "none.db")[1], doctor.FAIL)

    def test_socket_checks_and_report_text_never_leak_values(self):
        import socket
        path = self.tmp / "s.sock"
        s = socket.socket(socket.AF_UNIX)
        self.addCleanup(s.close)
        s.bind(str(path))
        os.chmod(path, 0o666)
        self.assertEqual(doctor.check_socket(path)[1], doctor.FAIL)
        os.chmod(path, 0o600)
        self.assertEqual(doctor.check_socket(path, os.geteuid())[1], doctor.OK)
        text = doctor.render(doctor.run_checks(owner_config=self.config, units=False))
        self.assertIn("Nothing was changed", text)
        self.assertNotIn("approval-app", text)

    def test_existing_preview26_service_is_reported_as_left_alone(self):
        d = self.tmp / "units"
        d.mkdir()
        (d / "stynpilot-remote-broker.service").write_text("x")
        name, level, detail = doctor.check_legacy((str(d),))
        self.assertEqual(level, doctor.OK)
        self.assertIn("untouched", detail)


FORM = {"issuer": "tenant.example.auth", "approval_client_id": "approval-app", "approval_public_host": "pc.example.test:8444",
        "mcp_public_host": "pc.example.test", "pairing_db": "", "chatgpt_client_id": "cg", "claude_client_id": "cl"}


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class SetupTests(unittest.TestCase):
    def setUp(self):
        self.home = tmpdir(self)
        make_pairing_db(self.home / "pair", [(ts.DEVICE, ts.OWNER, time.time() + 3600, None, ["workspace.propose"])])
        self.form = dict(FORM, pairing_db=str(next((self.home / "pair").iterdir())))

    def test_setup_writes_private_config_provisions_state_and_derives_owner_from_pairing(self):
        done = setup_wizard.run_setup(self.form, self.home, 1000)
        paths = setup_wizard.default_paths(self.home)
        self.assertEqual(paths["config"].stat().st_mode & 0o777, 0o600)
        proposal = json.loads(paths["proposed"].read_text())
        self.assertEqual((proposal["owner"], proposal["device"], proposal["owner_uid"]), (ts.OWNER, ts.DEVICE, 1000))
        self.assertTrue((paths["state"] / "revoked-clients.json").exists())
        self.assertEqual(service.OwnerConfig.from_file(paths["config"]).issuer, "https://tenant.example.auth/")
        with self.assertRaises(ConfigError):                                         # never overwrites
            setup_wizard.run_setup(self.form, self.home, 1000)

    def test_bad_form_or_no_pairing_writes_nothing(self):
        for bad in (dict(self.form, issuer=""), dict(self.form, approval_public_host="10.0.0.1:8444"),
                    dict(self.form, pairing_db=str(self.home / "missing.db"))):
            with self.assertRaises(Exception):
                setup_wizard.run_setup(bad, self.home, 1000)
        self.assertFalse(setup_wizard.default_paths(self.home)["config"].exists())

    def write_proposal(self, **over):
        setup_wizard.run_setup(self.form, self.home, over.pop("uid", os.geteuid()))
        return setup_wizard.default_paths(self.home)["proposed"]

    def root(self, source, **kw):
        return setup_wizard.root_setup(source, dest=self.home / "etc/installer.json", geteuid=lambda: 0,
                                       invoking_uid=kw.pop("uid", os.geteuid()), **kw)

    def test_root_step_installs_the_config_for_exactly_the_caller_and_never_replaces_one(self):
        source = self.write_proposal()
        # the sandbox user can't be uid >= 1000 in every environment; the check is that it equals the caller
        if os.geteuid() < 1000:
            with self.assertRaises(ConfigError):
                self.root(source)                                                    # uid must be a normal user
            return
        self.root(source)
        self.assertEqual((self.home / "etc/installer.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.root(source)

    def test_root_step_refuses_wrong_caller_loose_files_and_non_root(self):
        source = self.write_proposal(uid=os.geteuid())
        with self.assertRaises(ConfigError):
            setup_wizard.root_setup(source, dest=self.home / "e.json", geteuid=lambda: 1000, invoking_uid=1000)
        with self.assertRaises(ConfigError):
            self.root(source, uid=os.geteuid() + 1)                                  # file isn't theirs
        os.chmod(source, 0o644)
        with self.assertRaises(ConfigError):
            self.root(source)
        link = self.home / "link.json"
        link.symlink_to(source)
        with self.assertRaises(OSError):
            self.root(link)
        with self.assertRaises(ConfigError):
            setup_wizard.root_setup(source, dest=self.home / "e.json", geteuid=lambda: 0, environ={})   # not via polkit

    def test_root_step_pins_the_packaged_paths_and_fields(self):
        source = self.write_proposal()
        data = json.loads(source.read_text())
        for field, value in (("state_dir", "/etc"), ("socket_path", "/tmp/x.sock")):
            os.chmod(source, 0o600)
            source.write_text(json.dumps(dict(data, **{field: value})))
            with self.assertRaises(ConfigError):
                self.root(source)
        source.write_text(json.dumps(dict(data, extra=1)))
        with self.assertRaises(ConfigError):
            self.root(source)

    def test_wizard_page_needs_the_secret_host_and_origin_and_runs_the_root_step_only_on_click(self):
        import httpx
        calls = []
        app = setup_wizard.build_app(home=self.home, uid=1000, token="tok123", port=5555,
                                     root_runner=lambda src: calls.append(src) or SimpleNamespace(returncode=0),
                                     setup=lambda values, home, uid: {"ok": True})
        from starlette.testclient import TestClient
        c = TestClient(app, base_url="http://127.0.0.1:5555")
        self.assertEqual(c.get("/setup/wrong", headers={"host": "127.0.0.1:5555"}).status_code, 404)
        self.assertEqual(c.get("/setup/tok123", headers={"host": "evil.example"}).status_code, 404)
        page = c.get("/setup/tok123", headers={"host": "127.0.0.1:5555"})
        self.assertEqual(page.status_code, 200)
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertEqual(c.post("/setup/tok123/save", data=self.form, headers={"host": "127.0.0.1:5555"}).status_code, 404)  # no Origin
        ok = c.post("/setup/tok123/save", data=self.form, headers={"host": "127.0.0.1:5555", "origin": "http://127.0.0.1:5555"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(calls, [])                                                  # nothing privileged yet
        done = c.post("/setup/tok123/system", data={"go": "1"}, headers={"host": "127.0.0.1:5555", "origin": "http://127.0.0.1:5555"})
        self.assertEqual(done.status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertIn("Nothing is running yet", done.text)


@unittest.skipIf(jwt is None, "PyJWT/cryptography not installed")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cache = ROOT / ".build-cache"
        if not shutil.which("dpkg-deb") or not list(cache.glob("mcp-*.whl")):
            raise unittest.SkipTest("dpkg-deb or the pinned wheel cache is missing (build once with network)")
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_deb", ROOT / "tools/build_deb.py")
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)
        cls.deb = cls.mod.build(Path(cls.tmp.name) / "out", cache)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def listing(self):
        out = subprocess.run(["dpkg-deb", "-c", str(self.deb)], capture_output=True, text=True, check=True).stdout
        return [line.split()[-1] for line in out.splitlines()]

    def test_every_module_is_in_the_package(self):
        packaged = {n for n in self.listing() if n.endswith(".py") and "/lib/stynpilot/stynpilot/" in n.replace("./usr", "/usr") + "/"
                    or n.startswith("./usr/lib/stynpilot/lib/stynpilot/") and n.endswith(".py")}
        want = {"./usr/lib/stynpilot/lib/stynpilot/" + str(p.relative_to(ROOT / "src/stynpilot"))
                for p in (ROOT / "src/stynpilot").rglob("*.py")}
        self.assertEqual(want - set(packaged), set())

    def test_package_changes_nothing_when_installed_and_has_no_secrets(self):
        names = self.listing()
        self.assertFalse([n for n in names if "DEBIAN" in n or n.endswith(("postinst", "preinst", "prerm", "postrm"))])
        info = subprocess.run(["dpkg-deb", "-I", str(self.deb)], capture_output=True, text=True, check=True).stdout
        self.assertNotIn("postinst", info)
        self.assertIn("polkitd", info)
        self.assertIn("./usr/lib/systemd/system/stynpilot-installer.service", names)
        self.assertIn("./usr/lib/systemd/user/stynpilot-owner.service", names)
        self.assertFalse([n for n in names if "/etc/" in n and "systemd" not in n])   # no /etc files, nothing enabled
        self.assertFalse([n for n in names if "wants" in n])
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["dpkg-deb", "-x", str(self.deb), d], check=True)
            text = (Path(d) / "usr/lib/stynpilot/lib/stynpilot/service.py").read_text()
            for bad in ("dtdev_", "auth0|", "BEGIN PRIVATE"):
                self.assertNotIn(bad, text)
            launcher = (Path(d) / "usr/bin/stynpilot").read_text()
            self.assertTrue(launcher.startswith("#!/usr/bin/python3 -I"))
            for unit in ("usr/lib/systemd/system/stynpilot-installer.service", "usr/lib/systemd/user/stynpilot-owner.service"):
                self.assertTrue((Path(d) / unit).read_bytes() == (ROOT / "deploy/systemd" / Path(unit).name).read_bytes())

    def test_build_is_reproducible_and_the_vendored_wheel_is_hash_pinned(self):
        again = self.mod.build(Path(self.tmp.name) / "out2", ROOT / ".build-cache")
        self.assertEqual(hashlib.sha256(self.deb.read_bytes()).hexdigest(), hashlib.sha256(again.read_bytes()).hexdigest())
        name, version, digest = next(self.mod.read_lock())
        wheel = next((ROOT / ".build-cache").glob("%s-%s-*.whl" % (name, version)))
        self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
