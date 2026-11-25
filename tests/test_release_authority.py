"""dev16: the release authority. Build from an exact commit (twice, identical, tests green), then ONE owner approval signs,
publishes to GitHub and starts the protected upgrade. Fakes stand in for git/pytest and for GitHub; the installer, approval check,
upgrade preparation and manifest signature checks are the real ones."""
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
try:
    import test_dev4_upgrade as tu
    from stynpilot import release, release_console
    from stynpilot.broker.executor import ExecutionDenied
    from stynpilot.broker.release_authority import Authority, AuthorityError, default_http
    from stynpilot.requests import request_id
    from stynpilot.broker.proof import render_summary
except ImportError:          # pragma: no cover
    tu = None

COMMIT = "c" * 40
VERSION = "0.1.0~dev4"


class FakeMachine:
    """Pretends to be git + the build + pytest inside the builder's work folder, and records what ran."""
    def __init__(self, deb_bytes, *, tests="1 passed in 1.0s", second_build=None, commit=COMMIT, version="0.1.0.dev4"):
        self.deb, self.tests, self.second, self.commit, self.version = deb_bytes, tests, second_build, commit, version
        self.calls = []

    def __call__(self, argv, timeout, cwd=None, env=None):
        assert argv[:1] == ["env"], argv            # always run through the unprivileged-account prefix
        script = argv[-1]
        self.calls.append(script)
        work = Path(cwd)
        if "git init" in script:
            (work / "src").mkdir()
            return 0, "...\n" + self.commit + "\n"
        if "__version__" in script:
            return 0, self.version + "\n"
        m = re.search(r"build_deb\.build\('\.\./out(\d)'", script)
        if m:
            out = work / ("out" + m.group(1))
            out.mkdir()
            data = self.deb if m.group(1) == "0" or self.second is None else self.second
            (out / "stynpilot_x_all.deb").write_bytes(data)
            return 0, ""
        m = re.search(r"sha256sum out(\d)/", script)
        if m:
            return 0, hashlib.sha256((work / ("out" + m.group(1)) / "stynpilot_x_all.deb").read_bytes()).hexdigest() + "\n"
        if "pytest" in script:
            return 0, "....\n" + self.tests + "\n"
        return 1, "unexpected command"


class FakeGitHub:
    def __init__(self, existing=None):
        self.calls, self.releases, self.assets, self.next_id = [], dict(existing or {}), {}, 100
        self.fail_upload = False

    def __call__(self, method, url, headers, body, max_bytes=0):
        self.calls.append((method, url, headers, body))
        assert headers["Authorization"].startswith("Bearer ")
        m = re.fullmatch(r"https://api\.github\.com/repos/([^/]+/[^/]+)/releases/tags/(.+)", url)
        if m:
            rel = self.releases.get(m.group(2))
            return (200, json.dumps(rel).encode()) if rel else (404, b"{}")
        if url.endswith("/releases") and method == "POST":
            data = json.loads(body)
            self.next_id += 1
            rel = {"id": self.next_id, "tag_name": data["tag_name"], "target_commitish": data["target_commitish"], "assets": []}
            self.releases[data["tag_name"]] = rel
            return 201, json.dumps(rel).encode()
        m = re.fullmatch(r"https://uploads\.github\.com/repos/[^/]+/[^/]+/releases/(\d+)/assets\?name=(.+)", url)
        if m:
            if self.fail_upload:
                return 500, b"{}"
            name = m.group(2)
            self.assets[name] = body
            for rel in self.releases.values():
                if rel["id"] == int(m.group(1)):
                    rel["assets"].append({"name": name})
            return 201, b"{}"
        if url.endswith("/repos/bam5693/stynpilot"):
            return 200, json.dumps({"permissions": {"push": True}}).encode()
        raise AssertionError(url)


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class AuthorityTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        os.chmod(self.tmp, 0o700)
        self.deb_bytes = b"!<arch>\npretend package contents" * 100
        self.machine = FakeMachine(self.deb_bytes)
        self.http = FakeGitHub()
        self.auth = Authority(self.tmp, run=self.machine, http=self.http, build_prefix=["env"])
        self.auth.init_key()
        self.auth.set_token("github_pat_" + "A" * 30)

    def prepared(self):
        return self.auth.prepare(COMMIT, VERSION, "0.1.0~dev3")

    def test_a_good_build_is_recorded_with_everything_the_owner_will_see(self):
        got = self.prepared()
        self.assertEqual((got["state"], got["reproducible"], got["tests_passed"], got["tests_failed"]), ("ready", True, 1, 0))
        self.assertEqual(got["sha256"], hashlib.sha256(self.deb_bytes).hexdigest())
        intent = self.auth.intent(COMMIT, VERSION, "looked fine")
        self.assertEqual((intent["commit"], intent["size"], intent["key_id"]), (COMMIT, len(self.deb_bytes), self.auth.key_entry()["key_id"]))
        self.assertEqual(self.http.calls, [])                              # building publishes and signs nothing

    def test_every_way_a_build_can_be_wrong_is_a_failed_record_never_a_ready_one(self):
        cases = {"build_is_not_reproducible": FakeMachine(self.deb_bytes, second_build=b"different"),
                 "tests_failed_2_passed_5": FakeMachine(self.deb_bytes, tests="2 failed, 5 passed in 3s"),
                 "test_result_unreadable": FakeMachine(self.deb_bytes, tests="boom"),
                 "could_not_fetch_that_exact_commit": FakeMachine(self.deb_bytes, commit="d" * 40),
                 "source_version_differs_from_requested_version": FakeMachine(self.deb_bytes, version="0.1.0.dev9")}
        for why, machine in cases.items():
            auth = Authority(self.tmp / ("a-" + why[:8]), run=machine, http=self.http, build_prefix=["env"])
            auth.init_key()
            auth.set_token("github_pat_" + "B" * 30)
            got = auth.prepare(COMMIT, VERSION, "x")
            self.assertEqual((got["state"], got["why"]), ("failed", why), why)
            with self.assertRaises(AuthorityError):
                auth.intent(COMMIT, VERSION)

    def test_the_builder_cannot_make_root_publish_a_file_from_elsewhere(self):
        class Sneaky(FakeMachine):
            def __call__(self, argv, timeout, cwd=None, env=None):
                result = super().__call__(argv, timeout, cwd=cwd, env=env)
                m = re.search(r"build_deb\.build\('\.\./out(\d)'", argv[-1])
                if m and m.group(1) == "0":                  # swap the built package for a link to some other file
                    target = Path(cwd).parent / "elsewhere.deb"
                    target.write_bytes(self.deb)
                    link = Path(cwd) / "out0" / "stynpilot_x_all.deb"
                    link.unlink()
                    link.symlink_to(target)
                return result
        work = self.tmp / "buildroot"
        auth = Authority(self.tmp / "sn", run=Sneaky(self.deb_bytes), http=self.http, build_prefix=["env"], work_root=work)
        auth.init_key()
        auth.set_token("github_pat_" + "F" * 30)
        got = auth.prepare(COMMIT, VERSION, "x")
        self.assertEqual((got["state"], got["why"]), ("failed", "package_not_where_the_builder_should_have_put_it"))

    def test_unusable_requests_are_refused_up_front(self):
        for commit, version in (("abc", VERSION), (COMMIT.upper(), VERSION), (COMMIT, "bad version")):
            with self.assertRaises(AuthorityError):
                self.auth.prepare_check(commit, version)
        bare = Authority(self.tmp / "bare", run=self.machine, http=self.http, build_prefix=["env"])
        with self.assertRaises(AuthorityError) as e:
            bare.prepare_check(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "release_authority_not_provisioned")
        nobuilder = Authority(self.tmp / "nb", run=self.machine, http=self.http)
        with self.assertRaises(AuthorityError) as e:
            nobuilder.prepare_check(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "builder_not_configured")

    def test_a_verified_package_that_is_altered_afterwards_is_no_longer_offered(self):
        self.prepared()
        deb = next((self.tmp / "release/builds" / COMMIT).glob("*.deb"))
        os.chmod(deb, 0o600)
        deb.write_bytes(b"swapped")
        with self.assertRaises(AuthorityError) as e:
            self.auth.intent(COMMIT, VERSION)
        self.assertEqual(e.exception.code, "verified_package_was_altered")

    def test_secrets_are_private_files_and_the_key_is_created_once(self):
        for name in ("signing-ed25519.pem", "github-token"):
            self.assertEqual(stat.S_IMODE(os.stat(self.tmp / "release" / name).st_mode), 0o600)
        first = self.auth.key_entry()
        self.assertEqual(Authority(self.tmp, run=self.machine, http=self.http, build_prefix=["env"]).init_key(), first)
        for bad in ("", "short", "has space " + "A" * 30, "semi;colon" + "A" * 30, None, 5):
            with self.assertRaises(AuthorityError):
                self.auth.set_token(bad)

    def test_publishing_goes_only_to_githubs_api_hosts_at_the_exact_commit_and_can_be_repeated(self):
        self.prepared()
        intent = self.auth.intent(COMMIT, VERSION)
        manifest = self.auth.manifest_for(intent, ["note"])
        signature = self.auth.sign(manifest)
        self.auth.publish(manifest, signature, COMMIT)
        self.auth.publish(manifest, signature, COMMIT)                       # repeat: nothing new is uploaded
        hosts = {re.match(r"https://([^/]+)/", c[1]).group(1) for c in self.http.calls}
        self.assertEqual(hosts, {"api.github.com", "uploads.github.com"})
        creates = [c for c in self.http.calls if c[0] == "POST" and c[1].endswith("/releases")]
        self.assertEqual(len(creates), 1)
        self.assertEqual(json.loads(creates[0][3])["target_commitish"], COMMIT)
        self.assertEqual(set(self.http.assets), {manifest["asset"], "release-manifest.json", "release-manifest.json.sig"})
        self.assertEqual(self.http.assets[manifest["asset"]], self.deb_bytes)
        release.verify(json.loads(self.http.assets["release-manifest.json"]), self.http.assets["release-manifest.json.sig"].decode(),
                       {self.auth.key_entry()["key_id"]: self.auth._private().public_key()})

    def test_a_tag_that_already_exists_for_a_different_commit_is_refused(self):
        self.prepared()
        manifest = self.auth.manifest_for(self.auth.intent(COMMIT, VERSION), ["n"])
        self.http.releases[manifest["tag"]] = {"id": 7, "tag_name": manifest["tag"], "target_commitish": "e" * 40, "assets": []}
        with self.assertRaises(AuthorityError) as e:
            self.auth.publish(manifest, self.auth.sign(manifest), COMMIT)
        self.assertEqual(e.exception.code, "tag_exists_for_a_different_commit")
        self.assertEqual(self.http.assets, {})

    def test_the_http_helper_refuses_other_hosts_and_never_follows_redirects(self):
        for url in ("https://evil.example/x", "http://api.github.com/x", "https://api.github.com:444/x",
                    "https://user@api.github.com/x", "https://api.github.com.evil.example/x"):
            with self.assertRaises(AuthorityError):
                default_http("GET", url, {}, None)

    def test_token_check_reports_whether_it_can_write(self):
        self.assertTrue(self.auth.check_token()["ok"])


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class OneApprovalTests(tu.UpgradeTests):
    """The real executor: challenge, proof, sign, publish, protected upgrade - all behind one Auth0-signed approval."""
    def setUp(self):
        tu.UpgradeTests.setUp(self)
        self.deb = Path(self.pkg.deb(VERSION))
        self.machine = FakeMachine(self.deb.read_bytes())
        self.http = FakeGitHub()
        self.auth = Authority(self.tmp / "broker", run=self.machine, http=self.http, build_prefix=["env"])
        # the machine's own signing key IS the trusted key of this test machine
        (self.tmp / "broker" / "release").mkdir(parents=True, exist_ok=True)
        (self.auth.keyfile).write_bytes(release.private_pem(self.signing))
        os.chmod(self.auth.keyfile, 0o600)
        self.auth.set_token("github_pat_" + "C" * 30)
        self.build(authority=self.auth, sleep=lambda s: None)
        self.auth.prepare(COMMIT, VERSION, "0.1.0~dev3")

    def release_payload(self, note="reviewed", minutes=30):
        from datetime import datetime, timedelta, timezone
        intent = self.executor.release_intent(COMMIT, VERSION, note)
        return {"kind": "release", "owner": tu.OWNER, "device": tu.DEVICE, "intent": intent,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")}

    def publish_into_downloads(self):
        """Make what the fake GitHub received downloadable the way the real GitHub would serve it."""
        for rel in self.http.releases.values():
            tag = rel["tag_name"]
            base = "https://github.com/bam5693/stynpilot/releases/download/%s/" % tag
            for name, body in self.http.assets.items():
                self.downloads[base + name] = body

    def test_the_owner_reads_exact_facts_and_nothing_is_signed_or_published_before_approval(self):
        payload = self.release_payload()
        shown = self.executor.challenge(payload, "approve")
        text = "\n".join(shown["summary"])
        for needle in (COMMIT[:12], payload["intent"]["sha256"], payload["intent"]["key_id"], "ONE approval", "built it twice",
                       "1 passed, 0 failed", "Nothing is signed or published before you approve",
                       "written by an assistant, not verified"):
            self.assertIn(needle, text)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.launched, [])

    def test_approval_signs_publishes_and_starts_the_protected_upgrade_once(self):
        payload = self.release_payload()
        challenge, proof = self.approve(payload)
        # downloads are filled as the fake GitHub receives the assets; wire it by wrapping the http call
        real = self.http.__call__

        def wrapped(*a, **k):
            result = real(*a, **k)
            self.publish_into_downloads()
            return result
        self.auth.http = wrapped
        result = self.executor.release(payload, proof, challenge)
        self.assertEqual((result["pending"], result["to_version"], result["from_version"]), (True, VERSION, "0.1.0~dev3"))
        self.assertEqual(len(self.launched), 1)
        self.assertEqual(set(self.http.assets), {"stynpilot-v0.1.0-dev4.deb", "release-manifest.json", "release-manifest.json.sig"})
        manifest = json.loads(self.http.assets["release-manifest.json"])
        self.assertEqual((manifest["git_commit"], manifest["sha256"]), (COMMIT, payload["intent"]["sha256"]))
        self.denied("already_decided_or_used", self.executor.release, payload, proof, challenge)        # no replay
        self.assertEqual(len(self.launched), 1)

    def test_a_wrong_proof_publishes_nothing(self):
        payload = self.release_payload()
        challenge, _ = self.approve(payload)
        other = self.release_payload(note="a different note")
        bad_proof = self.proof(other, challenge)                       # signed for a different request
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, bad_proof, challenge)
        with self.assertRaises(ExecutionDenied):
            self.executor.release(payload, "not a token", challenge)
        self.assertEqual(self.http.calls, [])
        self.assertEqual(self.launched, [])

    def test_a_changed_intent_is_refused_before_anyone_is_asked(self):
        for field, value in (("sha256", "0" * 64), ("commit", "d" * 40), ("tests_failed", 3), ("tests_passed", 99),
                             ("key_id", "0" * 16), ("version", "0.1.0~dev9"), ("from_min", "0.1.0~dev3")):
            payload = self.release_payload()
            payload["intent"][field] = value
            with self.assertRaises(ExecutionDenied, msg=field):
                self.executor.challenge(payload, "approve")
        extra = self.release_payload()
        extra["intent"]["extra"] = 1
        with self.assertRaises(ExecutionDenied):
            self.executor.challenge(extra, "approve")
        stray = dict(self.release_payload(), surprise=1)
        with self.assertRaises(ExecutionDenied):
            self.executor.challenge(stray, "approve")
        self.assertEqual(self.http.calls, [])

    def test_a_key_this_machine_does_not_trust_cannot_even_be_requested(self):
        self.executor.upgrader._keys = {}
        self.executor.upgrader._keys = {"1" * 16: release.new_private_key().public_key()}
        self.denied("release_key_not_trusted_by_this_machine", self.executor.challenge, self.release_payload(), "approve")

    def test_a_github_failure_before_the_upgrade_leaves_the_approval_unspent(self):
        payload = self.release_payload()
        challenge, proof = self.approve(payload)
        self.http.fail_upload = True
        with self.assertRaises(ExecutionDenied) as caught:
            self.executor.release(payload, proof, challenge)
        self.assertTrue(caught.exception.code.startswith("release_upload_failed"))
        self.assertEqual(self.launched, [])
        self.assertEqual(self.executor.runs.status(request_id(payload)[0])["state"], "not_started")

    def test_not_newer_expired_and_unconfigured_cases(self):
        stale = self.release_payload(minutes=-5)
        self.denied("plan_invalid_or_expired", self.executor.challenge, stale, "approve")
        long = self.release_payload(minutes=120)
        self.denied("plan_invalid_or_expired", self.executor.challenge, long, "approve")
        self.build(sleep=lambda s: None)                               # no authority configured
        self.denied("release_publishing_not_configured", self.executor.challenge, {"kind": "release"}, "approve")
        self.denied("release_publishing_not_configured", self.executor.release_prepare, COMMIT, VERSION)


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class TrustAndConsoleTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = Path(t.name)
        os.chmod(self.tmp, 0o700)
        self.package_key = release.new_private_key()
        self.keys = self.tmp / "keys.json"
        self.keys.write_text(json.dumps({"keys": [release.public_entry(self.package_key)]}))
        self.addendum = self.tmp / "addendum.json"
        self.auth = Authority(self.tmp / "state", run=lambda *a, **k: (1, ""), http=lambda *a, **k: (200, b'{"permissions": {"push": true}}'), build_prefix=["env"])
        self.out = []

    def trusted(self):
        return release.load_trusted_keys(self.keys, addendum=self.addendum)

    def test_console_init_creates_the_key_and_makes_the_machine_trust_it_only_then(self):
        self.assertEqual(len(self.trusted()), 1)
        self.assertEqual(release_console.init(self.auth, self.addendum, out=self.out.append), 0)
        mine = self.auth.key_entry()["key_id"]
        self.assertIn(mine, self.trusted())
        self.assertEqual(len(self.trusted()), 2)
        self.assertEqual(release_console.init(self.auth, self.addendum, out=self.out.append), 0)          # idempotent
        self.assertEqual(len(self.trusted()), 2)

    def test_a_revoked_key_stops_being_trusted_and_a_damaged_addendum_is_an_error(self):
        release_console.init(self.auth, self.addendum, out=self.out.append)
        mine = self.auth.key_entry()["key_id"]
        data = json.loads(self.addendum.read_text())
        data["revoked"] = [mine, release.public_entry(self.package_key)["key_id"]]
        self.addendum.write_text(json.dumps(data))
        with self.assertRaises(release.ReleaseError) as e:
            self.trusted()
        self.assertEqual(e.exception.code, "no_trusted_keys")                     # both revoked: nothing left
        self.addendum.write_text("{not json")
        with self.assertRaises(release.ReleaseError) as e:
            self.trusted()
        self.assertEqual(e.exception.code, "trusted_keys_addendum_unreadable")
        self.addendum.write_text(json.dumps({"keys": [], "revoked": [], "extra": 1}))
        with self.assertRaises(release.ReleaseError):
            self.trusted()
        self.addendum.write_text(json.dumps({"keys": [{"key_id": "0" * 16, "public": release.public_entry(self.package_key)["public"]}]}))
        with self.assertRaises(release.ReleaseError):
            self.trusted()

    def test_the_token_needs_a_terminal_and_a_well_formed_value(self):
        token = "github_pat_" + "D" * 30
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: token, is_tty=False, out=self.out.append), 2)
        self.assertFalse(self.auth.tokenfile.exists())
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: "bad token", is_tty=True, out=self.out.append), 1)
        self.assertFalse(self.auth.tokenfile.exists())
        self.assertEqual(release_console.set_token(self.auth, getpass_fn=lambda _p: token, is_tty=True, out=self.out.append), 0)
        self.assertTrue(self.auth.tokenfile.exists())
        self.assertNotIn(token, "\n".join(self.out))

    def test_status_never_prints_secrets(self):
        release_console.init(self.auth, self.addendum, out=self.out.append)
        self.auth.set_token("github_pat_" + "E" * 30)
        release_console.status(self.auth, self.addendum, keys_file=self.keys, out=self.out.append)
        text = "\n".join(self.out)
        self.assertNotIn("E" * 30, text)
        self.assertNotIn("PRIVATE", text)
        self.assertIn("trusts the signing key: yes", text)


@unittest.skipIf(tu is None, "needs the upgrade test harness")
class ConfigTests(unittest.TestCase):
    BASE = {"issuer": "https://x.us.auth0.com/", "approval_client_id": "c", "owner": "o", "device": "d", "owner_uid": 1000,
            "state_dir": "/tmp/s", "socket_path": "/tmp/s.sock"}

    def put(self, path, data):
        if path.exists():
            path.unlink()
        path.write_text(json.dumps(data))
        os.chmod(path, 0o600)

    def test_release_settings_live_in_their_own_file_and_installer_json_keeps_dev14s_shape(self):
        from stynpilot.service import ConfigError, InstallerConfig, build_authority
        with tempfile.TemporaryDirectory() as folder:
            main, side = Path(folder) / "installer.json", Path(folder) / "release.json"
            self.put(main, self.BASE)
            cfg = InstallerConfig.from_file(main)
            self.assertIsNone(cfg.release_build_user)
            self.assertIsNone(build_authority(cfg))                                   # default: publishing is off
            self.put(main, dict(self.BASE, build_user="x"))
            with self.assertRaises(ConfigError):
                InstallerConfig.from_file(main)
            self.put(main, self.BASE)
            for bad in ("root", "Bad Name", "", 5, "a;b"):
                self.put(side, {"build_user": bad})
                with self.assertRaises(ConfigError):
                    InstallerConfig.from_file(main)
            self.put(side, {"build_user": "no-such-account-xyz"})
            with self.assertRaises(ConfigError) as e:
                build_authority(InstallerConfig.from_file(main), state_dir=Path(folder))
            self.assertEqual(str(e.exception), "release_build_user_does_not_exist")


if __name__ == "__main__":
    unittest.main()
