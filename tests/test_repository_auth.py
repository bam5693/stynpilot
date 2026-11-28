import json
from pathlib import Path
import tempfile
import unittest

from stynpilot import backup
from stynpilot.broker import repository_auth as auth
from stynpilot.broker.executor import Runs
from stynpilot.ledger import InstallLedger


TARGET = {"provider": "gitlab", "origin": "https://gitlab.com/team/fixture.git", "application": "a" * 64, "principal": 938}
DEVICE = "synthetic-device-code-01234"
SECRET = "synthetic-access-value-01234"
REFRESH = "synthetic-refresh-value-01234"
REQUEST = "f" * 64


class FakeGitLab:
    def __init__(self):
        self.ready = False
        self.principal = TARGET["principal"]
        self.scope = ["read_repository"]
        self.refresh_count = 0
        self.fail_refresh = False

    def __call__(self, endpoint, data=None, bearer=None):
        if endpoint == "/oauth/authorize_device":
            assert data == {"client_id": TARGET["application"], "scope": "read_repository"}
            return 200, {"device_code": DEVICE, "verification_uri_complete": "https://gitlab.com/oauth/device?user_code=EXAMPLE-123",
                         "user_code": "EXAMPLE-123", "interval": 5, "expires_in": 300}
        if endpoint == "/oauth/token/info":
            assert bearer == SECRET + str(self.refresh_count)
            return 200, {"resource_owner_id": self.principal, "scope": self.scope, "application": {"uid": TARGET["application"]}}
        assert endpoint == "/oauth/token"
        if "refresh_token" in data:
            assert data["refresh_token"] == REFRESH + str(self.refresh_count)
            self.refresh_count += 1
            if self.fail_refresh:
                raise auth.AuthorizationError("repository_provider_unavailable")
        else:
            assert data["device_code"] == DEVICE
            if not self.ready:
                return 400, {"error": "authorization_pending"}
        return 200, {"access_token": SECRET + str(self.refresh_count), "refresh_token": REFRESH + str(self.refresh_count),
                     "expires_in": 100, "token_type": "bearer"}


class RepositoryAuthTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.now = 100
        self.provider = FakeGitLab()
        self.store = self.reopen()

    def reopen(self):
        return auth.Store(self.root, {"fixture": TARGET}, provider=auth.GitLab(self.provider), clock=lambda: self.now)

    def grant(self):
        return self.store.apply("repository_authorize", "chatgpt", "fixture", ["read"], 1, REQUEST)

    def connect(self):
        self.grant()
        start = self.store.connect(REQUEST, False)
        self.assertIn("EXAMPLE-123", start["url"])
        self.assertNotIn(DEVICE, repr(start))
        self.now += 5
        self.assertEqual(self.store.connect(REQUEST, True)["state"], "waiting")
        self.now += 5
        self.provider.ready = True
        self.assertEqual(self.store.connect(REQUEST, True), {"state": "connected"})

    def test_exact_authorization_restart_renewal_and_expiry(self):
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_grant_unavailable"):
            self.store.connect(REQUEST, False)
        self.connect()
        self.store = self.reopen()
        checked = []

        def consume(source, credential):
            self.assertEqual(source, ("gitlab", TARGET["origin"]))
            checked.append(credential[1])
            return {"readable": True}

        self.assertEqual(self.store.use("chatgpt", "fixture", "read", consume), {"readable": True})
        self.now += 45
        self.assertEqual(self.store.use("chatgpt", "fixture", "read", consume), {"readable": True})
        self.assertEqual(checked, [SECRET + "0", SECRET + "1"])
        self.assertEqual(self.provider.refresh_count, 1)
        status = self.store.status("chatgpt")
        self.assertNotIn(SECRET, repr(status))
        self.assertNotIn(REFRESH, repr(status))
        self.assertEqual((self.store.root / "grants.json").stat().st_mode & 0o777, 0o600)
        self.now += 86400
        self.assertEqual(self.store.status("chatgpt")["grants"], [])
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_grant_unavailable"):
            self.store.use("chatgpt", "fixture", "read", consume)

    def test_maintenance_removes_expired_tokens_and_device_codes_from_storage(self):
        self.store.purge_expired()
        self.assertFalse(self.store.root.exists())
        self.connect()
        second = "b" * 64
        self.store.apply("repository_authorize", "other", "fixture", ["fetch"], 2, second)
        self.store.connect(second, False)
        self.now += 301
        self.store.purge_expired()
        data = (self.store.root / "grants.json").read_text()
        self.assertNotIn(DEVICE, data)
        self.assertIn(REFRESH, data)  # renewal remains authorized for this grant
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_sign_in_expired"):
            self.store.connect(second, True)
        self.now += 86400
        self.store.purge_expired()
        data = (self.store.root / "grants.json").read_text()
        self.assertNotIn(SECRET, data)
        self.assertNotIn(REFRESH, data)
        self.assertEqual(self.reopen().status("chatgpt")["grants"], [])

    def test_root_backup_of_an_active_grant_cannot_restore_it_after_revocation(self):
        self.connect()
        Runs(self.root / "runs.sqlite3")
        InstallLedger(self.root / "installs.sqlite3")
        for name in backup.ROOT_TREES:
            (self.root / name).mkdir(mode=0o700)
        archive = self.root / "before-revocation.tar"
        backup.make_backup(self.root, archive, kind="root")
        self.store.apply("repository_revoke", "chatgpt", "fixture", [], 0, REQUEST)
        _, contents = backup.read_backup(archive, expected_kind="root")
        self.assertNotIn("repository-authorization/grants.json", contents)
        self.assertTrue(all(SECRET.encode() not in data and REFRESH.encode() not in data for data in contents.values()))
        destination = self.root / "restored"
        backup.restore_backup(archive, destination, kind="root")
        restored = auth.Store(destination, {"fixture": TARGET}, clock=lambda: self.now)
        self.assertEqual(restored.status("chatgpt")["grants"], [])

    def test_unspecified_repository_cross_client_push_suspend_and_revoke(self):
        self.connect()
        for client, repository, operation, code in (
            ("other", "fixture", "read", "repository_grant_unavailable"),
            ("chatgpt", "another", "read", "repository_provider_not_configured"),
            ("chatgpt", "fixture", "fetch", "repository_grant_unavailable"),
            ("chatgpt", "fixture", "push", "repository_operation_not_supported"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(auth.AuthorizationError, code):
                self.store.use(client, repository, operation, lambda *args: self.fail("credential used"))
        self.store.apply("repository_suspend", "chatgpt", "", [], 0, REQUEST)
        self.store = self.reopen()
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_access_suspended"):
            self.store.use("chatgpt", "fixture", "read", lambda *args: self.fail("credential used"))
        self.store.apply("repository_resume", "chatgpt", "", [], 0, REQUEST)
        self.store.apply("repository_revoke", "chatgpt", "fixture", [], 0, REQUEST)
        self.assertEqual(self.store.status("chatgpt")["grants"], [])
        self.assertNotIn(REFRESH, (self.store.root / "grants.json").read_text())

    def test_provider_identity_and_scope_refusal(self):
        for failures in ({"principal": 99}, {"scope": ["read_repository", "api"]}):
            with self.subTest(failures=failures):
                self.grant()
                self.store.connect(REQUEST, False)
                self.provider.principal, self.provider.scope = TARGET["principal"], ["read_repository"]
                vars(self.provider).update(failures)
                self.provider.ready = True
                self.now += 5
                with self.assertRaisesRegex(auth.AuthorizationError, "repository_provider_scope_mismatch"):
                    self.store.connect(REQUEST, True)
                row = self.store.status("chatgpt")["grants"][0]
                self.assertEqual(row["state"], "sign_in_failed")
                self.assertNotIn(SECRET, (self.store.root / "grants.json").read_text())

    def test_interrupted_sign_in_and_refresh_close_grant(self):
        self.grant()
        self.store.connect(REQUEST, False)
        self.store = self.reopen()
        self.now += 301
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_sign_in_expired"):
            self.store.connect(REQUEST, True)
        self.connect()
        self.now += 45
        self.provider.fail_refresh = True
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_provider_unavailable"):
            self.store.use("chatgpt", "fixture", "read", lambda *args: self.fail("credential used"))
        self.store = self.reopen()
        self.assertEqual(self.store.status("chatgpt")["grants"][0]["state"], "renewal_uncertain")
        self.assertNotIn(REFRESH, (self.store.root / "grants.json").read_text())

    def test_failed_reconnection_keeps_the_previous_valid_grant(self):
        self.connect()
        rerun = "b" * 64
        self.store.apply("repository_authorize", "chatgpt", "fixture", ["fetch"], 1, rerun)
        self.store.connect(rerun, False)
        self.now += 5
        self.provider.principal = 99
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_provider_scope_mismatch"):
            self.store.connect(rerun, True)
        self.assertTrue(self.store.use("chatgpt", "fixture", "read", lambda *_: True))
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_grant_unavailable"):
            self.store.use("chatgpt", "fixture", "fetch", lambda *_: self.fail("unapproved replacement used"))

    def test_configuration_refuses_shared_identity_and_wrong_origin(self):
        path = self.root / "repository-authorization.json"
        path.write_text(json.dumps({"fixture": TARGET, "second": TARGET}))
        path.chmod(0o600)
        with self.assertRaisesRegex(auth.AuthorizationError, "repository_provider_config_invalid"):
            auth.load_targets(path)
