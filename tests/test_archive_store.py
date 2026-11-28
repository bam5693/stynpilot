from contextlib import contextmanager
import hashlib
import json
from io import BytesIO
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from stynpilot import archive_publication, archive_store, managed_activity, projects_helper, repo_archive, repo_git, root_restore
from stynpilot.broker import archive_jobs, repository_auth
from stynpilot.server.clients import ARCHIVE_AUTHORITY, ClientDenied, RevocationFile
from test_repository_auth import FakeGitLab, REQUEST, TARGET


class StoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.store = archive_store.Store(self.root / "store")
        working = self.root / "working"

        def git(*args):
            return subprocess.check_output(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                            "-C", str(self.root), *args], env=repo_git._ENV).decode().strip()

        git("init", "-q", "-b", "main", str(working))
        (working / "README").write_text("old\n")
        (working / "legacy.txt").write_text("name=old setup\npassword=fixture-historical-only\n")
        (working / ".env").write_text("fixture-hidden-value\n")
        cloud = working / "example/.aws"
        cloud.mkdir(parents=True)
        (cloud / "profile").write_text("fixture-aws-profile\n")
        git("-C", str(working), "add", ".")
        git("-C", str(working), "commit", "-qm", "old")
        self.old = git("-C", str(working), "rev-parse", "HEAD")
        (working / "README").write_text("new\n")
        (working / "legacy.txt").write_text("name=new setup\n")
        git("-C", str(working), "commit", "-qam", "new")
        self.new = git("-C", str(working), "rev-parse", "HEAD")
        bare = self.root / "intake.git"
        git("clone", "--quiet", "--bare", str(working), str(bare))
        self.archive = self.root / "archive"
        result = repo_archive.capture_prepared(bare, self.archive, "github", "https://github.com/fixture/archive.git",
                                               {"refs/heads/main": self.new}, default_head="refs/heads/main")
        self.binding = {"manifest_sha256": hashlib.sha256((self.archive / "manifest.json").read_bytes()).hexdigest(),
                        "bundle_sha256": result["bundle_sha256"], "clients": ["scope.chatgpt"]}

    def test_reconcile_provisions_a_private_empty_capture_mount(self):
        self.assertFalse(self.store.path.exists())
        self.store.reconcile()
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.store.list("scope.chatgpt"), {"archives": []})

    def test_bounded_inspection_and_cross_client_refusal(self):
        self.assertEqual(self.store.list("scope.chatgpt"), {"archives": []})
        archive_id = self.store.adopt(self.archive, **self.binding)["archive_id"]
        self.assertEqual(self.store.list("scope.other"), {"archives": []})
        for method, args in ((self.store.refs, (archive_id,)), (self.store.file, (archive_id, self.new, "README")),
                             (self.store.compare, (archive_id, self.old, archive_id, self.new))):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
                method("scope.other", *args)
        self.assertEqual(self.store.history("scope.chatgpt", archive_id, self.new, 0, 1)["items"],
                         [{"commit": self.new, "parents": [self.old]}])
        self.assertEqual(self.store.file("scope.chatgpt", archive_id, self.old, "README")["text"], "old\n")
        self.assertEqual(self.store.compare("scope.chatgpt", archive_id, self.old, archive_id, self.new)["total"], 2)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_path_invalid"):
            self.store.file("scope.chatgpt", archive_id, self.old, "../grant.json")

    def test_broker_stream_under_exact_client_and_digest(self):
        raw = (self.archive / "manifest.json").read_bytes()
        header = len(raw).to_bytes(4, "big") + raw
        bundle = (self.archive / "source.bundle").read_bytes()
        binding = {key: value for key, value in self.binding.items() if key != "clients"}
        for data, code in ((header + bundle[:-1], "archive_bundle_digest_mismatch"),
                           (header + bundle + b"x", "archive_bundle_limit"),
                           (header[:7], "archive_manifest_invalid"),
                           ((repo_archive.MAX_MANIFEST + 1).to_bytes(4, "big"), "archive_manifest_limit")):
            with self.subTest(code=code), self.assertRaisesRegex(repo_archive.ArchiveError, code):
                self.store.adopt_stream(BytesIO(data), client="scope.chatgpt", **binding)
            self.assertEqual(self.store.list("scope.chatgpt")["archives"], [])
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
            self.store.adopt_stream(BytesIO(header + bundle), client="scope.chatgpt",
                                    **{**binding, "manifest_sha256": "0" * 64})
        def revoke():
            raise repo_archive.ArchiveError("synthetic_revocation")

        with self.assertRaisesRegex(repo_archive.ArchiveError, "synthetic_revocation"):
            self.store.adopt_stream(BytesIO(header + bundle), client="scope.chatgpt", publication_guard=revoke, **binding)
        self.assertEqual(self.store.list("scope.chatgpt"), {"archives": []})
        adopted = self.store.adopt_stream(BytesIO(header + bundle), client="scope.chatgpt", **binding)
        self.assertEqual(self.store.list("scope.chatgpt")["archives"], [adopted])
        self.assertEqual(self.store.list("scope.other")["archives"], [])
        assert self.store.history("scope.chatgpt", adopted["archive_id"], self.new)["items"][0]["parents"] == [self.old]

    def test_private_archive_adoption_has_separate_revocable_read_scope(self):
        raw = (self.archive / "manifest.json").read_bytes()
        encoded = len(raw).to_bytes(4, "big") + raw + (self.archive / "source.bundle").read_bytes()
        binding = {key: value for key, value in self.binding.items() if key != "clients"}
        access = {"repository": "project", "authorization_profile": "e" * 64}
        source = {"provider": "github", "url": "https://github.com/fixture/archive.git"}
        allowed = True
        def authorizer(client, registered, origin):
            return allowed and client == "scope.chatgpt" and registered == access and origin == source

        store = archive_store.Store(self.store.path, private_read=authorizer)
        adopted = store.adopt_stream(BytesIO(encoded), client="scope.chatgpt", repository_access=access, **binding)
        self.assertEqual(store.list("scope.chatgpt")["archives"], [adopted])
        self.assertEqual(store.list("scope.other")["archives"], [])
        self.assertEqual(self.store.list("scope.chatgpt")["archives"], [])
        old_schema = json.loads((store.path / adopted["archive_id"] / "grant.json").read_bytes())
        self.assertNotIn("clients", old_schema)
        with patch.object(store, "private_read", side_effect=[True, False]):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_read_authorization_changed"):
                store.inspect(store.history, "scope.chatgpt", adopted["archive_id"], self.new)
        allowed = False
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
            store.history("scope.chatgpt", adopted["archive_id"], self.new)
        self.assertTrue((store.path / adopted["archive_id"] / "archive" / "source.bundle").is_file())

    def _publication_fixture(self, directory):
        directory.mkdir()
        now = [100]
        provider = FakeGitLab()
        provider.ready = True
        auth = repository_auth.Store(directory, {"fixture": TARGET}, provider=repository_auth.GitLab(provider),
                                     clock=lambda: now[0])
        auth.apply("repository_authorize", "chatgpt", "fixture", ["read", "fetch"], 1, REQUEST)
        auth.connect(REQUEST, False)
        now[0] += 5
        auth.connect(REQUEST, True)
        lease = auth.begin_fetch("chatgpt", "fixture", seconds=60)
        helper = Mock()
        helper.call.return_value = {"active": True}
        jobs = archive_jobs.Jobs(directory, auth, helper, "/home/fixture", transport=Mock(),
                                 receive_fence=Mock(), clock=lambda: now[0])
        job = "d" * 32
        jobs._folder(job).mkdir(mode=0o700)
        jobs._write(job, "job.json", {"job_id": job, "client": "chatgpt", "state": "running",
                                     "deadline": lease.expires})
        jobs._active = (job, lease, Mock())
        with root_restore.admission(directory, exclusive=True):
            managed_activity.claim(directory, archive_jobs.KIND, job)
        binding = {key: value for key, value in self.binding.items() if key != "clients"}
        dispatch = jobs._dispatch(job, lease, binding, {"repository": "fixture", "authorization_profile": "e" * 64})

        def cancel():
            with root_restore.admission(directory, exclusive=True):
                jobs.cancel("chatgpt", job)

        def revoke():
            auth.apply("repository_revoke", "chatgpt", "fixture", [], 0, "e" * 64)

        @contextmanager
        def guard():
            with archive_publication.lock(dispatch):
                if not (dispatch / "permit.json").is_file():
                    raise repo_archive.ArchiveError("archive_transfer_authority_missing")
                yield

        raw = (self.archive / "manifest.json").read_bytes()
        frame = len(raw).to_bytes(4, "big") + raw + (self.archive / "source.bundle").read_bytes()
        return dispatch, cancel, revoke, guard, frame, binding

    def test_cancel_and_revoke_after_staging_prevent_publication(self):
        sync = archive_store._sync_tree
        for mode in ("cancel", "revoke"):
            with self.subTest(mode=mode):
                dispatch, cancel, revoke, guard, frame, binding = self._publication_fixture(self.root / mode)
                action = cancel if mode == "cancel" else revoke

                def withdraw(path):
                    sync(path)
                    action()
                    self.assertFalse((dispatch / "permit.json").exists())

                with (patch.object(archive_store, "_sync_tree", side_effect=withdraw) as staged,
                      self.assertRaisesRegex(repo_archive.ArchiveError, "archive_transfer_authority_missing")):
                    self.store.adopt_stream(BytesIO(frame), client="scope.chatgpt", publication_guard=guard, **binding)
                staged.assert_called_once()
                self.assertFalse((self.store.path / binding["manifest_sha256"][:32]).exists())
                self.assertFalse(any(path.name.startswith(".pending-") for path in self.store.path.iterdir()))

    def test_cancel_and_revoke_cannot_race_atomic_publication(self):
        dispatch, cancel, revoke, guard, frame, binding = self._publication_fixture(self.root / "busy")
        publish = repo_archive._publish_directory

        def finish(staged, target):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_publication_busy"):
                cancel()
            with self.assertRaisesRegex(repository_auth.AuthorizationError, "archive_publication_busy"):
                revoke()
            self.assertTrue((dispatch / "permit.json").is_file())
            return publish(staged, target)

        with patch.object(repo_archive, "_publish_directory", side_effect=finish) as committed:
            adopted = self.store.adopt_stream(BytesIO(frame), client="scope.chatgpt", publication_guard=guard, **binding)
        committed.assert_called_once()
        revoke()
        self.assertFalse((dispatch / "permit.json").exists())
        self.assertTrue((self.store.path / adopted["archive_id"] / "archive" / "source.bundle").is_file())

    def test_global_revocation_is_ordered_with_the_final_publish(self):
        raw = (self.archive / "manifest.json").read_bytes()
        frame = len(raw).to_bytes(4, "big") + raw + (self.archive / "source.bundle").read_bytes()
        digests = {key: value for key, value in self.binding.items() if key != "clients"}
        revocations = RevocationFile(self.root / "owner" / "revoked-clients.json")
        revocations.provision()
        revocations.enable_archive_fence()
        authority = revocations.path.parent / ARCHIVE_AUTHORITY
        client = "scope.chatgpt"

        def adopt():
            return self.store.adopt_stream(BytesIO(frame), client=client, **digests,
                                           publication_guard=lambda: projects_helper._archive_client_publication(authority, client))

        sync = archive_store._sync_tree

        def revoke_after_stage(path):
            sync(path)
            revocations.set_revoked(client, True)

        with (patch.object(archive_store, "_sync_tree", side_effect=revoke_after_stage),
              self.assertRaisesRegex(repo_archive.ArchiveError, "archive_client_authorization_withdrawn")):
            adopt()
        self.assertEqual(self.store.list(client)["archives"], [])
        revocations.set_revoked(client, False)
        publish = repo_archive._publish_directory

        def revoke_during_publish(source, target):
            with self.assertRaisesRegex(ClientDenied, "archive_publication_busy"):
                RevocationFile(revocations.path).set_revoked(client, True)
            return publish(source, target)

        with patch.object(repo_archive, "_publish_directory", side_effect=revoke_during_publish):
            archive_id = adopt()["archive_id"]
        revocations.set_revoked(client, True)
        self.assertTrue((self.store.path / archive_id).is_dir())
        revocations._write([])
        self.assertIn(client, RevocationFile(revocations.path).revoked())

    def test_private_transport_cross_checks_worker_frame_and_fences_before_return(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from stynpilot.broker.archive_transport import Transport, capture_unit
        from stynpilot.broker.lab import LabError

        raw = (self.archive / "manifest.json").read_bytes()
        frame = len(raw).to_bytes(4, "big") + raw + (self.archive / "source.bundle").read_bytes()
        source = ("github", "https://github.com/fixture/archive.git")
        refs = {"refs/heads/main": self.new}
        with BytesIO(frame) as stream:
            binding = Transport._verify_frame(stream, source, refs, "refs/heads/main")
            self.assertEqual(stream.tell(), 0)
            self.assertEqual(binding["manifest_sha256"], self.binding["manifest_sha256"])
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
                Transport._verify_frame(stream, ("gitlab", "https://gitlab.com/team/fixture.git"),
                                        refs, "refs/heads/main")

        source = ("gitlab", "https://gitlab.com/team/fixture.git")
        job = "a" * 32
        fixture = "synthetic_read_only_credential"
        fence = Mock()
        runner = Mock(return_value=SimpleNamespace(returncode=1))
        with tempfile.TemporaryFile(dir=self.root) as file:
            args = dict(job=job, source=source, refs=refs, head="refs/heads/main",
                        credential=("oauth2", fixture), stream=file)
            driver = Transport(run=runner, fence=fence)
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_intake_refused"):
                driver.capture(**args)
            fence.stop.assert_called_once_with(job)
            command, = runner.call_args.args
            self.assertIn("--unit=" + capture_unit(job), command)
            self.assertNotIn(fixture, repr(command))
            self.assertNotIn(fixture, repr(runner.call_args.kwargs["env"]))
            fence.stop.side_effect = LabError("lab_quiescence_unverified")
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_intake_quiescence_unverified"):
                driver.capture(**args)

    def test_deckplay_checkout_preview_is_bound_and_nonmutating(self):
        adopted = self.store.adopt(self.archive, **self.binding)
        archive_id = adopted["archive_id"]
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_checkout_source_mismatch"):
            self.store.deckplay_checkout_preview("scope.chatgpt", archive_id, "refs/heads/main", self.new)
        with patch.object(archive_store, "_DECKPLAY_SOURCE", adopted["source"]):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
                self.store.deckplay_checkout_preview("scope.other", archive_id, "refs/heads/main", self.new)
            for ref, commit in (("refs/heads/main", self.old), ("refs/heads/other", self.new),
                                ("refs/tags/main", self.new), ("refs/heads/main", "HEAD")):
                with self.subTest(ref=ref, commit=commit), self.assertRaisesRegex(
                        repo_archive.ArchiveError, "archive_checkout_ref_mismatch"):
                    self.store.deckplay_checkout_preview("scope.chatgpt", archive_id, ref, commit)
            preview = self.store.deckplay_checkout_preview("scope.chatgpt", archive_id, "refs/heads/main", self.new)
            self.assertEqual(preview["workspace"], "deckplay-hq")
            self.assertEqual(preview["bundle_sha256"], adopted["bundle_sha256"])
            self.assertEqual(preview["entry_count"], 4)
            self.assertEqual(preview["protected_path_count"], 2)
            self.assertEqual(preview["nonregular_entry_count"], 0)
            self.assertFalse(preview["checkout_authorized"])
            self.assertTrue(preview["requires_content_review"])
            self.assertNotIn("paths", preview)
            self.assertFalse((self.root / "deckplay-hq").exists())
            bundle = self.store.path / archive_id / "archive" / "source.bundle"
            with bundle.open("ab") as stream:
                stream.write(b"x")
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_bundle_digest_mismatch"):
                self.store.deckplay_checkout_preview("scope.chatgpt", archive_id, "refs/heads/main", self.new)

    def test_deckplay_transfer_bundle_is_self_contained_and_ephemeral(self):
        adopted = self.store.adopt(self.archive, **self.binding)
        archive_id = adopted["archive_id"]
        with patch.object(archive_store, "_DECKPLAY_SOURCE", adopted["source"]):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
                with self.store._deckplay_transfer_bundle("scope.other", archive_id, "refs/heads/main", self.new):
                    self.fail("unapproved client")
            with self.store._deckplay_transfer_bundle("scope.chatgpt", archive_id, "refs/heads/main", self.new) as (bundle, receipt):
                self.assertEqual(receipt["source_bundle_sha256"], adopted["bundle_sha256"])
                self.assertEqual(receipt["commit"], self.new)
                self.assertEqual(repo_archive._bundle_digest(bundle), (receipt["bundle_sha256"], receipt["bundle_size"]))
                restored = self.root / "isolated.git"
                repo_archive._restore_bundle(bundle, restored, {"refs/heads/main": self.new}, "refs/heads/main")
                self.assertEqual(repo_archive._git(restored, "rev-parse", "HEAD").decode().strip(), self.new)
                self.assertEqual(repo_archive._git(restored, "rev-parse", "HEAD^").decode().strip(), self.old)
            self.assertFalse(bundle.exists())
            self.assertEqual(self.store.list("scope.chatgpt")["archives"], [adopted])

    def test_capacity_binding_and_startup_recovery(self):
        with patch.object(archive_store, "MAX_RETAINED", 4096), self.assertRaisesRegex(
                     repo_archive.ArchiveError, "archive_store_capacity"):
            self.store.adopt(self.archive, **self.binding)
        unfinished = self.store.path / ".pending-abcd1234"
        unfinished.mkdir(mode=0o700)
        (unfinished / "partial").write_text("interrupted")
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_recovery_required"):
            self.store.list("scope.chatgpt")
        self.store.reconcile()
        self.assertFalse(unfinished.exists())
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
            self.store.adopt(self.archive, **{**self.binding, "manifest_sha256": "0" * 64})
        first = self.store.adopt(self.archive, **self.binding)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_already_adopted"):
            self.store.adopt(self.archive, **self.binding)
        self.assertEqual(self.store.list("scope.chatgpt")["archives"], [first])

    def test_historical_file_redaction_preserves_original_blob(self):
        adopted = self.store.adopt(self.archive, **self.binding)
        archive_id = adopted["archive_id"]
        result = self.store.file("scope.chatgpt", archive_id, self.old, "legacy.txt")
        self.assertEqual(result["redacted"], {"secret-assignment": 1})
        self.assertIn("name=old setup", result["text"])
        self.assertNotIn("fixture-historical-only", result["text"])
        bare = self.store.path / archive_id / "comparison.git"
        self.assertIn(b"fixture-historical-only", repo_archive._git(bare, "cat-file", "blob", self.old + ":legacy.txt"))
        archive_paths = {row["path"] for row in self.store.tree("scope.chatgpt", archive_id, self.old)["items"]}
        self.assertEqual(archive_paths, {"README", "legacy.txt"})
        for path in (".env", "example/.aws/profile"):
            with self.subTest(path=path), self.assertRaisesRegex(repo_archive.ArchiveError, "archive_protected_path"):
                self.store.file("scope.chatgpt", archive_id, self.old, path)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
            self.store.file("scope.other", archive_id, self.old, "legacy.txt")

    def test_recovery_refusal_and_over_capacity_close_read_routes(self):
        archive_id = self.store.adopt(self.archive, **self.binding)["archive_id"]
        pending = self.store.path / ".pending-conflict"
        pending.symlink_to(self.archive)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_store_untrusted"):
            self.store.reconcile()
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_recovery_required"):
            self.store.refs("scope.chatgpt", archive_id)
        self.assertTrue((self.archive / "source.bundle").is_file())
        pending.unlink()
        with patch.object(archive_store, "MAX_RETAINED", 4096):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_store_capacity"):
                self.store.reconcile()
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_store_capacity"):
                self.store.refs("scope.chatgpt", archive_id)
        self.assertEqual(self.store.refs("scope.chatgpt", archive_id)["total"], 1)
