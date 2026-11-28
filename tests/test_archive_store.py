import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stynpilot import archive_store, repo_archive, repo_git


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
