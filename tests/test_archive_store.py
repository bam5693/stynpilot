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
        git("-C", str(working), "add", ".")
        git("-C", str(working), "commit", "-qm", "old")
        self.old = git("-C", str(working), "rev-parse", "HEAD")
        (working / "README").write_text("new\n")
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
        self.assertEqual(self.store.compare("scope.chatgpt", archive_id, self.old, archive_id, self.new)["total"], 1)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_path_invalid"):
            self.store.file("scope.chatgpt", archive_id, self.old, "../grant.json")

    def test_capacity_binding_and_startup_recovery(self):
        with patch.object(archive_store, "MAX_RETAINED", 4096), self.assertRaisesRegex(
                     repo_archive.ArchiveError, "archive_store_capacity"):
            self.store.adopt(self.archive, **self.binding)
        unfinished = self.store.path / ".pending-abcd1234"
        unfinished.mkdir(mode=0o700)
        (unfinished / "partial").write_text("interrupted")
        self.assertFalse(self.store.list("scope.chatgpt")["archives"])
        self.store.reconcile()
        self.assertFalse(unfinished.exists())
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
            self.store.adopt(self.archive, **{**self.binding, "manifest_sha256": "0" * 64})
        first = self.store.adopt(self.archive, **self.binding)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_already_adopted"):
            self.store.adopt(self.archive, **self.binding)
        self.assertEqual(self.store.list("scope.chatgpt")["archives"], [first])
