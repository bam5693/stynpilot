"""Real Git archives preserve all pinned refs without checking out source."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from stynpilot import repo_archive, repo_git


class RepositoryArchiveTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        working = self.root / "working"
        self.git(self.root, "init", "--quiet", "--initial-branch=main", str(working))
        (working / "README").write_text("base\n")
        self.git(working, "add", "README")
        self.git(working, "commit", "-qm", "base")
        self.base = self.git(working, "rev-parse", "HEAD")
        self.git(working, "branch", "review/historical")
        self.git(working, "tag", "-a", "v1", "-m", "original annotated tag")
        (working / "README").write_text("second\n")
        self.git(working, "commit", "-qam", "second")
        self.bare = self.root / "intake.git"
        self.git(self.root, "clone", "--quiet", "--bare", "--no-local", str(working), str(self.bare))
        self.refs = dict(line.split() for line in self.git(
            self.bare, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"
        ).splitlines())
        self.origin = "https://github.com/fixture/example.git"

    def git(self, cwd, *args):
        return subprocess.check_output(
            ["/usr/bin/git", "-c", "user.name=Archive Fixture", "-c", "user.email=fixture@example.invalid",
             "-C", str(cwd), *args], env=repo_git._ENV, text=True,
        ).strip()

    def test_complete_graph_branches_and_annotated_tag_preserved(self):
        for provider, origin in (("github", self.origin), ("gitlab", "https://gitlab.com/group/example.git"),
                                 ("forgejo", "https://forgejo.fixture.test/owner/example.git")):
            with self.subTest(provider=provider):
                archive, target = self.root / provider, self.root / (provider + ".git")
                receipt = repo_archive.capture_prepared(self.bare, archive, provider, origin, self.refs)
                self.assertEqual(self.refs, receipt["refs"])
                self.assertEqual({"provider": provider, "url": origin}, receipt["source"])
                restored = repo_archive.restore_comparison(
                    archive, target, provider, origin, self.refs, receipt["bundle_sha256"]
                )
                self.assertEqual(receipt, restored)
                self.assertFalse((target / "README").exists())
                self.assertEqual(self.refs["refs/tags/v1"], self.git(target, "rev-parse", "refs/tags/v1"))
                self.assertEqual(self.base, self.git(target, "rev-parse", "refs/tags/v1^{}"))
                self.assertEqual("2", self.git(target, "rev-list", "--count", "refs/heads/main"))
                self.assertEqual(self.base, self.git(target, "rev-parse", "refs/heads/review/historical"))

    def test_ref_drift_occupied_destination_and_untrusted_origin_refused(self):
        target = self.root / "archive"
        expected = dict(self.refs)
        expected.pop("refs/tags/v1")
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_refs_changed"):
            repo_archive.capture_prepared(self.bare, target, "github", self.origin, expected)
        self.assertFalse(target.exists())
        target.mkdir()
        (target / "keep").write_text("existing data")
        with self.assertRaises(FileExistsError):
            repo_archive.capture_prepared(self.bare, target, "github", self.origin, self.refs)
        self.assertEqual("existing data", (target / "keep").read_text())
        for origin in ("https://name:pass@github.com/fixture/example.git",
                       "https://other.example/fixture/example.git", self.origin + "?redirect=1"):
            with self.subTest(origin=origin), self.assertRaises(repo_archive.ArchiveError):
                repo_archive.source_origin("github", origin)

    def test_incremental_bundle_cannot_masquerade_as_complete_history(self):
        archive = self.root / "partial"
        archive.mkdir()
        bundle = archive / "source.bundle"
        self.git(self.bare, "bundle", "create", str(bundle), "refs/heads/main", "^" + self.base)
        data = bundle.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        expected = {"refs/heads/main": self.refs["refs/heads/main"]}
        manifest = {"format": 1, "source": {"provider": "github", "url": self.origin},
                    "refs": expected, "bundle_sha256": digest, "bundle_size": len(data)}
        (archive / "manifest.json").write_text(json.dumps(manifest))
        target = self.root / "partial.git"
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_git_refused"):
            repo_archive.restore_comparison(archive, target, "github", self.origin, expected, digest)
        self.assertFalse(target.exists())

    def test_corrupt_bundle_or_rewritten_manifest_cannot_authorize_itself(self):
        archive = self.root / "archive"
        receipt = repo_archive.capture_prepared(self.bare, archive, "github", self.origin, self.refs)
        target = self.root / "comparison.git"
        bundle = archive / "source.bundle"
        with bundle.open("r+b") as stream:
            stream.seek(-1, 2)
            byte = stream.read(1)
            stream.seek(-1, 2)
            stream.write(bytes([byte[0] ^ 1]))
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_bundle_digest_mismatch"):
            repo_archive.restore_comparison(archive, target, "github", self.origin, self.refs, receipt["bundle_sha256"])
        self.assertFalse(target.exists())
        receipt["bundle_sha256"] = "a" * 64
        (archive / "manifest.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
            repo_archive.restore_comparison(archive, target, "github", self.origin, self.refs, "b" * 64)
        self.assertFalse(target.exists())
