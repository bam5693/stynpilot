"""Real Git archives preserve all pinned refs without checking out source."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stynpilot import repo_archive, repo_git, repo_intake


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

    def test_readonly_intake_pins_origin_credentials_and_complete_fetch(self):
        scope = ("github", self.origin)
        target = self.root / "remote-archive"
        fixture = "synthetic_read_only_credential"
        calls = []

        def offline_https(repository, config, deadline, action, *args):
            calls.append(action)
            self.assertEqual(os.fstat(config).st_mode & 0o777, 0o600)
            self.assertFalse((repository.parent / "auth.conf").exists())
            self.assertIn(f'[http "{self.origin}"]'.encode(), os.pread(config, 4096, 0))
            self.assertNotIn(fixture, repr(args))
            remote = args.index("--") + 1
            self.assertEqual(args[remote], self.origin)
            mapped = (*args[:remote], str(self.bare), *args[remote + 1:])
            return self.git(repository, action, *mapped).encode("utf-8")

        with patch.object(repo_intake, "_git", side_effect=offline_https):
            receipt = repo_intake.intake_snapshot(target, scope, scope, self.refs, scratch=self.root,
                                                  credential=("x-access-token", fixture), default_head="refs/heads/main")
        self.assertEqual(calls, ["ls-remote", "ls-remote", "fetch", "ls-remote", "ls-remote"])
        self.assertEqual(receipt["refs"], self.refs)
        comparison = self.root / "remote-comparison.git"
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_binding_invalid"):
            repo_archive.restore_comparison(target, comparison, *scope, self.refs, receipt["bundle_sha256"],
                                            default_head="refs/heads/review/historical")
        repo_archive.restore_comparison(target, comparison, *scope, self.refs, receipt["bundle_sha256"],
                                        default_head="refs/heads/main")
        self.assertEqual(self.git(comparison, "symbolic-ref", "HEAD"), "refs/heads/main")
        self.assertFalse(list(self.root.glob("stynpilot-intake-*")))
        self.assertNotIn(fixture, (target / "manifest.json").read_text())
        self.assertEqual(set(self.refs), set(self.git(self.bare, "for-each-ref", "--format=%(refname)").splitlines()))

    def test_credential_is_an_inherited_sealed_fd_closed_on_interruption(self):
        origin = "https://gitlab.com/group/example.git"
        fixture = "synthetic_read_only_credential"
        with self.assertRaises(KeyboardInterrupt):
            with repo_intake._credential_config("gitlab", origin, ("oauth2", fixture)) as fd:
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                self.assertTrue(seals & fcntl.F_SEAL_WRITE)
                self.assertFalse(os.get_inheritable(fd))
                with self.assertRaises(PermissionError):
                    os.write(fd, b"changed")
                command = ["/usr/bin/git", "-c", f"include.path=/proc/self/fd/{fd}",
                           "config", "--get-urlmatch", "http.extraHeader", origin + "/info/refs"]
                output = subprocess.check_output(command, pass_fds=(fd,), cwd=self.root, env=repo_git._ENV)
                self.assertEqual(output.strip(), b"Authorization: Basic " + base64.b64encode(("oauth2:" + fixture).encode()))
                refused = subprocess.run([*command[:-1], "https://gitlab.com/group/other.git"], pass_fds=(fd,),
                                         cwd=self.root, env=repo_git._ENV, capture_output=True, check=False)
                self.assertEqual(refused.returncode, 1)
                self.assertEqual(refused.stdout, b"")
                raise KeyboardInterrupt
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_readonly_intake_rejects_wrong_source_and_ref_drift(self):
        scope = ("github", self.origin)
        target = self.root / "refused-archive"
        with patch.object(repo_intake, "_git") as transport:
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_intake_scope_mismatch"):
                repo_intake.intake_snapshot(target, scope, ("github", "https://github.com/else/other.git"),
                                            self.refs, scratch=self.root, default_head="refs/heads/main")
            transport.assert_not_called()
        rows = "\n".join(f"{oid}\t{name}" for name, oid in self.refs.items()).encode()
        head = f"ref: refs/heads/main\tHEAD\n{self.refs['refs/heads/main']}\tHEAD\n".encode()
        with patch.object(repo_intake, "_git", side_effect=[rows, head, b"", rows.split(b"\n", 1)[0]]) as transport:
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_refs_changed"):
                repo_intake.intake_snapshot(target, scope, scope, self.refs, scratch=self.root,
                                            default_head="refs/heads/main")
            self.assertEqual(transport.call_count, 4)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob("stynpilot-intake-*")))

    def test_archive_publication_preserves_a_destination_created_during_verification(self):
        target = self.root / "contended-archive"
        verify = repo_archive._verify_bundle

        def complete_verification(bundle, refs):
            self.assertFalse(target.exists())
            verify(bundle, refs)
            target.mkdir()
            (target / "owner-file").write_text("preserve me")

        with patch.object(repo_archive, "_verify_bundle", side_effect=complete_verification):
            with self.assertRaises(FileExistsError):
                repo_archive.capture_prepared(self.bare, target, "github", self.origin, self.refs)
        self.assertEqual(["owner-file"], [part.name for part in target.iterdir()])
        self.assertFalse(list(self.root.glob(".stynpilot-archive-*")))

    def test_interrupted_archive_is_invisible_and_clean_retry_completes(self):
        target = self.root / "interrupted-archive"
        with patch.object(repo_archive, "_verify_bundle", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                repo_archive.capture_prepared(self.bare, target, "github", self.origin, self.refs)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob(".stynpilot-archive-*")))
        receipt = repo_archive.capture_prepared(self.bare, target, "github", self.origin, self.refs)
        self.assertEqual(json.loads((target / "manifest.json").read_bytes()), receipt)
