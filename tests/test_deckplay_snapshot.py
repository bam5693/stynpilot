"""Snapshot tests: archived history stays outside the working bundle."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from stynpilot import archive_store, deckplay_snapshot, projects_helper, redact, repo_archive, repo_git, repo_push
from stynpilot.server.clients import RevocationFile
from unittest.mock import patch


class DeckPlaySnapshotTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.working = self.root / "working"
        self.working.mkdir()
        self.git("init", "-q", "-b", "main", "--template=")
        (self.working / "README").write_text("historical text\n")
        (self.working / ".env").write_text("synthetic historical value\n")
        self.git("add", ".")
        self.git("commit", "-qm", "historical")
        self.old = self.git("rev-parse", "HEAD")
        self.git("rm", "-q", ".env")
        (self.working / "README").write_text("reviewed text\n")
        self.git("commit", "-qam", "current")
        self.current = self.git("rev-parse", "HEAD")
        self.store = archive_store.Store(self.root / "store")

    def git(self, *args):
        return subprocess.check_output(
            ["/usr/bin/git", "-c", "user.name=Fixture", "-c",
             "user.email=fixture@example.invalid", *args],
            cwd=self.working, env=repo_git._ENV, text=True).strip()

    def adopt(self):
        bare = self.root / "intake.git"
        self.git("clone", "--bare", "-q", str(self.working), str(bare))
        commit = self.git("rev-parse", "HEAD")
        source = self.root / "archive"
        got = repo_archive.capture_prepared(
            bare, source, "github", repo_git.DECKPLAY_ORIGIN,
            {"refs/heads/main": commit}, default_head="refs/heads/main")
        result = self.store.adopt(source, manifest_sha256=hashlib.sha256(
            (source / "manifest.json").read_bytes()).hexdigest(),
            bundle_sha256=got["bundle_sha256"], clients=["scope.chatgpt"])
        return result["archive_id"], commit

    def test_admission_pins_migration_path_blob_and_tree_and_keeps_other_guards(self):
        path = "supabase/migrations/20261127001120_sync_catalog_with_inventory_and_public_profiles.sql"
        blob = b"select 1;\n"
        tree = "a" * 40
        hashes = {hashlib.sha256(path.encode()).hexdigest(): hashlib.sha256(blob).hexdigest()}
        self.assertFalse(archive_store._safe_path(path))
        with patch.object(deckplay_snapshot, "_REVIEWED_TREE", tree), \
                patch.object(deckplay_snapshot, "_MIGRATION_BLOBS", hashes):
            self.assertTrue(deckplay_snapshot.path_admitted(tree, path, blob))
            self.assertFalse(deckplay_snapshot.path_admitted("b" * 40, path, blob))
            self.assertFalse(deckplay_snapshot.path_admitted(tree, path, blob + b" "))
            self.assertFalse(deckplay_snapshot.path_admitted(tree, path.replace("catalog", "schema"), blob))
            self.assertFalse(deckplay_snapshot.path_admitted(tree, "supabase/migrations/.env", blob))
        self.assertIsNone(deckplay_snapshot.content_refusal(blob))
        self.assertEqual(deckplay_snapshot.content_refusal(b"password=synthetic-only"), "sensitive")

    def test_report_admission_is_exact_and_has_no_content_exemption(self):
        path = "tests/reports/2026-10-28-competitive-advantage-roadmap.md"
        tree = "a" * 40
        blob = b"password=synthetic-only"
        hashes = {hashlib.sha256(path.encode()).hexdigest(): hashlib.sha256(blob).hexdigest()}
        self.assertFalse(archive_store._safe_path(path))
        with (patch.object(deckplay_snapshot, "_REVIEWED_TREE", tree),
              patch.object(deckplay_snapshot, "_REPORT_BLOBS", hashes)):
            self.assertTrue(deckplay_snapshot.path_admitted(tree, path, blob))
            self.assertFalse(deckplay_snapshot.path_admitted("b" * 40, path, blob))
            self.assertFalse(deckplay_snapshot.path_admitted(tree, path, blob + b" "))
            self.assertFalse(deckplay_snapshot.path_admitted(tree, path.replace("roadmap", "notes"), blob))
            self.assertEqual(deckplay_snapshot.content_refusal(blob), "sensitive")

    def test_scanner_keeps_all_findings_except_the_pinned_reference_count(self):
        path = ".github/workflows/t4-synthetic-long-tracked-migration.yml"
        blob = b"      - 'tests/reports/2026-10-28-competitive-advantage-roadmap.md'\n"
        tree = "a" * 40
        self.assertEqual(redact.redact(blob.decode())[1], {"random-string": 1})
        pins = {hashlib.sha256(path.encode()).hexdigest(): (hashlib.sha256(blob).hexdigest(), 1)}
        with (patch.object(deckplay_snapshot, "_REVIEWED_TREE", tree),
              patch.object(deckplay_snapshot, "_WORKFLOW_REFERENCES", pins)):
            self.assertIsNone(deckplay_snapshot.content_refusal(blob, tree=tree, path=path))
            for value, source_tree, name in ((blob, "b" * 40, path), (blob, tree, path + ".txt"),
                                            (blob + b" ", tree, path), (blob + b"\npassword=fixture\n", tree, path)):
                self.assertEqual(deckplay_snapshot.content_refusal(value, tree=source_tree, path=name), "sensitive")
            with patch.object(redact, "redact", return_value=("", {"random-string": 1, "bearer": 1})):
                self.assertEqual(deckplay_snapshot.content_refusal(blob, tree=tree, path=path), "sensitive")

    def test_exact_tree_without_historical_objects(self):
        archive_id, commit = self.adopt()
        args = (self.store, "scope.chatgpt", archive_id, "refs/heads/main", commit)
        plan = deckplay_snapshot.review(*args)
        self.assertTrue(plan["eligible"])
        self.assertEqual(plan["source_commit"], self.current)
        self.assertEqual(plan["entry_count"], 1)
        self.assertEqual(plan["source_tree"], self.git("rev-parse", "HEAD^{tree}"))
        self.assertNotIn("paths", plan)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "snapshot_plan_changed"):
            with deckplay_snapshot.stage(*args, "0" * 64):
                self.fail("changed plan")
        with deckplay_snapshot.stage(*args, deckplay_snapshot.plan_digest(plan)) as (bundle, receipt):
            self.assertNotEqual(receipt["snapshot_commit"], self.current)
            bare = self.root / "snapshot-verifier.git"
            repo_archive._restore_bundle(bundle, bare,
                {deckplay_snapshot.REF: receipt["snapshot_commit"]}, deckplay_snapshot.REF)
            self.assertEqual(repo_archive._git(bare, "rev-parse", "HEAD^{tree}").decode().strip(), plan["source_tree"])
            self.assertEqual(repo_archive._git(bare, "rev-list", "--count", "HEAD").strip(), b"1")
            self.assertEqual(repo_archive._git(bare, "show", "HEAD:README"), b"reviewed text\n")
            with self.assertRaises(repo_archive.ArchiveError):
                repo_archive._git(bare, "cat-file", "-t", self.old)
        self.assertFalse(bundle.exists())
        self.assertEqual(self.store.history("scope.chatgpt", archive_id, commit)["items"][0]["parents"], [self.old])

    def test_materialization_rechecks_exact_reference_pins_with_tree_and_path(self):
        path = ".github/workflows/t4-synthetic-long-tracked-migration.yml"
        blob = b"      - 'tests/reports/2026-10-28-competitive-advantage-roadmap.md'\n"
        target = self.working / path
        target.parent.mkdir(parents=True)
        target.write_bytes(blob)
        self.git("add", ".")
        self.git("commit", "-qm", "test reference")
        archive_id, commit = self.adopt()
        tree = self.git("rev-parse", "HEAD^{tree}")
        pins = {hashlib.sha256(path.encode()).hexdigest(): (hashlib.sha256(blob).hexdigest(), 1)}
        projects = self.root / "StyNpilot-Projects"
        workspace = projects / "deckplay-hq"
        workspace.mkdir(parents=True)
        request = {"home": str(self.root), "projects": str(projects), "name": "deckplay-hq",
                   "client": "scope.chatgpt", "archive_id": archive_id, "ref": "refs/heads/main", "commit": commit}
        with (patch.object(deckplay_snapshot, "_REVIEWED_TREE", tree),
              patch.object(deckplay_snapshot, "_WORKFLOW_REFERENCES", pins),
              patch.object(projects_helper, "_deckplay_archive", return_value=self.store)):
            preview = projects_helper.op_deckplay_snapshot_preview(request)
            self.assertTrue(preview["plan"]["eligible"])
            bound = {**request, "plan_sha256": preview["plan_sha256"]}
            with patch.object(deckplay_snapshot, "_WORKFLOW_REFERENCES", {}):
                with self.assertRaisesRegex(projects_helper.Refuse, "snapshot_plan_changed"):
                    projects_helper._deckplay_checkout(bound, str(workspace))
            self.assertFalse(list(workspace.iterdir()))
            projects_helper._deckplay_checkout(bound, str(workspace))
            self.assertEqual((workspace / path).read_bytes(), blob)

    def test_environment_lookup_pin_accepts_only_the_one_reviewed_assignment(self):
        path = deckplay_snapshot._ENV_REFERENCE_PATH
        tree = "a" * 40
        blob = b"const password=process.env[passwordKey];\n"
        with (patch.object(deckplay_snapshot, "_REVIEWED_TREE", tree),
              patch.object(deckplay_snapshot, "_ENV_REFERENCE_BLOB", hashlib.sha256(blob).hexdigest())):
            self.assertEqual(redact.redact(blob.decode())[1], {"secret-assignment": 1})
            self.assertIsNone(deckplay_snapshot.content_refusal(blob, tree=tree, path=path))
            self.assertEqual(deckplay_snapshot.content_refusal(blob, tree=tree, path="other.js"), "sensitive")
            self.assertEqual(deckplay_snapshot.content_refusal(blob + b"password=fixture\n", tree=tree, path=path),
                             "sensitive")

    def test_stage_publication_keeps_original_ancestry_out_of_the_working_copy(self):
        archive_id, commit = self.adopt()
        args = (self.store, "scope.chatgpt", archive_id, "refs/heads/main", commit)
        source_plan = deckplay_snapshot.review(*args)
        digest = deckplay_snapshot.plan_digest(source_plan)
        with deckplay_snapshot.stage(*args, digest) as (bundle, work_receipt):
            work = self.root / "reviewed-work.git"
            snapshot = work_receipt["snapshot_commit"]
            repo_archive._restore_bundle(bundle, work, {deckplay_snapshot.REF: snapshot}, deckplay_snapshot.REF)
        source = self.root / "reviewed-content"
        source.write_bytes(b"reviewed edit\n")
        blob = repo_archive._git(work, "hash-object", "-w", "--no-filters", str(source)).decode().strip()
        repo_archive._git(work, "read-tree", snapshot)
        repo_archive._git(work, "update-index", "--add", "--cacheinfo", "100644," + blob + ",README")
        edited_tree = repo_archive._git(work, "write-tree").decode().strip()
        new_oid = repo_archive._git(work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                                   "commit-tree", edited_tree, "-p", snapshot, "-m", "reviewed edit").decode().strip()
        ref = "refs/heads/work/review"
        repo_archive._git(work, "update-ref", ref, new_oid)
        reviewed = self.root / "work.bundle"
        repo_archive._git(work, "bundle", "create", str(reviewed), ref)
        binding = (self.store, "scope.chatgpt", source_plan, digest, snapshot,
                   reviewed, hashlib.sha256(reviewed.read_bytes()).hexdigest(), ref, new_oid)
        remote = self.root / "staged-remote.git"
        self.git("clone", "-q", "--bare", str(self.working), str(remote))
        repo_archive._git(remote, "update-ref", ref, commit)
        with deckplay_snapshot.stage_publication(*binding, edited_tree, expected_remote=commit) as (publish, receipt):
            self.assertEqual(repo_archive._git(publish, "rev-parse", receipt["commit"] + "^").decode().strip(), commit)
            self.assertEqual(receipt["tree"], edited_tree)
            self.assertEqual(repo_archive._git(publish, "show", receipt["commit"] + ":README"), b"reviewed edit\n")
            self.assertEqual(repo_archive._git(publish, "cat-file", "-t", self.old).strip(), b"commit")
            with self.assertRaises(repo_archive.ArchiveError):
                repo_archive._git(work, "cat-file", "-t", self.old)
            self.assertEqual(receipt["origin"], repo_git.DECKPLAY_ORIGIN)
            self.assertEqual(receipt["expected_remote"], commit)
            outbound = self.root / "publish.bundle"
            repo_archive._git(publish, "bundle", "create", str(outbound), ref)
            repo_push.push_bundle(outbound.read_bytes(), "work/review", receipt["commit"], commit, "",
                                  remote=str(remote))
            self.assertEqual(repo_archive._git(remote, "rev-parse", ref).strip(), receipt["commit"].encode())
            self.assertEqual(repo_archive._git(remote, "rev-parse", "refs/heads/main").strip(), commit.encode())
        self.assertFalse(publish.exists())
        with self.assertRaisesRegex(repo_archive.ArchiveError, "snapshot_publication_review_required"):
            with deckplay_snapshot.stage_publication(*binding, "0" * 40, expected_remote=commit):
                self.fail("changed tree accepted")
        with self.assertRaisesRegex(repo_archive.ArchiveError, "snapshot_destination_not_ancestor"):
            with deckplay_snapshot.stage_publication(*binding, edited_tree, expected_remote=snapshot):
                self.fail("isolated snapshot accepted as a remote base")

    def test_owner_helper_materializes_exact_empty_workspace_only(self):
        archive_id, commit = self.adopt()
        projects = self.root / "StyNpilot-Projects"
        projects.mkdir()
        work = projects / "deckplay-hq"
        work.mkdir()
        request = {"home": str(self.root), "projects": str(projects),
                   "name": "deckplay-hq", "client": "scope.chatgpt", "archive_id": archive_id,
                   "ref": "refs/heads/main", "commit": commit}
        with patch.object(projects_helper, "_deckplay_archive", return_value=self.store):
            plan = projects_helper.op_deckplay_snapshot_preview(request)
            self.assertEqual(list(work.iterdir()), [])
            with self.assertRaisesRegex(projects_helper.Refuse, "snapshot_plan_changed"):
                projects_helper._deckplay_checkout({**request, "plan_sha256": "0" * 64}, str(work))
            self.assertEqual(list(work.iterdir()), [])
            with patch.object(projects_helper, "_publish_deckplay", side_effect=InterruptedError):
                with self.assertRaises(InterruptedError):
                    projects_helper._deckplay_checkout({**request, "plan_sha256": plan["plan_sha256"]}, str(work))
            self.assertEqual(list(work.iterdir()), [])
            self.assertEqual(list(projects.iterdir()), [work])
            result = projects_helper._deckplay_checkout({**request, "plan_sha256": plan["plan_sha256"]}, str(work))
            self.assertEqual(result["receipt"]["source_commit"], commit)
            evidence = json.loads((work / ".git" / "stynpilot-checkout.json").read_bytes())
            self.assertEqual(evidence["source_commit"], commit)
            self.assertEqual(evidence["source_tree"], plan["plan"]["source_tree"])
            self.assertEqual(evidence["plan_sha256"], plan["plan_sha256"])
            self.assertEqual(evidence["snapshot_commit"], result["receipt"]["snapshot_commit"])
            self.assertEqual((work / "README").read_text(), "reviewed text\n")
            self.assertFalse((work / ".env").exists())
            self.assertEqual(repo_archive._git(work / ".git", "rev-list", "--count", "HEAD").strip(), b"1")
            self.assertEqual(repo_archive._git(work / ".git", "config", "remote.origin.url").decode().strip(),
                             repo_git.DECKPLAY_ORIGIN)
            with self.assertRaisesRegex(projects_helper.Refuse, "checkout_workspace_not_empty"):
                projects_helper._deckplay_checkout({**request, "plan_sha256": plan["plan_sha256"]}, str(work))
            self.assertEqual((work / "README").read_text(), "reviewed text\n")

    def test_protected_binary_and_sensitive_content_refused(self):
        (self.working / ".env").write_text("synthetic value\n")
        (self.working / "image.bin").write_bytes(b"\xff\x00")
        (self.working / "settings.txt").write_text("pass" + "word" + "=" + "fixture-value\n")
        self.git("add", ".")
        self.git("commit", "-qm", "blocked")
        archive_id, commit = self.adopt()
        args = (self.store, "scope.chatgpt", archive_id, "refs/heads/main", commit)
        plan = deckplay_snapshot.review(*args)
        self.assertFalse(plan["eligible"])
        self.assertEqual(plan["blocked"]["protected"], 1)
        self.assertEqual(plan["blocked"]["binary"], 1)
        self.assertEqual(plan["blocked"]["sensitive"], 1)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "snapshot_review_required"):
            with deckplay_snapshot.stage(*args, deckplay_snapshot.plan_digest(plan)):
                self.fail("blocked content")
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_not_found"):
            deckplay_snapshot.review(self.store, "scope.other", archive_id, "refs/heads/main", commit)

    def test_revoked_client_is_refused_at_the_owner_helper(self):
        path = self.root / ".local/state/stynpilot/revoked-clients.json"
        clients = RevocationFile(path)
        clients.provision()
        request = {"home": str(self.root), "client": "scope.chatgpt"}
        projects_helper._deckplay_client_active(request)
        clients.set_revoked("scope.chatgpt", True)
        with self.assertRaisesRegex(projects_helper.Refuse, "deckplay_checkout_client_revoked"):
            projects_helper._deckplay_client_active(request)

    def test_archive_git_respects_the_tighter_checkout_file_limit(self):
        import sys
        invocation = ('import sys; sys.path.insert(0, sys.argv[1]); '
                      'from stynpilot.repo_archive import _git; '
                      'assert _git(None, "--version").startswith(b"git version ")')
        subprocess.run(["/usr/bin/prlimit", "--fsize=67108864:67108864", "--", sys.executable, "-IB", "-c",
                        invocation, str(Path(repo_archive.__file__).resolve().parents[1])], check=True)
