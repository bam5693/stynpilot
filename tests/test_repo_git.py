"""Real Git checks for the credential-free workspace recipes."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stynpilot import repo_git, runner
from stynpilot.workspace import WorkspaceError


class WorkspaceGitTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.folder = Path(root.name, "stynpilot")
        self.folder.mkdir()
        self.git("init", "-q", "--initial-branch=main", "--template=")
        self.git("remote", "add", "origin", repo_git.ORIGIN)
        for name in ("first.txt", "second.txt"):
            (self.folder / name).write_text("original\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        return subprocess.check_output(
            ["/usr/bin/git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgSign=false", "-c", "core.hooksPath=/dev/null", *args],
            cwd=self.folder, env=repo_git._ENV, text=True,
        ).strip()

    def run_recipe(self, recipe, *args):
        argv = runner.build_argv(recipe, args, str(self.folder))
        self.assertEqual(tuple(args), argv[-len(args):])
        return repo_git.run(recipe, args, self.folder)

    def test_new_work_branch_and_exact_tracked_commit(self):
        self.assertEqual(self.run_recipe(repo_git.BRANCH, "work/one", self.base), self.base)
        (self.folder / "first.txt").write_text("tested change\n")
        (self.folder / "second.txt").write_text("unrelated change\n")
        self.git("add", "second.txt")
        commit = self.run_recipe(repo_git.COMMIT, "work/one", self.base, "commit the tested edit", "first.txt")
        self.assertEqual(commit, self.git("rev-parse", "HEAD"))
        self.assertEqual(self.base, self.git("rev-parse", "main"))
        self.assertEqual("first.txt", self.git("diff-tree", "--no-commit-id", "--name-only", "-r", commit))
        self.assertEqual("second.txt", self.git("diff", "--cached", "--name-only"))
        with self.assertRaisesRegex(WorkspaceError, "git_head_changed"):
            repo_git.run(repo_git.COMMIT, ["work/one", self.base, "stale", "first.txt"], self.folder)

    def test_ref_transaction_refuses_branch_switch_during_commit(self):
        self.run_recipe(repo_git.BRANCH, "work/one", self.base)
        (self.folder / "first.txt").write_text("tested change\n")
        native = subprocess.run

        def switch_before_commit(argv, **kwargs):
            if "commit" in argv:
                self.git("symbolic-ref", "HEAD", "refs/heads/main")
            return native(argv, **kwargs)

        with patch.object(repo_git.subprocess, "run", side_effect=switch_before_commit):
            with self.assertRaisesRegex(WorkspaceError, "git_operation_refused"):
                repo_git.run(repo_git.COMMIT, ["work/one", self.base, "tested", "first.txt"], self.folder)
        self.assertEqual(self.base, self.git("rev-parse", "main"))
        self.assertEqual(self.base, self.git("rev-parse", "work/one"))
        self.assertEqual("tested change\n", (self.folder / "first.txt").read_text())

    def test_rejects_wrong_origin_unsafe_config_and_missing_file(self):
        self.git("remote", "set-url", "origin", "https://example.invalid/other.git")
        with self.assertRaisesRegex(WorkspaceError, "origin_mismatch"):
            repo_git.run(repo_git.BRANCH, ["work/one", self.base], self.folder)
        self.git("remote", "set-url", "origin", repo_git.ORIGIN)
        self.git("config", "include.path", "/tmp/other")
        with self.assertRaisesRegex(WorkspaceError, "config_not_supported"):
            repo_git.run(repo_git.BRANCH, ["work/one", self.base], self.folder)
        self.git("config", "--unset", "include.path")
        self.run_recipe(repo_git.BRANCH, "work/one", self.base)
        with self.assertRaisesRegex(WorkspaceError, "git_path_invalid"):
            repo_git.run(repo_git.COMMIT, ["work/one", self.base, "new", "new.txt"], self.folder)
        self.assertEqual(self.base, self.git("rev-parse", "HEAD"))

    def test_commits_explicit_new_file_and_preserves_unrelated_staging(self):
        self.run_recipe(repo_git.BRANCH, "work/one", self.base)
        (self.folder / "new.txt").write_text("new\n")
        (self.folder / "other.txt").write_text("leave untracked\n")
        (self.folder / "second.txt").write_text("staged separately\n")
        self.git("add", "second.txt")
        new = self.run_recipe(repo_git.COMMIT, "work/one", self.base, "new file", "new.txt")
        self.assertEqual("new", self.git("show", new + ":new.txt"))
        self.assertEqual("second.txt", self.git("diff", "--cached", "--name-only"))
        self.assertEqual("other.txt", self.git("ls-files", "--others", "--exclude-standard"))

    def test_switch_and_fast_forward_are_exact_and_preserve_dirty_workspace(self):
        self.run_recipe(repo_git.BRANCH, "work/one", self.base)
        self.run_recipe(repo_git.BRANCH, "test/two", self.base)
        (self.folder / "first.txt").write_text("tested change\n")
        with self.assertRaisesRegex(WorkspaceError, "workspace_dirty"):
            self.run_recipe(repo_git.SWITCH, "work/one", self.base, self.base)
        new = self.run_recipe(repo_git.COMMIT, "test/two", self.base, "descendant", "first.txt")
        with self.assertRaisesRegex(WorkspaceError, "target_changed"):
            self.run_recipe(repo_git.SWITCH, "work/one", new, new)
        self.assertEqual(self.base, self.run_recipe(repo_git.SWITCH, "work/one", new, self.base))
        self.assertEqual(new, self.run_recipe(repo_git.FAST_FORWARD, "work/one", self.base, new))
        self.assertEqual("tested change", (self.folder / "first.txt").read_text().strip())
        self.assertEqual(self.base, self.git("rev-parse", "main"))
        with self.assertRaises(WorkspaceError):
            self.run_recipe(repo_git.FAST_FORWARD, "work/one", new, self.base)
        self.assertEqual(new, self.git("rev-parse", "HEAD"))

    def test_rejects_protected_refs_paths_and_other_workspaces(self):
        for branch in ("main", "refs/heads/work/one", "work/-flag", "work/../main"):
            with self.subTest(branch=branch), self.assertRaises(runner.RunnerError):
                runner.build_argv(repo_git.BRANCH, [branch, self.base], str(self.folder))
        for path in (".git/config", "src/.env", "../outside", "tests/"):
            with self.subTest(path=path), self.assertRaises(runner.RunnerError):
                runner.build_argv(repo_git.COMMIT, ["work/one", self.base, "message", path], str(self.folder))
        with self.assertRaisesRegex(runner.RunnerError, "git_workspace_not_bound"):
            runner.build_argv(repo_git.BRANCH, ["work/one", self.base], str(self.folder.parent / "other-project"))

    def test_deckplay_local_operations_only(self):
        destination = self.folder.parent / repo_git.DECKPLAY_WORKSPACE
        self.folder.rename(destination)
        self.folder = destination
        with self.assertRaisesRegex(WorkspaceError, "git_workspace_origin_mismatch"):
            self.run_recipe(repo_git.BRANCH, "work/deckplay", self.base)
        self.git("remote", "set-url", "origin", repo_git.DECKPLAY_ORIGIN)
        self.assertEqual(self.run_recipe(repo_git.BRANCH, "work/deckplay", self.base), self.base)
        (self.folder / "first.txt").write_text("DeckPlay change\n")
        new = self.run_recipe(repo_git.COMMIT, "work/deckplay", self.base, "local DeckPlay edit", "first.txt")
        self.assertEqual(new, self.git("rev-parse", "HEAD"))
        self.assertEqual(self.base, self.git("rev-parse", "main"))
        self.run_recipe(repo_git.BRANCH, "test/deckplay", new)
        self.assertEqual(new, self.run_recipe(repo_git.SWITCH, "work/deckplay", new, new))
        for recipe in (repo_git.FETCH, repo_git.EXPORT):
            with self.subTest(recipe=recipe), self.assertRaisesRegex(WorkspaceError, "git_workspace_not_bound"):
                repo_git.run(recipe, ["work/deckplay", new], self.folder)
            with self.assertRaisesRegex(runner.RunnerError, "unknown_recipe"):
                runner.build_argv(recipe, ["work/deckplay", new], str(self.folder))
        self.assertEqual(self.git("remote", "get-url", "origin"), repo_git.DECKPLAY_ORIGIN)
