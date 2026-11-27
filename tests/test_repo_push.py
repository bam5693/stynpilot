"""Guarded push uses native Git and its non-forced receive-pack protocol."""
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from stynpilot import repo_git, repo_push
from stynpilot.broker.repo_push import Transport


class PushTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.local = self.root / "stynpilot"
        self.local.mkdir()
        self.remote = self.root / "remote.git"
        self.git(self.remote.parent, "init", "--quiet", "--bare", str(self.remote))
        self.git(self.local, "init", "--quiet", "--initial-branch=work/demo", "--template=")
        self.git(self.local, "remote", "add", "origin", repo_git.ORIGIN)
        self.base = self.commit("base")

    def git(self, directory, *argv):
        return subprocess.check_output(
            ["/usr/bin/git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "core.hooksPath=/dev/null", "-C", str(directory), *argv], env=repo_git._ENV,
            stderr=subprocess.DEVNULL, text=True).strip()

    def commit(self, text):
        (self.local / "tracked.txt").write_text(text)
        self.git(self.local, "add", "tracked.txt")
        self.git(self.local, "commit", "--quiet", "-m", text)
        return self.git(self.local, "rev-parse", "HEAD")

    def publish(self, commit, expected):
        bundle = repo_git.run(repo_git.EXPORT, ["work/demo", commit], self.local)
        repo_push.push_bundle(bundle, "work/demo", commit, expected, "", remote=str(self.remote))

    def test_creates_and_fast_forwards_only_the_bound_ref(self):
        self.publish(self.base, repo_push.ZERO)
        self.git(self.remote, "update-ref", "refs/heads/protected", self.base)
        descendant = self.commit("descendant")
        self.publish(descendant, self.base)
        self.publish(descendant, self.base)  # retry after a lost response
        self.assertEqual(descendant, self.git(self.remote, "rev-parse", "refs/heads/work/demo"))
        self.assertEqual(self.base, self.git(self.remote, "rev-parse", "refs/heads/protected"))
        self.git(self.local, "reset", "--hard", self.base)
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish(self.base, descendant)
        self.assertEqual(descendant, self.git(self.remote, "rev-parse", "refs/heads/work/demo"))

    def test_rejects_stale_expected_remote_and_wrong_export_identity(self):
        self.publish(self.base, repo_push.ZERO)
        next_commit = self.commit("advance")
        with self.assertRaisesRegex(repo_git.WorkspaceError, "git_push_remote_changed"):
            self.publish(next_commit, repo_push.ZERO)
        with self.assertRaisesRegex(repo_git.WorkspaceError, "git_push_commit_mismatch"):
            repo_git.run(repo_git.EXPORT, ["work/demo", self.base], self.local)
        with self.assertRaisesRegex(repo_git.WorkspaceError, "git_push_binding_invalid"):
            repo_git.validate_push("main", self.base, repo_push.ZERO)
        self.assertEqual(self.base, self.git(self.remote, "rev-parse", "refs/heads/work/demo"))

    def test_push_hook_checks_the_remote_state_on_the_actual_connection(self):
        self.publish(self.base, repo_push.ZERO)
        intervening = self.commit("intervening")
        requested = self.commit("requested")
        original = subprocess.run

        def advance_remote(argv, *args, **kwargs):
            if "push" in argv:
                self.git(self.local, "push", "--quiet", str(self.remote),
                         intervening + ":refs/heads/work/demo")
            return original(argv, *args, **kwargs)

        with patch.object(repo_push.subprocess, "run", side_effect=advance_remote):
            # Inject the race only for the guarded call, not the fixture update.
            fired = False
            def advance_once(argv, *args, **kwargs):
                nonlocal fired
                if not fired and "push" in argv:
                    fired = True
                    return advance_remote(argv, *args, **kwargs)
                return original(argv, *args, **kwargs)
            repo_push.subprocess.run.side_effect = advance_once
            with self.assertRaises(subprocess.CalledProcessError):
                self.publish(requested, self.base)
        self.assertEqual(intervening, self.git(self.remote, "rev-parse", "refs/heads/work/demo"))

    def test_verified_full_history_hydrates_existing_shallow_workspace(self):
        tip = self.commit("shallow tip")
        incoming = self.root / "clone" / "stynpilot"
        incoming.mkdir(parents=True)
        self.git(incoming, "init", "--quiet", "--template=")
        self.git(incoming, "remote", "add", "origin", repo_git.ORIGIN)
        self.git(incoming, "fetch", "--quiet", "--depth=1", self.local.as_uri(), tip)
        self.git(incoming, "checkout", "--quiet", "--detach", tip)
        self.git(incoming, "switch", "--quiet", "--create", "work/hydrated")
        self.git(self.local, "update-ref", repo_git.BUNDLE_REF, tip)
        bundle = self.root / "history.bundle"
        self.git(self.local, "bundle", "create", str(bundle), repo_git.BUNDLE_REF)
        data = bundle.read_bytes()
        with patch.object(repo_git.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(data))):
            self.assertEqual(tip, repo_git.run(repo_git.FETCH, [tip, hashlib.sha256(data).hexdigest()], incoming))
        self.assertEqual("false", self.git(incoming, "rev-parse", "--is-shallow-repository"))
        self.assertEqual("work/hydrated", self.git(incoming, "branch", "--show-current"))
        self.assertTrue(repo_git.run(repo_git.EXPORT, ["work/hydrated", tip], incoming).startswith(b"# v"))

    def test_protected_credential_goes_to_separate_unit_only(self):
        credential = self.root / "repository-github-token"
        token = b"ghp_fixture123456789012345"
        credential.write_bytes(token)
        credential.chmod(0o600)
        with patch("stynpilot.broker.repo_push.subprocess.run") as run:
            run.return_value.returncode = 0
            transport = Transport(self.root, run)
            transport.publish(b"fixture bundle", "work/demo", self.base, repo_push.ZERO)
            argv = run.call_args.args[0]
            params = run.call_args.kwargs
            self.assertIn("--property=LoadCredential=github:" + str(credential), argv)
            self.assertIn("--property=DynamicUser=yes", argv)
            self.assertEqual(b"fixture bundle", params["input"])
            self.assertNotIn(token.decode(), repr(run.call_args))
