"""Private native archive jobs reserve recovery until both cgroups quiesce."""

from contextlib import nullcontext
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from stynpilot import managed_activity, projects_helper, repo_archive, root_restore
from stynpilot.broker.archive_jobs import Jobs, KIND
from stynpilot.broker.lab import LabError
from stynpilot.server.clients import RevocationFile

REFS = {"refs/heads/main": "a" * 40}
HEAD = "refs/heads/main"
SOURCE = ("gitlab", "https://gitlab.com/team/fixture.git")
MANIFEST = "b" * 64


class PrivateArchiveJobsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.ready = threading.Event()
        self.release = threading.Event()
        self.addCleanup(self._stop_fixture)
        binding = SimpleNamespace(client="chatgpt", source=SOURCE, credential=("oauth2", "synthetic-secret"),
                                  expires=int(time.time()) + 360)
        auth = Mock()
        auth.begin_fetch.return_value = binding
        auth.fetch_guard.side_effect = lambda _: nullcontext()
        auth.describe.return_value = {"authorization_profile": "e" * 64}
        self.transport, self.receiver = Mock(), Mock()
        self.transport.capture.side_effect = self._capture
        self.helper = Mock()
        self.helper.adopt_archive.side_effect = self._adopt
        self.home = self.state / "owner"
        self.revocations = RevocationFile(self.home / ".local/state/stynpilot/revoked-clients.json")
        self.revocations.provision()
        self.helper.call.side_effect = lambda request, timeout: projects_helper.op_archive_client_active(request)
        self.jobs = Jobs(self.state, auth, self.helper, str(self.home),
                         transport=self.transport, receive_fence=self.receiver)

    def _capture(self, **kwargs):
        self.ready.set()
        if not self.release.wait(5):
            raise AssertionError("test worker never released")
        return {"manifest_sha256": MANIFEST, "bundle_sha256": "c" * 64}

    def _adopt(self, **kwargs):
        self.assertTrue((kwargs["dispatch_dir"] / "permit.json").is_file())
        self.assertEqual(kwargs["client"], "chatgpt")
        self.assertEqual(kwargs["repository_access"]["repository"], "fixture")
        return {"archive_id": MANIFEST[:32]}

    def _stop_fixture(self):
        self.release.set()
        if self.jobs._active is not None:
            self.jobs._active[2].join(6)

    def start(self):
        capacity = SimpleNamespace(f_bavail=1 << 20, f_frsize=4096, f_favail=65536)
        with (root_restore.admission(self.state, exclusive=True),
              patch("stynpilot.broker.archive_jobs.os.statvfs", return_value=capacity)):
            job = self.jobs.start("chatgpt", "fixture", REFS, HEAD)["job_id"]
        self.assertTrue(self.ready.wait(2))
        return job

    def test_insufficient_disk_refuses_before_credential_or_activity_claim(self):
        capacity = SimpleNamespace(f_bavail=1, f_frsize=4096, f_favail=65536)
        with (root_restore.admission(self.state, exclusive=True),
              patch("stynpilot.broker.archive_jobs.os.statvfs", return_value=capacity)):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_intake_insufficient_headroom"):
                self.jobs.start("chatgpt", "fixture", REFS, HEAD)
        self.jobs.authorization.begin_fetch.assert_not_called()
        self.assertFalse(managed_activity.held(self.state))

    def test_result_is_client_scoped_and_only_settled_after_quiescence(self):
        job = self.start()
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_job_not_found"):
            self.jobs.status("claude", job)
        with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_job_not_found"):
            self.jobs.cancel("claude", job)
        self.assertEqual(self.jobs.status("chatgpt", job)["state"], "running")
        self.release.set()
        self.jobs._active[2].join(2)
        self.receiver.stop.side_effect = LabError("lab_quiescence_unverified")
        with root_restore.admission(self.state, exclusive=True):
            with self.assertRaisesRegex(repo_archive.ArchiveError, "archive_intake_quiescence_unverified"):
                self.jobs.reconcile()
            self.assertTrue(managed_activity.held(self.state))
            self.receiver.stop.side_effect = None
            self.jobs.reconcile()
        self.assertFalse(managed_activity.held(self.state))
        self.assertEqual(self.jobs.status("chatgpt", job)["archive_id"], MANIFEST[:32])

    def test_cancelling_blocks_late_dispatch_until_the_orchestrator_stops(self):
        job = self.start()
        with root_restore.admission(self.state, exclusive=True):
            result = self.jobs.cancel("chatgpt", job)
            self.assertEqual(result["state"], "cancel_requested")
            self.assertTrue(managed_activity.held(self.state))
        self.release.set()
        self.jobs._active[2].join(2)
        with root_restore.admission(self.state, exclusive=True):
            self.jobs.reconcile()
        self.assertEqual(self.jobs.status("chatgpt", job)["state"], "cancelled")
        self.assertFalse(managed_activity.held(self.state))
        self.helper.adopt_archive.assert_not_called()

    def test_global_client_revocation_stops_active_private_capture_and_blocks_late_dispatch(self):
        job = self.start()
        self.revocations.set_revoked("claude", True)
        with root_restore.admission(self.state, exclusive=True):
            self.jobs.reconcile()
        self.assertEqual(self.jobs.status("chatgpt", job)["state"], "running")
        self.revocations.set_revoked("chatgpt", True)
        with root_restore.admission(self.state, exclusive=True):
            self.jobs.reconcile()
            self.assertTrue(managed_activity.held(self.state))
        self.transport.fence.stop.assert_called_once_with(job)
        self.receiver.stop.assert_called_once_with(job)
        self.release.set()
        self.jobs._active[2].join(2)
        with root_restore.admission(self.state, exclusive=True):
            self.jobs.reconcile()
        self.assertEqual(self.jobs.status("chatgpt", job)["state"], "authorization_withdrawn")
        self.assertFalse(managed_activity.held(self.state))
        self.helper.adopt_archive.assert_not_called()

    def test_archive_client_probe_accepts_enrolled_identity_syntax(self):
        request = {"op": "archive_client_active", "home": str(self.home), "client": "provider:assistant"}
        self.assertTrue(projects_helper.op_archive_client_active(request)["active"])
        self.revocations.set_revoked(request["client"], True)
        self.assertFalse(projects_helper.op_archive_client_active(request)["active"])

    def test_restart_refuses_to_replay_interrupted_intent(self):
        job = "d" * 32
        self.jobs._folder(job).mkdir(mode=0o700)
        self.jobs._write(job, "job.json", {"job_id": job, "client": "chatgpt", "state": "running"})
        with root_restore.admission(self.state, exclusive=True):
            managed_activity.claim(self.state, KIND, job)
            self.jobs.reconcile()
        self.transport.fence.stop.assert_called_once_with(job)
        self.receiver.stop.assert_called_once_with(job)
        self.transport.capture.assert_not_called()
        self.assertEqual(self.jobs.status("chatgpt", job)["state"], "interrupted")
        self.assertFalse(managed_activity.held(self.state))
