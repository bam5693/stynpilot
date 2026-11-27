"""Tests of the installer-owned lab lifecycle and recovery reservation."""
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from stynpilot import managed_activity, root_restore, vault
from stynpilot.broker import lab
from stynpilot.broker.executor import Executor
from stynpilot.broker.release_authority import Authority, AuthorityError
from stynpilot.broker.service import BrokerService

COMMIT = "a" * 40
SOURCE = b"synthetic git archive"
DIGEST = hashlib.sha256(SOURCE).hexdigest()
DEVICE = "dtdev_SYNTHETIC900"


class LabBrokerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.authority = Authority(self.root)
        folder = self.authority._dir(COMMIT)
        folder.mkdir()
        vault._write_atomic(folder, "lab-source.tar", SOURCE)
        self.authority._save(COMMIT, {"state": "ready", "commit": COMMIT, "tests_failed": 0,
                                      "reproducible": True, "lab_source_sha256": DIGEST})
        self.backend = Mock(ready=Mock(return_value=True), idle=Mock(return_value=False))
        real_statvfs = os.statvfs
        capacity = SimpleNamespace(f_bavail=1 << 20, f_frsize=4096, f_favail=65536)
        statvfs = patch.object(lab.os, "statvfs", side_effect=lambda path: capacity if path == self.root / "dev-lab" else real_statvfs(path))
        statvfs.start()
        self.addCleanup(statvfs.stop)
        self.jobs = lab.LabJobs(self.root, self.authority, owner="owner", device=DEVICE, backend=self.backend,
                                memory=lambda: 10 << 30)
        self.executor = Executor(state_dir=self.root, owner="owner", device=DEVICE, verifier=Mock(),
                                 require_root=False, lab_jobs=self.jobs, passkeys=Mock())
        self.addCleanup(lambda: os.close(self.executor._alive))
        self.service = BrokerService(socket_path=self.root / "socket", executor=self.executor, allowed_uid=1)

    def call(self, call, client="assistant", **arguments):
        return self.service.handle({"op": "runner", "call": call, "args": {"client": client, **arguments}})

    def start(self, client="assistant", **changes):
        args = {"commit": COMMIT, "artifact_sha256": DIGEST, "repository": lab.REPOSITORY, "scenario": lab.PROFILE}
        args.update(changes)
        return self.call("lab_start", client, **args)

    def test_passkey_enrollment_is_one_time_and_token_approval_does_not_spend_it(self):
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"kind": "runner", "action": "lab_enroll", "name": "", "owner": "owner", "device": DEVICE,
                   "client": "assistant", "profile": lab.POLICY, "repository": lab.REPOSITORY, "expires_at": expires}
        result = self.service.handle({"op": "challenge", "payload": payload, "decision": "approve"})
        self.assertTrue(result["ok"], result)
        challenge = result["challenge"]["challenge"]
        request = {"op": "runner_admin", "payload": payload, "challenge": challenge, "proof": "test"}
        with patch.object(self.executor, "_prove", return_value=("ordinary-token", None)):
            self.assertEqual(self.service.handle(request)["error"], "lab_enrollment_requires_passkey")
        with patch.object(self.executor, "_prove", return_value=("passkey-proof", {"kid": "fixture"})), \
                patch.object(self.executor, "_used_passkey"):
            self.assertTrue(self.service.handle(request)["result"]["enabled"])
        self.assertTrue(self.call("lab_enrollment", repository=lab.REPOSITORY)["result"]["enrolled"])
        self.assertFalse(self.call("lab_enrollment", "other", repository=lab.REPOSITORY)["result"]["enrolled"])
        self.assertEqual(self.service.handle(request)["error"], "lab_already_enrolled")

    def test_only_verified_commit_and_digest_from_the_enrolled_repository_can_start(self):
        self.assertEqual(self.start()["error"], "lab_enrollment_required")
        self.jobs.enroll("assistant")
        self.assertEqual(self.start(repository="elsewhere/project")["error"], "lab_repository_not_supported")
        self.assertEqual(self.start(commit="HEAD")["error"], "lab_exact_commit_required")
        self.assertEqual(self.start(artifact_sha256="f" * 64)["error"], "lab_source_not_verified")
        self.assertEqual(self.start(scenario="guest_restore")["error"], "lab_scenario_not_implemented")
        self.assertFalse(managed_activity.held(self.root))
        self.backend.start.assert_not_called()

    def test_private_evidence_and_recovery_reservation_until_every_process_is_gone(self):
        self.jobs.enroll("assistant")
        job = self.start()["result"]["id"]
        folder = self.jobs._folder(job)
        self.assertEqual((folder / "source.tar").read_bytes(), SOURCE)
        self.assertEqual(self.call("lab_jobs", "other")["result"]["jobs"], [])
        for op, kwargs in (("lab_job_status", {}), ("lab_cancel", {}), ("lab_job_output", {"offset": 0, "limit": 99})):
            self.assertEqual(self.call(op, "other", job=job, **kwargs)["error"], "lab_unknown_job")
        with self.assertRaises(managed_activity.ActivityError):
            managed_activity.require_idle(self.root)
        vault._write_atomic(folder, "result", json.dumps(
            {"state": "passed", "exit_code": 0, "output": "password=synthetic-value\npassed",
             "commit": COMMIT, "scenario": lab.PROFILE}).encode())
        with root_restore.admission(self.root, exclusive=True):
            self.jobs.reconcile()
        self.assertTrue(managed_activity.held(self.root))
        self.backend.idle.return_value = True
        with root_restore.admission(self.root, exclusive=True):
            self.jobs.reconcile()
        self.assertFalse(managed_activity.held(self.root))
        self.assertFalse((folder / "source.tar").exists())
        evidence = self.call("lab_job_output", job=job, offset=0, limit=512)["result"]
        self.assertNotIn("synthetic-value", evidence["text"])
        self.assertIn("passed", evidence["text"])

    def test_cancel_keeps_intent_if_the_cgroup_is_unverified_and_restart_finishes_it(self):
        self.jobs.enroll("assistant")
        job = self.start()["result"]["id"]
        self.assertEqual(self.call("lab_cancel", job=job)["error"], "lab_quiescence_unverified")
        self.assertTrue(managed_activity.held(self.root))
        self.assertFalse((self.jobs._folder(job) / "dispatch").exists())
        self.backend.idle.return_value = True
        restarted = lab.LabJobs(self.root, self.authority, owner="owner", device=DEVICE, backend=self.backend)
        with root_restore.admission(self.root, exclusive=True):
            restarted.reconcile(startup=True)
        self.assertEqual(restarted.status("assistant", job)["state"], "cancelled")
        self.assertFalse(managed_activity.held(self.root))

    def test_changed_artifact_under_verified_record_is_refused(self):
        vault._write_atomic(self.authority._dir(COMMIT), "lab-source.tar", b"altered")
        with self.assertRaisesRegex(AuthorityError, "lab_source_digest_mismatch"):
            self.authority.lab_artifact(COMMIT, DIGEST)

    def test_lab_can_prepare_current_version_only_after_enrollment(self):
        self.executor.authority = Mock()
        self.executor.authority.status.return_value = {
            "state": "ready", "version": "0.1.0~dev25", "lab_source_sha256": DIGEST}
        arguments = {"repository": lab.REPOSITORY, "commit": COMMIT, "version": "0.1.0~dev25"}
        self.assertEqual(self.call("lab_prepare", **arguments)["error"], "lab_enrollment_required")
        self.jobs.enroll("assistant")
        with patch.object(self.executor.upgrader, "installed_version", return_value="0.1.0~dev25"):
            prepared = self.call("lab_prepare", **arguments)
            self.assertEqual(prepared["result"]["lab_source_sha256"], DIGEST)
            release = self.service.handle({"op": "release_prepare", "commit": COMMIT, "version": "0.1.0~dev25"})
            self.assertEqual(release["error"], "not_newer_than_installed")

    def test_time_limit_revokes_dispatch_but_does_not_waive_quiescence(self):
        self.jobs.enroll("assistant")
        self.jobs.clock = Mock(return_value=1000)
        job = self.start()["result"]["id"]
        self.jobs.clock.return_value += lab.JOB_SECONDS
        with root_restore.admission(self.root, exclusive=True):
            with self.assertRaisesRegex(lab.LabError, "lab_quiescence_unverified"):
                self.jobs.reconcile()
        self.assertTrue(managed_activity.held(self.root))
        self.assertFalse((self.jobs._folder(job) / "dispatch").exists())
        self.backend.idle.return_value = True
        with root_restore.admission(self.root, exclusive=True):
            self.jobs.reconcile()
        self.assertEqual(self.jobs.status("assistant", job)["state"], "timeout")
        self.assertFalse(managed_activity.held(self.root))

    def test_completion_prunes_oldest_record_before_admitting_another_job(self):
        self.jobs.enroll("assistant")
        self.jobs.clock = Mock(return_value=1000)
        first = self.start()["result"]["id"]
        self.backend.idle.return_value = True
        with root_restore.admission(self.root, exclusive=True):
            self.jobs.reconcile()
        self.jobs.clock.return_value += 1
        with patch.object(lab, "RETAIN", 1):
            self.assertTrue(self.start()["ok"])
        self.assertFalse(self.jobs._folder(first).exists())


class CgroupTests(unittest.TestCase):
    def test_inactive_leader_is_insufficient_when_cgroup_is_populated(self):
        with tempfile.TemporaryDirectory() as work:
            cgroups = Path(work)
            (cgroups / "cgroup.controllers").touch()
            name = lab._name("a" * 32)
            unit = cgroups / "system.slice" / name
            unit.mkdir(parents=True)
            events = unit / "cgroup.events"
            events.write_text("populated 1\nfrozen 0\n")
            show = "LoadState=loaded\nActiveState=inactive\nControlGroup=/system.slice/" + name + "\nJob=0\n"
            backend = lab.SystemdLab(control=Mock(return_value=SimpleNamespace(returncode=0, stdout=show)), cgroups=cgroups)
            self.assertFalse(backend.idle("a" * 32))
            events.write_text("populated 0\nfrozen 0\n")
            self.assertTrue(backend.idle("a" * 32))
