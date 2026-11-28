"""Durable, client-scoped orchestration for native private repository intake."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import threading
import time

from .. import archive_store, managed_activity, repo_archive, root_restore, statelock, vault
from .archive_transport import Transport
from .helper import HelperError, archive_receive_unit
from .lab import LabError, SystemdLab
from .repository_auth import AuthorizationError

KIND = "private_archive"
DEADLINE = 360
RETAINED_JOBS = 16
CALLS = frozenset({"archive_capture_start", "archive_capture_status", "archive_capture_cancel"})
_ACTIVE = ("running", "cancel_requested")
_MIN_FREE = archive_store.ADOPTION_RESERVATION + repo_archive.MAX_BUNDLE + (64 << 20)


class Jobs:
    """Start, cancel, and reconcile under exclusive restore admission."""

    def __init__(self, state, authorization, helper, home, *, transport=None, receive_fence=None, clock=time.time):
        self.state = Path(state)
        self.path = vault._private_folder(self.state / "archive-intake")
        self.authorization, self.helper, self.home, self.clock = authorization, helper, home, clock
        self.transport = transport or Transport()
        self.receive_fence = receive_fence or SystemdLab(unit_name=archive_receive_unit)
        self._active = None

    def _folder(self, job):
        if type(job) is not str or not managed_activity.ID.fullmatch(job):
            raise repo_archive.ArchiveError("archive_job_not_found")
        return self.path / job

    def _write(self, job, name, data, mode=0o600):
        vault._write_atomic(self._folder(job), name, json.dumps(data, sort_keys=True).encode(), mode=mode)

    def _read(self, job, name="job.json"):
        return json.loads(vault._read_private(self._folder(job) / name, 4096))

    def _owned(self, client, job):
        try:
            row = self._read(job)
        except FileNotFoundError:
            raise repo_archive.ArchiveError("archive_job_not_found") from None
        if row["client"] != client:
            raise repo_archive.ArchiveError("archive_job_not_found")
        return row

    @staticmethod
    def _public(row):
        return {key: value for key, value in row.items() if key != "client"}

    def status(self, client, job):
        return self._public(self._owned(client, job))

    def _prune(self):
        rows = []
        for child in self.path.iterdir():
            if managed_activity.ID.fullmatch(child.name):
                try:
                    row = self._read(child.name)
                except FileNotFoundError:
                    shutil.rmtree(child)
                    continue
                if row["state"] in _ACTIVE:
                    # No managed claim means this intent could not launch.
                    shutil.rmtree(child)
                else:
                    rows.append(row)
        for row in sorted(rows, key=lambda row: row["started"])[:max(0, len(rows) + 1 - RETAINED_JOBS)]:
            shutil.rmtree(self._folder(row["job_id"]))

    def start(self, client, repository, refs, head):
        if self.authorization is None:
            raise repo_archive.ArchiveError("repository_authorization_unavailable")
        if managed_activity.held(self.state):
            raise repo_archive.ArchiveError("managed_activity_busy")
        refs = repo_archive._expected_map(refs)
        if not repo_archive._default_head(refs, head):
            raise repo_archive.ArchiveError("archive_default_head_invalid")
        free = os.statvfs(self.path)
        if free.f_bavail * free.f_frsize < _MIN_FREE or free.f_favail < 1024:
            raise repo_archive.ArchiveError("archive_intake_insufficient_headroom")
        binding = self.authorization.begin_fetch(client, repository, seconds=DEADLINE)
        access = {"repository": repository,
                  "authorization_profile": self.authorization.describe(repository)["authorization_profile"]}
        self._prune()
        job = secrets.token_hex(16)
        vault._private_folder(self._folder(job))
        row = {"job_id": job, "client": client, "repository": repository, "started": int(self.clock()),
               "deadline": binding.expires, "state": "running", "ref_count": len(refs),
               "refs_sha256": hashlib.sha256(json.dumps(refs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        self._write(job, "job.json", row)
        managed_activity.claim(self.state, KIND, job)
        thread = threading.Thread(target=self._run, args=(job, binding, refs, head, access), daemon=True)
        self._active = (job, binding, thread)
        try:
            thread.start()
        except RuntimeError:
            self._active = None
            self._write(job, "result.json", {"state": "failed", "error": "archive_job_start_failed"})
            self.reconcile()
            raise repo_archive.ArchiveError("archive_job_start_failed") from None
        return self._public(row)

    def _permit(self, job):
        return self._folder(job) / "dispatch" / "permit.json"

    def _dispatch(self, job, binding, captured, access):
        # A concurrent revoke or cancellation cannot publish an older grant.
        for _ in range(20):
            try:
                with root_restore.admission(self.state, exclusive=True):
                    self.authorization.check_fetch(binding)
                    if (self._read(job)["state"] != "running"
                            or managed_activity.current(self.state) != {"job_id": job, "kind": KIND}):
                        raise repo_archive.ArchiveError("archive_job_cancelled")
                    permit = self._permit(job)
                    permit.parent.mkdir(mode=0o755)
                    receipt = {"op": "archive_receive", "job": job, "client": binding.client,
                               "manifest_sha256": captured["manifest_sha256"], "bundle_sha256": captured["bundle_sha256"],
                               "repository_access": access, "expires": binding.expires}
                    vault._write_atomic(permit.parent, permit.name, json.dumps(receipt).encode(), mode=0o644)
                    return permit.parent
            except statelock.Busy:
                time.sleep(0.1)
        raise repo_archive.ArchiveError("archive_dispatch_busy")

    def _run(self, job, binding, refs, head, access):
        result = {"state": "failed", "error": "archive_intake_failed"}
        try:
            self.authorization.check_fetch(binding)
            with tempfile.TemporaryFile(dir=self._folder(job)) as stream:
                captured = self.transport.capture(job=job, source=binding.source, refs=refs, head=head,
                                                  credential=binding.credential, stream=stream)
                dispatch = self._dispatch(job, binding, captured, access)
                adopted = self.helper.adopt_archive(home=self.home, job=job, client=binding.client,
                                                    manifest_sha256=captured["manifest_sha256"],
                                                    bundle_sha256=captured["bundle_sha256"], repository_access=access,
                                                    dispatch_dir=dispatch, stream=stream)
            expected = captured["manifest_sha256"][:32]
            if adopted.get("archive_id") != expected:
                raise repo_archive.ArchiveError("archive_transfer_outcome_unverified")
            result = {"state": "done", "archive_id": expected}
        except (repo_archive.ArchiveError, AuthorizationError, HelperError) as error:
            result["error"] = error.code
        except (OSError, subprocess.SubprocessError, vault.VaultError):
            pass
        finally:
            self._write(job, "result.json", result)

    def _stop(self, job):
        permit = self._permit(job)
        if permit.exists():
            permit.unlink()
            vault._fsync_dir(permit.parent)
        for fence in (self.transport.fence, self.receive_fence):
            try:
                fence.stop(job)
            except (OSError, LabError, subprocess.SubprocessError):
                raise repo_archive.ArchiveError("archive_intake_quiescence_unverified") from None

    def cancel(self, client, job):
        row = self._owned(client, job)
        if row["state"] in _ACTIVE:
            row.update(state="cancel_requested", stop_reason="cancelled")
            self._write(job, "job.json", row)
            self.reconcile()
        return self.status(client, job)

    def reconcile(self):
        claim = managed_activity.current(self.state)
        if claim is None or claim["kind"] != KIND:
            return
        job = claim["job_id"]
        row = self._read(job)
        current = self._active if self._active is not None and self._active[0] == job else None
        running = current is not None and current[2].is_alive()
        if running and row["state"] == "running":
            reason = "timeout" if self.clock() >= row["deadline"] else None
            if reason is None:
                try:
                    self.authorization.check_fetch(current[1])
                except AuthorizationError as error:
                    if error.code == "repository_authorization_busy":
                        return
                    reason = "authorization_withdrawn"
            if reason is None:
                return
            row.update(state="cancel_requested", stop_reason=reason)
            self._write(job, "job.json", row)
        self._stop(job)
        if running:
            # A launch race can still be in progress. Keep the durable claim
            # until the orchestrator is dead and both units are verified empty.
            return
        if row["state"] in _ACTIVE:
            try:
                result = self._read(job, "result.json")
            except FileNotFoundError:
                result = {"state": "interrupted"}
            if row.get("stop_reason") and result.get("state") != "done":
                result = {"state": row["stop_reason"]}
            row.update(result, ended=int(self.clock()))
            self._write(job, "job.json", row)
        managed_activity.finish(self.state, KIND, job)
        self._active = None
