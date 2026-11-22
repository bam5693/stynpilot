"""The installer (runs as root): executes ONLY an owner-approved, unchanged, exact plan.

For an install request it does, in order, and stops at the first failure:
1. **Same plan:** recompute the plan's SHA-256 from the exact payload; it must equal
   the request ID the owner approved. Re-validate it against the owner and device this
   installer was enrolled for (never values from the request).
2. **Owner approved it:** verify the Auth0-signed proof (see proof.py). It must be for
   this owner, recent, and bound to this exact plan.
3. **Only once:** record the proof and request as used, before doing anything. A second
   attempt with the same proof or request is refused (one live attempt per approval).
4. **No drift:** ask apt what it would install right now. It must be exactly the
   approved packages and versions, and nothing may be removed.
5. **Backup first:** record every affected package's current version in a root-only
   snapshot file, then read it back and check its hash.
6. **Install** exactly the pinned versions, then check dpkg shows exactly those versions.
7. **Verify the way back:** simulate the rollback. Only if that works is the install
   recorded as having a *verified* backup, and only then can a rollback be requested.
If the install fails part-way, it restores the snapshot at once and reports that.

Rollback (separately approved): the install must be in the root ledger for this owner,
device and software, not rolled back yet, with a verified backup. Packages that were
not installed before are removed with their settings files kept (retire, don't purge).
Packages that were at another version go back to it.

Containers are refused until their own reviewed executor exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..ledger import InstallLedger, LedgerError
from ..plan import PlanError, validate_plan
from ..requests import request_id as payload_hash
from . import apt
from .proof import ProofDenied


class ExecutionDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Runs:
    """Root-only record of used proofs and of every run's outcome."""

    def __init__(self, path):
        self.path, self._lock = str(path), threading.Lock()
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS runs (
                request_id TEXT PRIMARY KEY, proof TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
                state TEXT NOT NULL, result TEXT, started REAL NOT NULL, finished REAL)""")

    @contextmanager
    def _tx(self):
        with self._lock:
            db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("BEGIN IMMEDIATE")
                try:
                    yield db
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
                db.execute("COMMIT")
            finally:
                db.close()

    def claim(self, request_id, proof, kind):
        try:
            with self._tx() as db:
                db.execute("INSERT INTO runs (request_id, proof, kind, state, started) VALUES (?,?,?,?,?)",
                           (request_id, proof, kind, "running", time.time()))
        except sqlite3.IntegrityError:
            raise ExecutionDenied("already_used") from None

    def finish(self, request_id, state, result):
        with self._tx() as db:
            db.execute("UPDATE runs SET state=?, result=?, finished=? WHERE request_id=?",
                       (state, json.dumps(result, sort_keys=True), time.time(), request_id))

    def status(self, request_id):
        with self._tx() as db:
            row = db.execute("SELECT state, result FROM runs WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return {"state": "not_started"}
        return {"state": row["state"], "result": json.loads(row["result"]) if row["result"] else None}


class Executor:
    def __init__(self, *, state_dir, owner, device, verifier, run=apt.real_run, require_root=True):
        self.dir = Path(state_dir)
        if require_root and not apt.is_root():
            raise ExecutionDenied("installer_must_run_as_root")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = os.lstat(self.dir)
        if self.dir.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ExecutionDenied("installer_state_not_private")
        self.owner, self.device, self.verifier, self.run = owner, device, verifier, run
        self.runs = Runs(self.dir / "runs.sqlite3")
        self.ledger = InstallLedger(self.dir / "installs.sqlite3")
        (self.dir / "snapshots").mkdir(exist_ok=True, mode=0o700)

    # -- shared checks ----------------------------------------------------------------------
    def _approved(self, payload, proof_token, kind):
        rid, _ = payload_hash(payload)
        try:
            self.verifier.verify(proof_token, request_id=rid, plan_sha256=rid, owner=self.owner)
        except ProofDenied as denied:
            raise ExecutionDenied(denied.code) from None
        from .proof import proof_fingerprint
        self.runs.claim(rid, proof_fingerprint(proof_token), kind)
        return rid

    def _snapshot(self, rollback_id, before):
        path = self.dir / "snapshots" / (rollback_id + ".json")
        data = json.dumps({"rollback_id": rollback_id, "before": before}, sort_keys=True).encode()
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if hashlib.sha256(path.read_bytes()).hexdigest() != hashlib.sha256(data).hexdigest():
            raise ExecutionDenied("backup_not_verified")
        return path

    def _restore(self, before):
        """Put every package back to its recorded state. Returns True if dpkg then agrees."""
        newly = sorted(name for name, version in before.items() if version is None)
        older = [(name, version) for name, version in sorted(before.items()) if version is not None]
        ok = True
        if newly:
            ok = apt.remove(newly, self.run) and ok
        if older:
            ok = self.run(["apt-get", "install", "-q", "-y", "--allow-downgrades", "--no-install-recommends",
                           "-o", "Dpkg::Options::=--force-confold", "--",
                           *apt._pins(older)])[0] == 0 and ok
        return ok and apt.installed_versions(sorted(before), self.run) == before

    def _rollback_simulates(self, before):
        newly = sorted(name for name, version in before.items() if version is None)
        older = [(name, version) for name, version in sorted(before.items()) if version is not None]
        if newly and not apt.simulate_remove(newly, self.run):
            return False
        if older:
            return self.run(["apt-get", "-s", "-q", "-y", "--allow-downgrades", "install", "--",
                             *apt._pins(older)])[0] == 0
        return True

    # -- install ----------------------------------------------------------------------------
    def install(self, payload, proof_token, *, software, now=None):
        """Execute an approved install. Returns a result dict; raises ExecutionDenied before any change."""
        try:
            plan = validate_plan(payload, expected_owner=self.owner, expected_device=self.device,
                                 now=now or datetime.now(timezone.utc))
        except PlanError:
            raise ExecutionDenied("plan_invalid_or_expired") from None
        content = plan.content()
        if plan.plan_sha256 != payload_hash(payload)[0]:
            raise ExecutionDenied("plan_hash_mismatch")
        if any(step["kind"] != "apt" for step in content["steps"]):
            raise ExecutionDenied("step_kind_not_supported_yet")
        rid = self._approved(payload, proof_token, "install")
        try:
            result = self._install_apt(rid, content, software)
        except ExecutionDenied as stopped:
            result = {"ok": False, "stopped": stopped.code, "changed_anything": False}
        except Exception as error:
            result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__, "changed_anything": None}
        self.runs.finish(rid, "done" if result.get("ok") else "failed", result)
        return result

    def _install_apt(self, rid, content, software):
        wanted = {p["name"]: p["version"] for step in content["steps"] for p in step["packages"]}
        pins = sorted(wanted.items())
        try:
            would, removals = apt.simulate_install(apt._pins(pins), self.run)
        except RuntimeError:
            raise ExecutionDenied("approved_version_no_longer_available") from None   # e.g. archive moved on
        if removals:
            raise ExecutionDenied("would_remove_packages")
        before = apt.installed_versions(sorted(wanted), self.run)
        # Drift: apt may install nothing outside the plan, only the approved versions, and every
        # planned package it would NOT touch must already be at its approved version.
        if (not set(would) <= set(wanted) or any(would[n] != wanted[n] for n in would)
                or any(before[n] != wanted[n] for n in wanted if n not in would)):
            raise ExecutionDenied("drift_from_approved_plan")
        rollback_id = secrets.token_hex(16)
        self._snapshot(rollback_id, before)
        if not apt.install(pins, self.run) or apt.installed_versions(sorted(wanted), self.run) != wanted:
            restored = self._restore(before)
            return {"ok": False, "stopped": "install_failed", "changed_anything": not restored,
                    "restored_from_backup": restored}
        verified = self._rollback_simulates(before)
        self.ledger.record(rollback_id=rollback_id, software=software, owner=self.owner, device=self.device,
                           request_id=rid, snapshot_id=rollback_id, snapshot_verified=verified)
        return {"ok": True, "installed": [{"name": n, "version": v} for n, v in pins],
                "rollback_id": rollback_id, "rollback_verified": verified}

    # -- rollback ---------------------------------------------------------------------------
    def rollback(self, payload, proof_token):
        if (type(payload) is not dict or payload.get("kind") != "rollback"
                or payload.get("owner") != self.owner or payload.get("device") != self.device):
            raise ExecutionDenied("rollback_request_invalid")
        try:
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ExecutionDenied("rollback_request_invalid") from None
        if expires <= datetime.now(timezone.utc):
            raise ExecutionDenied("plan_invalid_or_expired")
        try:
            entry = self.ledger.rollbackable(payload.get("rollback_id"), software=payload.get("software"),
                                             owner=self.owner, device=self.device)
        except LedgerError as refused:
            raise ExecutionDenied(refused.code) from None
        rid = self._approved(payload, proof_token, "rollback")
        try:
            before = json.loads((self.dir / "snapshots" / (entry["snapshot_id"] + ".json")).read_text())["before"]
            ok = self._restore(before)
            if ok:
                self.ledger.mark_rolled_back(entry["rollback_id"])
            result = {"ok": ok, "restored": before} if ok else {"ok": False, "stopped": "restore_incomplete"}
        except Exception as error:
            result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__}
        self.runs.finish(rid, "done" if result["ok"] else "failed", result)
        return result
