"""The installer (runs as root): executes ONLY an owner-approved, unchanged, exact plan.

Install, stopping at the first failure:
1. **Same plan, right software.** Re-hash the payload (the request ID the owner decided on),
   re-validate it against the owner and device this installer was enrolled for, and take
   the software name from inside the hashed plan, checked against the catalog. The
   caller's opinion is never used.
2. **The owner approved it.** A root-issued, single-use challenge for (approve, request,
   plan) must exist, and the Auth0-signed proof must carry its nonce (see proof.py).
   Challenge and proof are consumed before anything changes: one attempt per approval.
3. **Trusted source.** No apt source may switch off signature checks, and every planned
   version must come from a signed source whose Release says Origin/Label Ubuntu.
4. **Exact transaction.** Download exactly the planned .deb files into a root-only folder,
   then simulate with ``--no-download``. apt must install exactly the planned set at the
   planned versions and remove nothing. The install itself runs ``--no-download`` from
   that folder, so the archive changing in between can't add anything.
5. **Real backup.** For every planned package that is already installed (an upgrade), its
   current .deb is saved and its settings files are copied, together with the auto/manual
   marks. Each saved file is hashed and read back. If an upgraded package's current
   version can't be saved, the install stops (fail closed).
6. **Install, then prove nothing else changed.** The full dpkg state before and after
   must differ in exactly the planned packages and versions. Otherwise it restores
   automatically and reports failure.

Rollback (separately approved, same challenge rules):
- The ledger entry must exist for this owner, device and software, not be rolled back,
  and have a verified backup. The backup files are re-hashed.
- Every affected package must still be at the version the install left. Otherwise it
  refuses ("changed_since_install").
- Simulate removing the added packages: apt must remove exactly those and nothing else.
  If something installed later depends on them, it refuses. The downgrades are simulated
  from the saved .deb files with no download and no removals.
- Then it executes, restores the settings files and marks, and verifies the final state
  against the backup.
Containers are refused until their own reviewed executor exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .. import catalog, impact, statelock
from ..ledger import InstallLedger, LedgerError
from ..plan import PlanError, validate_plan
from ..requests import request_id as payload_hash
from . import apt
from .proof import ProofDenied, decision_nonce, render_summary, summary_hash

CHALLENGE_LIFETIME = 600
BACKUP_SCOPE = "packages_and_dpkg_tracked_settings_only"
LIMITS = ("This is a bounded package rollback, not a system snapshot. It restores the packages this install "
          "added or upgraded, their dpkg-tracked settings files and their auto/manual marks. It does not restore "
          "application data, untracked files, service state, changes made by package scripts outside those files, "
          "or other packages changed while it ran.")


class ExecutionDenied(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Runs:
    """Root-only: issued challenges, used proofs, decisions and every run's outcome."""

    def __init__(self, path, clock=time.time):
        self.path, self.clock, self._lock = str(path), clock, threading.Lock()
        with self._tx() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS runs (
                request_id TEXT PRIMARY KEY, proof TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
                state TEXT NOT NULL, result TEXT, started REAL NOT NULL, finished REAL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS challenges (
                challenge TEXT PRIMARY KEY, request_id TEXT NOT NULL, decision TEXT NOT NULL,
                expires REAL NOT NULL, used REAL)""")

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

    def issue(self, request_id, decision):
        challenge = secrets.token_hex(32)
        with self._tx() as db:
            if db.execute("SELECT 1 FROM runs WHERE request_id=?", (request_id,)).fetchone():
                raise ExecutionDenied("already_decided_or_used")
            db.execute("INSERT INTO challenges VALUES (?,?,?,?,NULL)",
                       (challenge, request_id, decision, self.clock() + CHALLENGE_LIFETIME))
        return challenge

    def consume(self, *, challenge, request_id, decision, proof, kind):
        """Atomically: the challenge is ours, fresh, unused and matches; record the run. Else refuse."""
        try:
            with self._tx() as db:
                row = db.execute("SELECT * FROM challenges WHERE challenge=?",
                                 (challenge if type(challenge) is str else "",)).fetchone()
                if row is None or row["request_id"] != request_id or row["decision"] != decision:
                    raise ExecutionDenied("challenge_unknown")
                if row["used"] is not None:
                    raise ExecutionDenied("already_used")
                if row["expires"] <= self.clock():
                    raise ExecutionDenied("challenge_expired")
                db.execute("UPDATE challenges SET used=? WHERE challenge=?", (self.clock(), challenge))
                db.execute("INSERT INTO runs (request_id, proof, kind, state, started) VALUES (?,?,?,?,?)",
                           (request_id, proof, kind, "denied" if decision == "deny" else "running", self.clock()))
        except sqlite3.IntegrityError:
            raise ExecutionDenied("already_used") from None

    def finish(self, request_id, state, result):
        with self._tx() as db:
            db.execute("UPDATE runs SET state=?, result=?, finished=? WHERE request_id=?",
                       (state, json.dumps(result, sort_keys=True), self.clock(), request_id))

    def running(self):
        with self._tx() as db:
            return [r["request_id"] for r in db.execute("SELECT request_id FROM runs WHERE state='running'")]

    def status(self, request_id):
        with self._tx() as db:
            row = db.execute("SELECT state, result FROM runs WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return {"state": "not_started"}
        return {"state": row["state"], "result": json.loads(row["result"]) if row["result"] else None}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Executor:
    def __init__(self, *, state_dir, owner, device, verifier, run=apt.real_run, require_root=True,
                 sources_root="/etc/apt", file_root="/"):
        self.dir = Path(state_dir)
        if require_root and not apt.is_root():
            raise ExecutionDenied("installer_must_run_as_root")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = os.lstat(self.dir)
        if self.dir.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ExecutionDenied("installer_state_not_private")
        try:
            self._alive = statelock.hold_alive(self.dir)        # a restore of these records is refused while we live
        except statelock.Busy:
            raise ExecutionDenied("installer_records_are_being_restored") from None
        self.owner, self.device, self.verifier, self.run = owner, device, verifier, run
        self.sources_root, self.file_root = sources_root, Path(file_root)
        self.runs = Runs(self.dir / "runs.sqlite3")
        self.ledger = InstallLedger(self.dir / "installs.sqlite3")
        for sub in ("snapshots", "downloads", "attention"):
            (self.dir / sub).mkdir(exist_ok=True, mode=0o700)
        # A run still marked "running" means the installer died mid-change. We can't know what state
        # the machine is in, so record that durably and refuse new installs until the owner looks.
        for rid in self.runs.running():
            self._attention(rid, None, "interrupted_by_restart_or_crash", None)
            self.runs.finish(rid, "needs_owner_intervention", {"ok": False, "stopped": "interrupted_by_restart_or_crash",
                                                               "needs_owner_intervention": True})

    def status(self, request_id):
        """What the installer's own durable record says about this request (reconciliation source)."""
        return self.runs.status(request_id)

    def needs_attention(self):
        """Durable records of runs that may have left the machine changed. New installs are refused while any exist."""
        return sorted(p.name for p in (self.dir / "attention").glob("*.json"))

    def _attention(self, rid, rollback_id, reason, detail):
        record = {"request_id": rid, "rollback_id": rollback_id, "reason": reason, "detail": detail,
                  "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "what_to_do": "Owner: check the package state before any further install; clear this record "
                                "only after checking."}
        path = self.dir / "attention" / ("%s.json" % rid)
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, json.dumps(record, sort_keys=True).encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    # -- decisions ----------------------------------------------------------------------------
    def challenge(self, payload, decision):
        """Start the owner's decision: a root challenge plus the root-rendered summary to show."""
        if decision not in ("approve", "deny"):
            raise ExecutionDenied("invalid_decision")
        self._check_payload(payload)
        rid, _ = payload_hash(payload)
        challenge = self.runs.issue(rid, decision)
        summary = render_summary(payload)
        if payload.get("kind") != "rollback" and catalog.is_generic(payload.get("software")):
            try:
                found = self.package_notes(payload)
            except ExecutionDenied:
                raise
            except Exception:
                raise ExecutionDenied("package_contents_unreadable") from None
            summary += (["What these packages would install (checked by StyNpilot before you decide):"]
                        + (["  - " + n for n in found] if found else ["  - no background services or privileged programs found."]))
        return {"request_id": rid, "decision": decision, "challenge": challenge,
                "nonce": decision_nonce(decision, rid, rid, challenge),
                "summary": summary, "summary_sha256": summary_hash(summary), "expires_in": CHALLENGE_LIFETIME}

    def _check_payload(self, payload):
        if type(payload) is not dict:
            raise ExecutionDenied("plan_invalid_or_expired")
        if payload.get("kind") == "rollback":
            return self._check_rollback_payload(payload)
        return self._check_install_payload(payload)

    def _decide(self, payload, proof_token, challenge, decision, kind):
        rid, _ = payload_hash(payload)
        if type(challenge) is not str or len(challenge) != 64:
            raise ExecutionDenied("challenge_unknown")
        try:
            nonce = decision_nonce(decision, rid, rid, challenge)
            fingerprint = self.verifier.verify(proof_token, owner=self.owner, expected_nonce=nonce)
        except ProofDenied as denied:
            raise ExecutionDenied(denied.code) from None
        self.runs.consume(challenge=challenge, request_id=rid, decision=decision, proof=fingerprint, kind=kind)
        return rid

    def deny(self, payload, proof_token, challenge):
        """The owner said no. Recorded; this request can never be approved afterwards."""
        self._check_payload(payload)
        rid = self._decide(payload, proof_token, challenge, "deny", payload.get("kind", "install"))
        self.runs.finish(rid, "denied", {"ok": True, "denied_by_owner": True})
        return {"ok": True, "denied_by_owner": True}

    # -- install ------------------------------------------------------------------------------
    def _check_install_payload(self, payload, now=None):
        try:
            plan = validate_plan(payload, expected_owner=self.owner, expected_device=self.device,
                                 now=now or datetime.now(timezone.utc))
        except PlanError:
            raise ExecutionDenied("plan_invalid_or_expired") from None
        if plan.plan_sha256 != payload_hash(payload)[0]:
            raise ExecutionDenied("plan_hash_mismatch")
        if self.needs_attention():
            raise ExecutionDenied("owner_intervention_required")
        content = plan.content()
        if any(step["kind"] != "apt" for step in content["steps"]):
            raise ExecutionDenied("step_kind_not_supported_yet")
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        wanted = {p["name"]: p["version"] for step in content["steps"] for p in step["packages"]}
        if catalog.is_generic(content.get("software")):
            self._check_generic(content, wanted)
            return content
        try:
            entry = catalog.entry(content.get("software"))
        except catalog.CatalogError:
            raise ExecutionDenied("software_not_in_plan_or_catalog") from None
        if entry["kind"] != "apt" or not set(entry["packages"]) <= set(wanted):
            raise ExecutionDenied("plan_does_not_match_catalog_entry")
        # The root installer derives the allowed package set ITSELF: the catalog's packages plus
        # exactly the dependencies apt resolves for them now. Extra packages, even real Ubuntu ones,
        # are refused before anyone is asked to approve.
        try:
            allowed = {p["name"]: p["version"] for p in apt.resolve(list(entry["packages"]), self.run)}
        except (RuntimeError, ValueError):
            raise ExecutionDenied("catalog_resolution_failed") from None
        if wanted != allowed:
            raise ExecutionDenied("plan_is_not_the_exact_catalog_closure")
        return content

    def _check_generic(self, content, wanted):
        """AI-named Ubuntu packages: the root side re-derives everything from the requested names alone."""
        steps = content["steps"]
        requested = steps[0].get("requested") if len(steps) == 1 else None
        if not requested or content["software"] != catalog.generic_slug(requested):
            raise ExecutionDenied("generic_install_not_well_formed")
        for name in requested:
            code = impact.refusal_for(name)
            if code:
                raise ExecutionDenied("blocked_package:" + code)
        try:
            analysis = apt.analyze(list(requested), self.run)
        except (RuntimeError, ValueError):
            raise ExecutionDenied("catalog_resolution_failed") from None
        code, _ = impact.check_transaction(requested, analysis)
        if code:
            raise ExecutionDenied("blocked_package:" + code)
        if not set(requested) <= set(analysis["installs"]) or wanted != analysis["installs"]:
            raise ExecutionDenied("plan_is_not_the_exact_package_closure")

    def install(self, payload, proof_token, challenge, *, now=None):
        """Execute an approved install. Raises ExecutionDenied before any change; else returns a result.
        Holds the operation lock for the whole change so a backup can never read half-written records."""
        try:
            with statelock.operation(self.dir):
                return self._install_locked(payload, proof_token, challenge, now=now)
        except statelock.Busy:
            raise ExecutionDenied("a_backup_or_restore_is_running_try_again") from None

    def _install_locked(self, payload, proof_token, challenge, *, now=None):
        content = self._check_install_payload(payload, now)
        rid = self._decide(payload, proof_token, challenge, "approve", "install")
        try:
            result = self._install_apt(rid, content)
        except ExecutionDenied as stopped:
            result = {"ok": False, "stopped": stopped.code, "changed_anything": False}
        except Exception as error:
            result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__, "changed_anything": False}
        state = ("needs_owner_intervention" if result.get("needs_owner_intervention")
                 else "done" if result.get("ok") else "failed")
        self._record_result(rid, state, result)
        return result

    def _record_result(self, rid, state, result):
        """Save the outcome. If that fails after the machine may have changed, leave a durable owner-must-check
        record (new installs are refused) and let the failure surface: the run row stays 'running', which
        reconciliation reports as unknown, never as 'nothing changed'."""
        try:
            self.runs.finish(rid, state, result)
        except Exception as error:
            if result.get("changed_anything") is not False:
                try:
                    self._attention(rid, result.get("rollback_id"), "result_not_recorded_%s" % type(error).__name__,
                                    "the run finished but its result could not be saved")
                except Exception:
                    pass
            raise

    def _fetch_verified(self, pins, cache):
        """Source checks, then download the exact files and prove each is the one the signed index lists."""
        if apt.untrusted_sources(self.sources_root) or apt.insecure_config(self.run):
            raise ExecutionDenied("untrusted_package_source_configured")
        for name, version in pins:
            if not apt.origin_is_ubuntu(name, version, self.run):
                raise ExecutionDenied("package_not_from_the_ubuntu_archive")
        hashes = {}
        for name, version in pins:
            found = apt.sha256_of_version(name, version, self.run)
            if len(found) != 1:
                raise ExecutionDenied("package_source_ambiguous")
            hashes[name] = next(iter(found))
        if not apt.download(pins, cache, self.run):
            raise ExecutionDenied("download_failed")
        for name, version in pins:                                   # the file apt fetched is the indexed one
            files = sorted(cache.glob("%s_*.deb" % name))
            if len(files) != 1 or _sha256(files[0]) != hashes[name]:
                raise ExecutionDenied("downloaded_file_does_not_match_the_signed_index")

    def _inspect_downloads(self, pins, cache):
        """Notes about what the downloaded packages ship. Refuses (fail closed) on anything unreadable or dangerous."""
        notes = []
        for name, version in pins:
            files = sorted(cache.glob("%s_*.deb" % name))
            if len(files) != 1:
                raise ExecutionDenied("package_contents_unreadable")
            code, found = impact.inspect_listing(apt.deb_listing(files[0], self.run))
            if code:
                raise ExecutionDenied("blocked_package:" + code)
            notes += ["%s: %s" % (name, n) for n in found]
            try:
                notes += ["%s: %s" % (name, n) for n in impact.inspect_scripts(
                    apt.deb_script(files[0], "preinst", self.run), apt.deb_script(files[0], "postinst", self.run))]
            except Exception:
                pass                                                     # notes only; the listing check above is the gate
        return notes

    def package_notes(self, content):
        """Findings the owner must see BEFORE approving an assistant-named install: downloads the exact files into a
        private folder, verifies them against the signed index and inspects them. Nothing is installed."""
        wanted = {p["name"]: p["version"] for step in content["steps"] for p in step["packages"]}
        pins = sorted(wanted.items())
        cache = self.dir / "preview" / secrets.token_hex(8)
        try:
            self._fetch_verified(pins, cache)
            return self._inspect_downloads(pins, cache)
        finally:
            shutil.rmtree(cache, ignore_errors=True)

    def _install_apt(self, rid, content):
        wanted = {p["name"]: p["version"] for step in content["steps"] for p in step["packages"]}
        pins = sorted(wanted.items())
        before = apt.state(self.run)
        manual_before = apt.manual_packages(self.run)
        upgraded = sorted(n for n in wanted if n in before and before[n] != wanted[n])
        expected = {n: v for n, v in wanted.items() if before.get(n) != v}
        cache = self.dir / "downloads" / rid
        self._fetch_verified(pins, cache)
        if catalog.is_generic(content.get("software")):               # what the downloaded files would put on disk
            self._inspect_downloads(pins, cache)
        try:
            would, removals, chosen = apt.simulate_install(apt._pins(pins), self.run, cache=cache, no_download=True,
                                                           with_origins=True)
        except RuntimeError:
            raise ExecutionDenied("approved_version_no_longer_available") from None
        if any(not apt.origins_trusted(chosen.get(n)) for n in would):
            raise ExecutionDenied("package_not_from_the_ubuntu_archive")
        if removals:
            raise ExecutionDenied("would_remove_packages")
        if would != expected:
            raise ExecutionDenied("drift_from_approved_plan")

        rollback_id = secrets.token_hex(16)
        manifest = self._backup(rollback_id, before, manual_before, upgraded, wanted)
        # From here on the machine may change. Any failure, including in our own bookkeeping, must
        # either restore from the backup or leave a durable "owner must check" record.
        try:
            return self._change_and_record(rid, rollback_id, manifest, pins, wanted, expected, before, cache, content)
        except Exception as error:
            return self._recover(rid, rollback_id, manifest, before, "post_change_failure_%s" % type(error).__name__)

    def _change_and_record(self, rid, rollback_id, manifest, pins, wanted, expected, before, cache, content):
        if not apt.install(pins, self.run, cache=cache, no_download=True):
            return self._recover(rid, rollback_id, manifest, before, "install_failed")
        after = apt.state(self.run)
        diff = self._diff(before, after)
        if diff != expected:
            return self._recover(rid, rollback_id, manifest, before, "transaction_differed_from_plan",
                                 extra_added=sorted(n for n, v in diff.items()
                                                    if v is not None and before.get(n) is None and n not in wanted))
        manifest["after"] = {n: after.get(n) for n in wanted}
        self._write_manifest(rollback_id, manifest)
        self.ledger.record(rollback_id=rollback_id, software=content["software"], owner=self.owner,
                           device=self.device, request_id=rid, snapshot_id=rollback_id, snapshot_verified=True)
        shutil.rmtree(cache, ignore_errors=True)
        return {"ok": True, "installed": [{"name": n, "version": v} for n, v in pins],
                "rollback_id": rollback_id, "backup_verified": True, "backup_scope": BACKUP_SCOPE, "limits": LIMITS,
                "backup": {"saved_package_files": len(manifest["debs"]), "saved_settings_files": len(manifest["files"])}}

    def _recover(self, rid, rollback_id, manifest, before, reason, extra_added=()):
        """Put the machine back from the backup. If we can't PROVE it is back, record that durably."""
        left, detail = None, None
        try:
            try:
                if not extra_added:                               # find packages that appeared that we didn't plan
                    now = apt.state(self.run)
                    extra_added = sorted(n for n, v in now.items() if before.get(n) is None and n not in manifest["before"])
            except Exception:
                extra_added = ()
            restored = self._restore(manifest, extra_added=extra_added)
            left = self._diff(before, apt.state(self.run))
            if not restored and not left:
                # Package versions match but a settings file or an auto/manual mark did not come back.
                detail = "settings_or_marks_not_restored"
                left = None
        except Exception as error:
            detail = "recovery_failed_%s" % type(error).__name__
        if left == {}:
            return {"ok": False, "stopped": reason, "changed_anything": False, "restored_from_backup": True}
        detail = detail or "not_restored: %s" % ", ".join(sorted(left or []))
        self._attention(rid, rollback_id, reason, detail)
        return {"ok": False, "stopped": reason, "changed_anything": True, "restored_from_backup": False,
                "not_restored": sorted(left or []), "needs_owner_intervention": True, "limits": LIMITS}

    @staticmethod
    def _diff(before, after):
        changed = {n: v for n, v in after.items() if before.get(n) != v}
        for n in before:
            if n not in after:
                changed[n] = None
        return changed

    # -- backup ---------------------------------------------------------------------------------
    def _backup(self, rollback_id, before, manual_before, upgraded, wanted):
        root = self.dir / "snapshots" / rollback_id
        (root / "debs").mkdir(parents=True, mode=0o700)
        (root / "files").mkdir(mode=0o700)
        debs = {}
        if upgraded:
            old = [(n, before[n]) for n in upgraded]
            if not apt.download(old, root / "debs", self.run):
                raise ExecutionDenied("backup_not_possible_current_version_unavailable")
            for name, version in old:
                matches = sorted((root / "debs").glob("%s_*.deb" % name))
                if len(matches) != 1:
                    raise ExecutionDenied("backup_not_possible_current_version_unavailable")
                debs[name] = {"version": version, "file": matches[0].name, "sha256": _sha256(matches[0])}
        files = {}
        for path in (apt.conffiles(upgraded, self.run) if upgraded else []):
            source = self.file_root / path.lstrip("/")
            if source.is_file() and not source.is_symlink():
                target = root / "files" / hashlib.sha256(path.encode()).hexdigest()
                shutil.copy2(source, target)
                files[path] = {"copy": target.name, "sha256": _sha256(target), "mode": source.stat().st_mode & 0o7777}
        manifest = {"rollback_id": rollback_id, "before": {n: before.get(n) for n in wanted},
                    "manual_before": sorted(n for n in wanted if n in manual_before),
                    "debs": debs, "files": files, "after": None}
        self._write_manifest(rollback_id, manifest)
        self._verify_backup(rollback_id)
        return manifest

    def _write_manifest(self, rollback_id, manifest):
        path = self.dir / "snapshots" / rollback_id / "manifest.json"
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, json.dumps(manifest, sort_keys=True).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def _verify_backup(self, rollback_id):
        """Every saved file is still there with its recorded hash. Returns the manifest."""
        root = self.dir / "snapshots" / rollback_id
        try:
            manifest = json.loads((root / "manifest.json").read_text())
            for item in manifest["debs"].values():
                if _sha256(root / "debs" / item["file"]) != item["sha256"]:
                    raise ExecutionDenied("backup_damaged")
            for item in manifest["files"].values():
                if _sha256(root / "files" / item["copy"]) != item["sha256"]:
                    raise ExecutionDenied("backup_damaged")
        except (OSError, ValueError, KeyError):
            raise ExecutionDenied("backup_damaged") from None
        return manifest

    def _restore(self, manifest, extra_added=()):
        """Put the affected packages, settings files and marks back. True if dpkg agrees afterwards."""
        root = self.dir / "snapshots" / manifest["rollback_id"]
        before = manifest["before"]
        current = apt.installed_versions(sorted(before), self.run)
        added = sorted({n for n, v in before.items() if v is None and current[n] is not None} | set(extra_added))
        ok = True
        if added:
            ok = apt.remove(added, self.run) and ok
        olds = sorted((n, item["version"]) for n, item in manifest["debs"].items())
        if olds:
            ok = apt.install(olds, self.run, cache=root / "debs", no_download=True, allow_downgrades=True) and ok
        for path, item in manifest["files"].items():
            target = self.file_root / path.lstrip("/")
            try:
                shutil.copy2(root / "files" / item["copy"], target)
                os.chmod(target, item["mode"])
            except OSError:
                ok = False
        manual = set(manifest["manual_before"])
        present = [n for n, v in before.items() if v is not None]
        ok = apt.set_marks(manual & set(present), set(present) - manual, self.run) and ok
        return ok and apt.installed_versions(sorted(before), self.run) == before

    # -- rollback -------------------------------------------------------------------------------
    def _check_rollback_payload(self, payload):
        if (payload.get("kind") != "rollback" or payload.get("owner") != self.owner
                or payload.get("device") != self.device):
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
        if payload.get("request_id") != entry["request_id"] or payload.get("snapshot_id") != entry["snapshot_id"]:
            raise ExecutionDenied("rollback_request_invalid")
        return entry

    def rollback(self, payload, proof_token, challenge):
        try:
            with statelock.operation(self.dir):
                return self._rollback_locked(payload, proof_token, challenge)
        except statelock.Busy:
            raise ExecutionDenied("a_backup_or_restore_is_running_try_again") from None

    def _rollback_locked(self, payload, proof_token, challenge):
        entry = self._check_rollback_payload(payload)
        manifest = self._verify_backup(entry["snapshot_id"])
        self._rollback_preflight(manifest)                      # refuses before the approval is consumed
        rid = self._decide(payload, proof_token, challenge, "approve", "rollback")
        try:
            self._rollback_preflight(manifest)                  # and again, right before acting
        except ExecutionDenied as stopped:
            result = {"ok": False, "stopped": stopped.code, "changed_anything": False}
        except Exception as error:
            result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__, "changed_anything": False}
        else:
            try:                                                # from here the machine changes
                ok = self._restore(manifest)
                if ok:
                    self.ledger.mark_rolled_back(entry["rollback_id"])
                    result = {"ok": True, "restored": manifest["before"], "limits": LIMITS}
                else:
                    self._attention(rid, entry["rollback_id"], "rollback_restore_incomplete", None)
                    result = {"ok": False, "stopped": "restore_incomplete", "changed_anything": True,
                              "needs_owner_intervention": True, "limits": LIMITS}
            except Exception as error:
                reason = "rollback_failed_%s" % type(error).__name__
                try:
                    self._attention(rid, entry["rollback_id"], reason, None)
                except Exception:
                    pass
                result = {"ok": False, "stopped": reason, "changed_anything": True, "needs_owner_intervention": True}
        state = ("needs_owner_intervention" if result.get("needs_owner_intervention")
                 else "done" if result["ok"] else "failed")
        self._record_result(rid, state, result)
        return result

    def _rollback_preflight(self, manifest):
        after, before = manifest["after"], manifest["before"]
        if after is None or apt.installed_versions(sorted(after), self.run) != after:
            raise ExecutionDenied("changed_since_install")
        added = sorted(n for n, v in before.items() if v is None)
        if added:
            try:
                removals = apt.simulate_remove(added, self.run)
            except RuntimeError:
                raise ExecutionDenied("rollback_simulation_failed") from None
            if set(removals) != set(added):
                raise ExecutionDenied("rollback_would_affect_other_packages")
        olds = sorted((n, item["version"]) for n, item in manifest["debs"].items())
        if olds:
            root = self.dir / "snapshots" / manifest["rollback_id"] / "debs"
            try:
                would, removals = apt.simulate_install(apt._pins(olds), self.run, cache=root, no_download=True,
                                                       allow_downgrades=True)
            except RuntimeError:
                raise ExecutionDenied("rollback_simulation_failed") from None
            if removals or would != dict(olds):
                raise ExecutionDenied("rollback_would_affect_other_packages")
