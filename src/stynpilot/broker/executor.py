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
import pwd
import re
import secrets
import shutil
import sys
import sqlite3
import threading
import time
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import catalog, impact, managed_activity, root_restore, statelock
from ..ledger import InstallLedger, LedgerError
from ..plan import PlanError, validate_plan
from ..requests import request_id as payload_hash
from .. import backup, release, vault
from . import apt
from .. import runner as runner_policy
from .jobs import JobError
from .selftest import clean_diagnostics
from .passkeys import PasskeyError
from .release_authority import AuthorityError, _write_private
from .. import webauthn
from .proof import ProofDenied, decision_nonce, render_summary, summary_hash
from .upgrade import UpgradeRefused, Upgrader

ReleaseErrorTypes = (release.ReleaseError,)

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

    def consume(self, *, challenge, request_id, decision, proof, kind, restore_payload=None):
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
                state = "denied" if decision == "deny" else "running"
                if restore_payload is not None:
                    state = "restore_queued"
                db.execute("INSERT INTO runs (request_id,proof,kind,state,started,result) VALUES (?,?,?,?,?,?)",
                           (request_id, proof, kind, state, self.clock(), json.dumps(restore_payload) if restore_payload else None))
        except sqlite3.IntegrityError:
            raise ExecutionDenied("already_used") from None

    def peek(self, *, challenge, request_id, decision):
        """The same checks ``consume`` makes, without using the challenge (lets a bad passkey try again)."""
        with self._tx() as db:
            row = db.execute("SELECT * FROM challenges WHERE challenge=?", (challenge if type(challenge) is str else "",)).fetchone()
            if row is None or row["request_id"] != request_id or row["decision"] != decision:
                raise ExecutionDenied("challenge_unknown")
            if row["used"] is not None:
                raise ExecutionDenied("already_used")
            if row["expires"] <= self.clock():
                raise ExecutionDenied("challenge_expired")

    def finish(self, request_id, state, result):
        with self._tx() as db:
            db.execute("UPDATE runs SET state=?, result=?, finished=? WHERE request_id=?",
                       (state, json.dumps(result, sort_keys=True), self.clock(), request_id))

    def unsettled_rotations(self):
        """Installer-side key rotations recorded as interrupted ('in_progress'), to be settled with their real outcome."""
        with self._tx() as db:
            rows = db.execute("SELECT request_id, result FROM runs WHERE state='failed' AND result LIKE '%\"rotation\": \"in_progress\"%'")
            out = []
            for row in rows:
                try:
                    result = json.loads(row["result"])
                except ValueError:
                    continue
                if result.get("action") == "rotate_key" and result.get("side") == "root" and result.get("rotation") == "in_progress":
                    out.append(row["request_id"])
            return out

    def running_operations(self):
        with self._tx() as db:
            return db.execute("SELECT request_id, kind FROM runs WHERE state='running'").fetchall()

    def running(self):
        return [row["request_id"] for row in self.running_operations()]

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
                 sources_root="/etc/apt", file_root="/", owner_uid=None, release_keys=None, fetch_release=None,
                 launch_worker=None, upgrade_options=None, jobs=None, passkeys=None,
                 allow_remote_activation=False, authority=None, sleep=time.sleep, root_vault=None):
        self.dir = Path(state_dir)
        self.vault = None                                      # the root backup vault (dev22), set by the installer at start
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
        self.restore_available = lambda: False
        self.owner, self.device, self.verifier, self.run = owner, device, verifier, run
        self.sources_root, self.file_root = sources_root, Path(file_root)
        self.runs = Runs(self.dir / "runs.sqlite3")
        with self.runs._tx() as db:
            queued = db.execute("SELECT request_id,result FROM runs WHERE kind=? AND state='restore_queued'",
                                (root_restore.KIND,)).fetchall()
        for rid, raw in queued:
            root_restore.wake(self.dir, rid, json.loads(raw))
        self.ledger = InstallLedger(self.dir / "installs.sqlite3")
        for sub in ("snapshots", "downloads", "attention", "attention-resolved"):
            (self.dir / sub).mkdir(exist_ok=True, mode=0o700)
        self.owner_uid = owner_uid
        self.inference_settlement_fence = None
        self.upgrader = Upgrader(self, keys=release_keys, fetch=fetch_release, launch=launch_worker,
                                 options=upgrade_options)
        self.jobs = jobs
        # Activating a passkey through the owner-side service is OFF unless explicitly allowed: by default the owner confirms a new
        # passkey at the computer's console (passkey_console.py), which does not depend on that service.
        self.allow_remote_activation = allow_remote_activation
        self.passkeys = passkeys                  # PasskeyStore or None (passkeys not configured)
        self.authority = authority                # release_authority.Authority or None (release publishing not configured)
        self._sleep = sleep
        self._builds = {}
        if jobs is not None:
            jobs.reconcile()
        # A run still marked "running" means the installer died mid-change. We can't know what state
        # the machine is in, so record that durably and refuse new installs until the owner looks.
        # An UPGRADE run is different: its worker runs on its own and outlives this installer's restart, so it is
        # settled from its job folder (or left running while its worker is alive), never blamed on this restart.
        for rid, kind in self.runs.running_operations():
            if self.upgrader.is_job(rid):
                self._settle(rid)
                continue
            if self._release_pending(rid):
                continue                      # a spent release approval waiting to be resumed: not damage, never "attention"
            if root_vault is not None and self._recover_root_rotation(root_vault, rid, kind):
                continue
            if not os.path.lexists(self.dir / "attention" / ("%s.json" % rid)):
                self._attention(rid, None, "interrupted_by_restart_or_crash", None)
            self.runs.finish(rid, "needs_owner_intervention", {"ok": False, "stopped": "interrupted_by_restart_or_crash",
                                                               "needs_owner_intervention": True})

        if root_vault is not None:
            self.attach_vault(root_vault)

    def _recover_root_rotation(self, root_vault, rid, kind):
        """Classify the spent approval before generic crash recovery and before starting the scheduler."""
        operation, _, mode = kind.rpartition(".")
        if operation != "backup.rotate_key.root" or mode not in vault.ROTATION_MODES or root_vault.side != "root":
            return False
        result = {"action": "rotate_key", "side": "root", "mode": mode}
        try:
            journal = root_vault._journal()
            if journal is None:
                if root_vault.rotation_outcome(rid) != "completed":
                    return False       # includes death before journal creation: never start again from approval alone
                self.runs.finish(rid, "done", dict(result, ok=True, rotation="completed", finished_later=True))
                return True
            if journal["request_id"] != rid or journal["mode"] != mode or journal["state"] == "awaiting_authorization":
                return False
            progress = root_vault.rotation_progress()
        except (vault.VaultError, OSError, ValueError, TypeError):
            return False
        self.runs.finish(rid, "failed", dict(result, ok=False, rotation="in_progress", progress=progress,
                                             stopped="interrupted_by_restart_or_crash"))
        return True

    def status(self, request_id):
        """What the installer's own durable record says about this request (reconciliation source)."""
        record = self.runs.status(request_id)
        if record["state"] == "restore_queued":
            return {"state": "running", "result": {"pending": True, "action": "restore_root", "side": "root"}}
        if record["state"] == "running" and self.upgrader.is_job(request_id):
            self._settle(request_id)
            record = self.runs.status(request_id)
        tx = self._tx_load(request_id) if re.fullmatch(r"[0-9a-f]{64}", request_id or "") else None
        if tx:
            record = dict(record, release={"state": tx["state"], "approval_spent": tx["state"] != "authorized",
                                           "resumable": self._tx_resumable(tx) and record["state"] == "running"})
        return record

    def _settle_upgrades(self):
        for rid in self.runs.running():
            if self.upgrader.is_job(rid):
                self._settle(rid)

    def needs_attention(self):
        """Durable records of runs that may have left the machine changed. New installs are refused while any exist.
        A record about a failed UPGRADE is first re-checked against the real machine (at most every 30 s): if the
        failure is provably over, it is moved (never deleted) to ``attention-resolved`` with the proof attached."""
        self._resolve_stale_attention()
        return sorted(p.name for p in (self.dir / "attention").glob("*.json"))

    RESOLVE_EVERY = 30

    @staticmethod
    def _log(line):
        """One audit line to the installer's journal (visible through the read-only logs tool). Names and counts only."""
        try:
            print("stynpilot-installer: " + line, file=sys.stderr, flush=True)
        except OSError:
            pass

    def _resolve_stale_attention(self):
        if not any((self.dir / "attention").glob("*.json")):
            return
        now = time.monotonic()
        if now - getattr(self, "_resolve_at", -1e9) < self.RESOLVE_EVERY:
            return
        self._resolve_at = now
        for path in sorted((self.dir / "attention").glob("*.json")):
            try:
                record = json.loads(path.read_text())
                rid = record["request_id"]
                if path.is_symlink() or path.name != "%s.json" % rid or not self.upgrader.is_job(rid):
                    continue
                if record.get("reason") not in self.upgrader.RESOLVABLE:
                    continue
                ok, checks = self.upgrader.verify_recovered(rid)
                if not ok:
                    self._log("attention_kept request=%s failed_checks=%s" % (
                        rid[:12], ",".join(sorted(k for k, v in checks.items() if v is not True)) or "none"))
                    continue
                record["resolution"] = {"resolved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                        "by": "installer_verification", "checks": checks,
                                        "installed_version": self.upgrader.installed_version()}
                target = self.dir / "attention-resolved" / path.name
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, json.dumps(record, sort_keys=True).encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
                path.unlink()                    # only after the audit copy is safely on disk
                self._log("attention_released request=%s reason=%s installed=%s checks=%s" % (
                    rid[:12], record.get("reason"), record["resolution"]["installed_version"], ",".join(sorted(checks))))
            except (OSError, ValueError, KeyError, TypeError, UpgradeRefused):
                continue                         # anything unclear: the record stays and the owner is still asked

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
        if payload.get("kind") == "upgrade":
            try:
                summary = self.upgrader.summary(payload)
            except UpgradeRefused as refused:
                raise ExecutionDenied(refused.code) from None
            return {"request_id": rid, "decision": decision, "challenge": challenge,
                    "nonce": decision_nonce(decision, rid, rid, challenge),
                    "summary": summary, "summary_sha256": summary_hash(summary), "expires_in": CHALLENGE_LIFETIME}
        summary = render_summary(payload)
        if payload.get("kind") in ("runner", "passkey", "release", "backup"):
            return {"request_id": rid, "decision": decision, "challenge": challenge,
                    "nonce": decision_nonce(decision, rid, rid, challenge),
                    "summary": summary, "summary_sha256": summary_hash(summary), "expires_in": CHALLENGE_LIFETIME}
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
        if payload.get("kind") == "passkey":                  # pure bookkeeping: must keep working (revocation!) in any state
            return self._check_passkey_payload(payload)
        self._settle_upgrades()
        if any(self.upgrader.is_job(r) for r in self.runs.running()):
            raise ExecutionDenied("an_upgrade_is_still_running")
        if payload.get("kind") == "upgrade":
            return self._check_upgrade_payload(payload)
        if payload.get("kind") == "release":
            return self._check_release_payload(payload)
        if payload.get("kind") == "runner":
            return self._check_runner_payload(payload)
        if payload.get("kind") == "backup":
            return self._check_backup_payload(payload)
        if payload.get("kind") == "rollback":
            return self._check_rollback_payload(payload)
        return self._check_install_payload(payload)

    def _prove(self, rid, proof_token, challenge, decision):
        """Check the owner's proof (Auth0 token or passkey assertion) for exactly this decision; uses nothing up.
        Returns (fingerprint, passkey-or-None). The ONLY place an owner proof is accepted."""
        if type(challenge) is not str or len(challenge) != 64:
            raise ExecutionDenied("challenge_unknown")
        try:
            nonce = decision_nonce(decision, rid, rid, challenge)
            if type(proof_token) is str and proof_token.startswith("{"):
                return self._verify_passkey(proof_token, nonce, rid, decision)
            return self.verifier.verify(proof_token, owner=self.owner, expected_nonce=nonce), None
        except ProofDenied as denied:
            raise ExecutionDenied(denied.code) from None

    def _used_passkey(self, passkey, rid, decision):
        """Record the accepted proof (signature counter + audit chain) BEFORE the challenge is used up. If it cannot be
        recorded the approval is refused (fail closed): counter enforcement and the audit trail never silently lapse."""
        if passkey is not None:
            try:
                self.passkeys.record_use(passkey[0]["credential_id"], passkey[1], request_id=rid, decision=decision)
            except Exception:
                raise ExecutionDenied("passkey_record_failed_nothing_was_approved") from None

    def _decide(self, payload, proof_token, challenge, decision, kind):
        rid, _ = payload_hash(payload)
        fingerprint, passkey = self._prove(rid, proof_token, challenge, decision)
        if (decision == "approve" and payload.get("kind") == "runner"
                and payload.get("action") == "settle_inference" and passkey is None):
            raise ExecutionDenied("inference_settlement_requires_passkey")
        self._used_passkey(passkey, rid, decision)
        self.runs.consume(challenge=challenge, request_id=rid, decision=decision, proof=fingerprint, kind=kind)
        return rid

    # -- passkey proofs --------------------------------------------------------------------------------------------
    _PASSKEY_PROOF_KEYS = {"credential_id", "client_data_json", "authenticator_data", "signature"}

    def _verify_passkey(self, token, nonce, rid, decision):
        """A WebAuthn assertion whose challenge IS the decision nonce (request, exact plan, decision, root challenge).
        Needs an enrolled, un-revoked passkey, the exact origin, user verification, and a valid signature."""
        if self.passkeys is None:
            raise ExecutionDenied("passkeys_not_configured")
        try:
            data = json.loads(token) if len(token) <= 8192 else None
        except ValueError:
            data = None
        if type(data) is not dict or set(data) != self._PASSKEY_PROOF_KEYS or any(type(v) is not str for v in data.values()):
            raise ExecutionDenied("proof_invalid")
        try:
            row = self.passkeys.lookup(data["credential_id"])
            if row is None:
                raise ExecutionDenied("passkey_unknown_or_revoked")
            try:
                auth = webauthn.verify_assertion(data, rp_id=self.passkeys.rp_id, origin=self.passkeys.origin,
                                                 challenge=bytes.fromhex(nonce), public_key_xy=bytes.fromhex(row["public_key"]))
            except webauthn.WebAuthnError as error:
                raise ExecutionDenied("passkey_" + error.code) from None
            try:
                self.passkeys.check_counter(row, auth)
            except PasskeyError as error:
                raise ExecutionDenied(error.code) from None
        except ExecutionDenied as refused:
            try:
                self.passkeys.audit("refused", {"request_id": rid, "decision": decision, "code": refused.code})
            except Exception:
                pass
            raise
        fingerprint = hashlib.sha256(("passkey|%s|%s" % (row["credential_id"], data["signature"])).encode()).hexdigest()
        return fingerprint, (row, auth)

    def passkey_precheck(self, payload, proof_token, challenge, decision):
        """Would this passkey proof be accepted right now? Changes nothing and uses nothing up, so a wrong fingerprint or a
        cancelled prompt leaves the request exactly as it was and the owner can simply try again."""
        if decision not in ("approve", "deny"):
            raise ExecutionDenied("invalid_decision")
        self._check_payload(payload)
        self._auth0_only(payload)
        rid, _ = payload_hash(payload)
        if type(challenge) is not str or len(challenge) != 64:
            raise ExecutionDenied("challenge_unknown")
        self.runs.peek(challenge=challenge, request_id=rid, decision=decision)
        try:
            nonce = decision_nonce(decision, rid, rid, challenge)
        except ProofDenied as denied:
            raise ExecutionDenied(denied.code) from None
        if type(proof_token) is not str or not proof_token.startswith("{"):
            raise ExecutionDenied("proof_invalid")
        self._verify_passkey(proof_token, nonce, rid, decision)
        return {"ok": True}

    # -- passkey administration (YELLOW): enroll one, revoke one ---------------------------------------------------------
    _PASSKEY_KEYS = {"kind", "action", "label", "kid", "pub", "owner", "device", "expires_at"}

    @staticmethod
    def _auth0_only(payload):
        """Adding a passkey is never approved by a passkey: a stolen phone must not be able to add its own successors."""
        if payload.get("kind") == "passkey" and payload.get("action") in ("enroll", "activate"):
            raise ExecutionDenied("adding_a_passkey_needs_the_auth0_sign_in")

    def _check_passkey_payload(self, payload):
        if self.passkeys is None:
            raise ExecutionDenied("passkeys_not_configured")
        action = payload.get("action")
        if (set(payload) != self._PASSKEY_KEYS or payload.get("kind") != "passkey" or action not in ("enroll", "activate", "revoke")
                or payload.get("owner") != self.owner or payload.get("device") != self.device):
            raise ExecutionDenied("passkey_request_invalid")
        from .passkeys import KID, LABEL, PUBHASH
        label, kid, pub = payload.get("label"), payload.get("kid"), payload.get("pub")
        labeled = type(label) is str and bool(LABEL.fullmatch(label))
        named = type(kid) is str and bool(KID.fullmatch(kid))
        hashed = type(pub) is str and bool(PUBHASH.fullmatch(pub))
        if action == "activate" and not self.allow_remote_activation:
            raise ExecutionDenied("activation_needs_the_console")
        shape = {"enroll": labeled and kid == "" and pub == "", "activate": labeled and named and hashed,
                 "revoke": label == "" and named and pub == ""}[action]
        if not shape:
            raise ExecutionDenied("passkey_request_invalid")
        try:
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ExecutionDenied("passkey_request_invalid") from None
        if expires <= datetime.now(timezone.utc):
            raise ExecutionDenied("plan_invalid_or_expired")
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        return payload

    def passkey_admin(self, payload, proof_token, challenge):
        """Execute an owner-approved passkey change. Enrolling only OPENS a short window; the phone creates the key inside it
        (pending, powerless); a separate Auth0-approved ACTIVATE that commits to the exact key's hash makes it live."""
        self._check_payload(payload)
        self._auth0_only(payload) if (type(proof_token) is str and proof_token.startswith("{")) else None
        rid = self._decide(payload, proof_token, challenge, "approve", "passkey")
        by = "passkey" if type(proof_token) is str and proof_token.startswith("{") else "auth0"
        try:
            if payload["action"] == "enroll":
                self.passkeys.open_window(rid, payload["label"], by)
                result = {"ok": True, "action": "enroll", "enrollment_open": True, "label": payload["label"]}
            elif payload["action"] == "activate":
                left = self.passkeys.activate(payload["kid"], payload["label"], payload["pub"], rid, by)
                result = {"ok": True, "action": "activate", "kid": payload["kid"], "label": payload["label"], "passkeys_active": left}
            else:
                left = self.passkeys.revoke(payload["kid"], rid)
                result = {"ok": True, "action": "revoke", "kid": payload["kid"], "passkeys_active": left}
        except PasskeyError as stopped:
            result = {"ok": False, "stopped": stopped.code, "changed_anything": False, "action": payload["action"]}
        except Exception as error:
            result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__, "changed_anything": None,
                      "action": payload["action"]}
        self._record_result(rid, "done" if result.get("ok") else "failed", result)
        return result

    def passkey_list(self):
        if self.passkeys is None:
            return {"configured": False, "passkeys": [], "retirement_ready": False}
        active = self.passkeys.active()
        return {"configured": True, "rp_id": self.passkeys.rp_id, "origin": self.passkeys.origin, "passkeys": active,
                "pending": [{"kid": k["kid"], "label": k["label"]} for k in self.passkeys.pending()],
                "retirement_ready": len(active) >= 2, "audit_chain_ok": self.passkeys.audit_ok(),
                "remote_activation": bool(self.allow_remote_activation),
                "quarantined": [{"kid": k["kid"], "label": k["label"]} for k in self.passkeys.quarantined()]}

    def passkey_begin(self, request_id):
        if self.passkeys is None:
            raise ExecutionDenied("passkeys_not_configured")
        try:
            return self.passkeys.begin(request_id)
        except PasskeyError as refused:
            raise ExecutionDenied(refused.code) from None

    def passkey_complete(self, request_id, response):
        if self.passkeys is None:
            raise ExecutionDenied("passkeys_not_configured")
        try:
            return self.passkeys.complete(request_id, response)
        except PasskeyError as refused:
            raise ExecutionDenied(refused.code) from None

    def deny(self, payload, proof_token, challenge):
        """The owner said no. Recorded; this request can never be approved afterwards."""
        self._check_payload(payload)
        rid = self._decide(payload, proof_token, challenge, "deny", payload.get("kind", "install"))
        self.runs.finish(rid, "denied", {"ok": True, "denied_by_owner": True})
        return {"ok": True, "denied_by_owner": True}

    # -- backup settings (dev23 stage 1): YELLOW, owner-approved ---------------------------------------
    _BACKUP_KEYS = {"kind", "action", "daily", "weekly", "owner", "device", "expires_at"}
    _ROTATE_KEYS = {"kind", "action", "side", "mode", "owner", "device", "expires_at"}

    def _check_backup_payload(self, payload):
        from .. import vault as _vault
        if getattr(self, "vault", None) is None:
            raise ExecutionDenied("backups_not_available")
        action = payload.get("action")
        if action == "retention":
            ok = set(payload) == self._BACKUP_KEYS and _vault.valid_retention(payload.get("daily"), payload.get("weekly"))
        elif action == "restore_root":
            details = self.vault._run("restore_preview", args={"archive": payload.get("archive")})
            ok = root_restore.matches(payload, details)
        elif action == "rotate_key":
            ok = (set(payload) == self._ROTATE_KEYS and payload.get("side") in ("root", "owner")
                  and payload.get("mode") in _vault.ROTATION_MODES)
        else:
            ok = False
        if (not ok or payload.get("kind") != "backup" or payload.get("owner") != self.owner
                or payload.get("device") != self.device):
            raise ExecutionDenied("backup_request_invalid")
        try:
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ExecutionDenied("backup_request_invalid") from None
        if expires <= datetime.now(timezone.utc):
            raise ExecutionDenied("plan_invalid_or_expired")
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        return payload

    def backup_admin(self, payload, proof_token, challenge):
        """Execute an owner-approved backup change (YELLOW). Retention: nothing is deleted at this moment. Key rotation, root side:
        runs here, resumable; owner side: the approval is verified and spent here, the owner's service then rotates its own vault."""
        self._check_payload(payload)
        self._no_other_change()
        action = payload["action"]
        if action == "restore_root":
            def authorize():
                if not self.restore_available():
                    raise ExecutionDenied("independent_restore_worker_unavailable")
                if (root_restore.held(self.dir) or self.vault._rotation_active()
                        or any(t.is_alive() for t in self._builds.values())
                        or self.jobs is None or not self.jobs.enabled() or self.jobs._live):
                    raise ExecutionDenied("restore_requires_idle_installer_and_runner")
                try:
                    managed_activity.require_idle(self.dir)
                except managed_activity.ActivityError as error:
                    raise ExecutionDenied(error.code) from None
                if not root_restore.still_current(self.vault, payload):
                    raise ExecutionDenied("approved_restore_changed")
                rid, _ = payload_hash(payload)
                fingerprint, key = self._prove(rid, proof_token, challenge, "approve")
                if key is None:
                    raise ExecutionDenied("root_restore_requires_passkey")
                if payload["expires_at"] <= datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
                    raise ExecutionDenied("plan_invalid_or_expired")
                self._used_passkey(key, rid, "approve")
                root_restore.wake(self.dir, rid, payload)
                self.runs.consume(challenge=challenge, request_id=rid, decision="approve", proof=fingerprint,
                                  kind=root_restore.KIND, restore_payload=payload)
                return {"pending": True, "action": action, "side": "root"}
            with statelock.operation(self.dir):
                return self.vault._locked(authorize)
        kind = "backup"
        if action == "rotate_key" and payload["side"] == "root":
            # Stored in the same transaction as the consumed proof, before any vault side effect.
            kind = "backup.rotate_key.root." + payload["mode"]
        rid = self._decide(payload, proof_token, challenge, "approve", kind)
        try:
            if action == "retention":
                result = dict(self.vault.set_retention(payload["daily"], payload["weekly"], rid), action=action)
            elif payload["side"] == "root":
                outcome = self.vault.rotate_key(payload["mode"], rid)
                result = dict(outcome, action=action, side="root")
                if not outcome.get("ok"):
                    result["stopped"] = outcome.get("error", "key_rotation_failed")    # 'rotation' + 'progress' say what is durable
            else:
                # The owner's own vault is not the installer's to touch: this records the owner's verified, spent approval as an
                # AUTHORIZATION for exactly this request. The owner side reports completion separately, from its own vault.
                result = {"ok": True, "action": action, "side": "owner", "mode": payload["mode"], "owner_side_authorized": rid,
                          "rotation": "authorized_owner_side_runs_it"}
        except Exception as error:
            result = {"ok": False, "stopped": getattr(error, "code", "unexpected_%s" % type(error).__name__), "action": action}
        self._record_result(rid, "done" if result.get("ok") else "failed", result)
        return result

    # -- sandboxed command runner ------------------------------------------------------------------
    _NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z")
    _RUNNER_KEYS = {"kind", "action", "name", "owner", "device", "expires_at"}

    def _check_runner_payload(self, payload):
        if self.jobs is None:
            raise ExecutionDenied("runner_not_available")
        action = payload.get("action")
        if (set(payload) != self._RUNNER_KEYS or payload.get("kind") != "runner" or action not in ("setup", "enroll", "unenroll", "settle_inference")
                or payload.get("owner") != self.owner or payload.get("device") != self.device):
            raise ExecutionDenied("runner_request_invalid")
        name = payload.get("name")
        if type(name) is not str or (name != "" if action == "setup" else not self._NAME.fullmatch(name)):
            raise ExecutionDenied("runner_request_invalid")
        if action == "settle_inference":
            if not managed_activity.ID.fullmatch(name):
                raise ExecutionDenied("activity_claim_invalid")
            try:
                if managed_activity.current(self.dir) != {"kind": "inference", "job_id": name}:
                    raise ExecutionDenied("activity_claim_changed")
            except managed_activity.ActivityError as error:
                raise ExecutionDenied(error.code) from None
        try:
            expires = datetime.strptime(payload["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            raise ExecutionDenied("runner_request_invalid") from None
        if expires <= datetime.now(timezone.utc):
            raise ExecutionDenied("plan_invalid_or_expired")
        if self.needs_attention():
            raise ExecutionDenied("owner_intervention_required")
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        if action != "setup" and not self.jobs.enabled():
            raise ExecutionDenied("runner_not_set_up")
        return payload

    def runner_admin(self, payload, proof_token, challenge):
        """Execute owner-approved runner changes through the single proof gate."""
        fence = nullcontext()
        if type(payload) is dict and payload.get("action") == "settle_inference":
            if self.inference_settlement_fence is None:
                raise ExecutionDenied("inference_fence_unavailable")
            fence = self.inference_settlement_fence()
        try:
            with fence:
                self._check_payload(payload)
                self._no_other_change()
                rid = self._decide(payload, proof_token, challenge, "approve", "runner")
                try:
                    result = self._runner_do(payload)
                except (JobError, runner_policy.RunnerError, managed_activity.ActivityError) as stopped:
                    result = {"ok": False, "stopped": stopped.code, "changed_anything": None, "action": payload["action"]}
                except Exception as error:
                    result = {"ok": False, "stopped": "unexpected_%s" % type(error).__name__, "changed_anything": None,
                              "action": payload["action"]}
                self._record_result(rid, "done" if result.get("ok") else "failed", result)
                return result
        except managed_activity.ActivityError as error:
            raise ExecutionDenied(error.code) from None

    def _workspace_path(self, name):
        if type(name) is not str or not self._NAME.fullmatch(name) or self.jobs.projects_dir is None:
            raise ExecutionDenied("workspace_name_invalid")
        return os.path.join(self.jobs.projects_dir, name)

    def _runner_do(self, payload):
        action = payload["action"]
        if action == "setup":
            info = self.jobs.setup()
            test = self.jobs.selftest()
            return {"ok": True, "action": "setup", "runner_user": info["runner_user"], "enabled": True,
                    "selftest": self._safe_selftest(test)}
        if action == "settle_inference":
            from ..inference_settlement import stop_and_verify
            # The exact claim and passkey were checked under exclusive admission.
            if managed_activity.current(self.dir) != {"kind": "inference", "job_id": payload["name"]}:
                raise managed_activity.ActivityError("activity_claim_changed")
            stop_and_verify(self.owner_uid)
            managed_activity.finish(self.dir, "inference", payload["name"])
            return {"ok": True, "action": action, "service_stopped": True}
        path = self._workspace_path(payload["name"])
        if action == "enroll":
            done = self.jobs.enroll(path)           # the owner-side helper creates the folder if needed; root never touches the home
            return {"ok": True, "action": "enroll", "workspace": payload["name"], "entries": done["entries"],
                    "skipped": done["skipped"]}
        self.jobs.unenroll(path)
        return {"ok": True, "action": "unenroll", "workspace": payload["name"]}

    @staticmethod
    def _safe_selftest(state):
        return {"ok": state.get("ok") is True, "ran": bool(state.get("ran")), "passed": list(state.get("passed", [])),
                "failed": list(state.get("failed", [])), "unverified": list(state.get("unverified", [])),
                "diagnostics": clean_diagnostics(state.get("diagnostics")),
                "version": str(state.get("version", ""))[:40], "at": state.get("at")}

    def runner_call(self, call, args):
        """GREEN runner operations (owner-only socket, no approval): refused while an upgrade runs."""
        if self.jobs is None:
            raise ExecutionDenied("runner_not_available")
        if type(call) is not str or type(args) is not dict:
            raise ExecutionDenied("runner_call_invalid")
        self._settle_upgrades()
        if any(self.upgrader.is_job(r) for r in self.runs.running()):
            raise ExecutionDenied("an_upgrade_is_still_running")
        try:
            return self._runner_green(call, args)
        except (JobError, runner_policy.RunnerError) as stopped:
            raise ExecutionDenied(stopped.code) from None

    def _runner_green(self, call, args):
        jobs, base = self.jobs, self.jobs.projects_dir
        name_of = lambda path: os.path.basename(path)
        if call == "status":
            enabled = jobs.enabled()
            test = jobs.selftest_state()
            return {"enabled": enabled, "selftest": self._safe_selftest(test) if test.get("ran") else {"ran": False, "ok": False},
                    "gate_open": not root_restore.held(self.dir) and enabled and test.get("ok") is True and test.get("version") == jobs.version,
                    "workspaces": [name_of(w["path"]) for w in jobs.workspaces()],
                    "recipes": {rid: r.title for rid, r in sorted(runner_policy.RECIPES.items())}}
        if call == "inference_claim_status":
            if args:
                raise ExecutionDenied("activity_claim_invalid")
            try:
                claim = managed_activity.current(self.dir)
            except managed_activity.ActivityError as error:
                raise ExecutionDenied(error.code) from None
            return {"claim": claim if claim and claim["kind"] == "inference" else None}
        if call in ("inference_claim", "inference_validate") and self.inference_settlement_fence is None:
            raise ExecutionDenied("inference_fence_unavailable")
        if call == "inference_validate":
            if set(args) != {"job_id"} or type(args["job_id"]) is not str or not managed_activity.ID.fullmatch(args["job_id"]):
                raise ExecutionDenied("activity_claim_invalid")
            from ..local_ai import require_workspace, LocalAIError
            try:
                require_workspace(self._runner_green("status", {}))
                if managed_activity.current(self.dir) != {"kind": "inference", "job_id": args["job_id"]}:
                    raise ExecutionDenied("activity_claim_changed")
            except (LocalAIError, managed_activity.ActivityError) as error:
                raise ExecutionDenied(error.code) from None
            return {"ok": True}
        if call in ("inference_claim", "inference_finish"):
            if set(args) != {"job_id"}:
                raise ExecutionDenied("activity_claim_invalid")
            try:
                if call == "inference_claim":
                    from ..local_ai import require_workspace, LocalAIError
                    try:
                        require_workspace(self._runner_green("status", {}))
                    except LocalAIError as error:
                        raise ExecutionDenied(error.code) from None
                    managed_activity.claim(self.dir, "inference", args["job_id"])
                else:
                    if managed_activity.current(self.dir) != {"kind": "inference", "job_id": args["job_id"]}:
                        raise ExecutionDenied("activity_claim_changed")
                    from ..inference_settlement import verify_idle
                    verify_idle(self.owner_uid)
                    managed_activity.finish(self.dir, "inference", args["job_id"])
            except managed_activity.ActivityError as error:
                raise ExecutionDenied(error.code) from None
            return {"ok": True}
        if call == "selftest":
            return self._safe_selftest(jobs.selftest())
        if call == "workspaces":
            return {"workspaces": [{"name": name_of(w["path"]), "enrolled_at": w["enrolled_at"]} for w in jobs.workspaces()]}
        if call == "run":
            recipe, extra = args.get("recipe"), args.get("args", [])
            if type(recipe) is not str or type(extra) is not list or not all(type(a) is str for a in extra):
                raise ExecutionDenied("runner_call_invalid")
            started = jobs.run(self._workspace_path(args.get("workspace")), recipe, extra)
            return {"job_id": started["job_id"], "argv": started["argv"], "limits": started["limits"]}
        if call == "jobs":
            ws = args.get("workspace")
            rows = jobs.recent(args.get("limit", 20), None if ws is None else self._workspace_path(ws))
            return {"jobs": [dict(r, workspace=name_of(r["workspace"])) for r in rows]}
        if call in ("job_status", "job_output", "job_cancel"):
            job_id = args.get("job_id")
            if call == "job_cancel":
                return jobs.cancel(job_id)
            if call == "job_output":
                return jobs.output(job_id, args.get("offset", 0), args.get("limit", 32768))
            st = jobs.status(job_id)
            st["workspace"] = name_of(st["workspace"])
            return st
        raise ExecutionDenied("runner_call_unknown")

    # -- self-upgrade ---------------------------------------------------------------------------
    def _check_upgrade_payload(self, payload):
        try:
            content, _, _ = self.upgrader.check(payload)
        except UpgradeRefused as refused:
            raise ExecutionDenied(refused.code) from None
        if self.needs_attention():
            raise ExecutionDenied("owner_intervention_required")
        self._rotation_guard()
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        return content

    def upgrade(self, payload, proof_token, challenge):
        """Execute an approved, signed StyNpilot upgrade. Everything that can fail BEFORE the machine changes happens
        first (proof check, records backup, download, package inspection, rollback copy); only then is the owner's
        one-time challenge consumed and the detached worker started. Returns immediately with ``pending``: the
        outcome is settled later from the worker's result (see status)."""
        content = self._check_upgrade_payload(payload)
        rid, _ = payload_hash(payload)
        if type(challenge) is not str or len(challenge) != 64:
            raise ExecutionDenied("challenge_unknown")
        fingerprint, passkey = self._prove(rid, proof_token, challenge, "approve")
        try:
            self._backup_records(rid)
            _, _, installed = self.upgrader.check(payload)
            with statelock.operation(self.dir):
                self._rotation_guard()                        # under the lock: a rotation cannot start or be mid-way now
                job = self.upgrader.prepare(rid, content, installed)
                try:
                    self._used_passkey(passkey, rid, "approve")
                    self.runs.consume(challenge=challenge, request_id=rid, decision="approve", proof=fingerprint,
                                      kind="upgrade")
                    unit = self.upgrader.start(rid, job)
                except BaseException:
                    if self.runs.status(rid)["state"] == "not_started":
                        shutil.rmtree(job, ignore_errors=True)
                    raise
        except statelock.Busy:
            raise ExecutionDenied("a_backup_or_restore_is_running_try_again") from None
        except UpgradeRefused as refused:
            raise ExecutionDenied(refused.code) from None
        except backup.BackupError as failed:
            raise ExecutionDenied("records_backup_failed_%s" % str(failed)[:40]) from None
        except ReleaseErrorTypes:
            raise ExecutionDenied("release_download_failed") from None
        except ExecutionDenied:
            raise
        except OSError as error:
            raise ExecutionDenied("could_not_prepare_%s" % type(error).__name__) from None
        return {"ok": None, "pending": True, "started": True, "request_id": rid, "unit": unit,
                "from_version": installed, "to_version": content["manifest"]["version"],
                "backup_scope": "installer_records_and_a_full_copy_of_the_current_version"}


    # -- release authority: build from an exact commit, then ONE approval signs, publishes and installs --------------------
    RELEASE_FIELDS = {"kind", "owner", "device", "intent", "expires_at"}

    def _need_authority(self):
        if self.authority is None:
            raise ExecutionDenied("release_publishing_not_configured")
        if self.authority.inspect is None:                # the package must pass exactly the checks the upgrade itself will make
            self.authority.inspect = lambda path, version: self.upgrader.inspect(
                path, {"version": version}, self.upgrader.installed_version())
        return self.authority

    def release_prepare(self, commit, version):
        """GREEN: start building and verifying a release from an exact commit (background). Nothing is signed or published."""
        authority = self._need_authority()
        if self._pending_release():                       # a pending release's inputs must not change under it
            raise ExecutionDenied("a_release_is_in_progress")
        try:
            installed = self.upgrader.installed_version()
            if not self.upgrader.version_gt(version, installed):
                raise ExecutionDenied("not_newer_than_installed")
            state = authority.status(commit)
            if state.get("state") == "building":
                return state
            authority.prepare_check(commit, version)          # refuse an unusable request before going to the background
            thread = threading.Thread(target=self._build_in_background, args=(commit, version, installed), daemon=True)
            self._builds[commit] = thread
            thread.start()
        except UpgradeRefused as refused:
            raise ExecutionDenied(refused.code) from None
        except AuthorityError as refused:
            raise ExecutionDenied(refused.code) from None
        return {"state": "building"}

    def _build_in_background(self, commit, version, installed):
        try:
            self.authority.prepare(commit, version, installed)
        except Exception:
            pass                                               # the record (written by prepare) says what happened

    def release_status(self, commit):
        try:
            return self._need_authority().status(commit)
        except AuthorityError as refused:
            raise ExecutionDenied(refused.code) from None

    def release_intent(self, commit, version, review_note=""):
        """What the owner would be asked to approve, derived ONLY from the installer's own verified build record."""
        authority = self._need_authority()
        try:
            return authority.intent(commit, version, review_note)
        except AuthorityError as refused:
            raise ExecutionDenied(refused.code) from None

    def _check_release_payload(self, payload):
        authority = self._need_authority()
        if set(payload) != self.RELEASE_FIELDS or payload["owner"] != self.owner or payload["device"] != self.device:
            raise ExecutionDenied("plan_invalid_or_expired")
        expiry = payload["expires_at"]
        if type(expiry) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expiry):
            raise ExecutionDenied("plan_invalid_or_expired")
        when = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if not 0 < (when - datetime.now(timezone.utc)).total_seconds() <= 3600:
            raise ExecutionDenied("plan_invalid_or_expired")
        want = payload["intent"]
        if type(want) is not dict:
            raise ExecutionDenied("plan_invalid_or_expired")
        try:
            have = authority.intent(want.get("commit"), want.get("version"), want.get("review_note", ""))
        except AuthorityError as refused:
            raise ExecutionDenied(refused.code) from None
        if have != want:
            raise ExecutionDenied("release_intent_does_not_match_the_verified_build")
        try:
            trusted = self.upgrader.keys
            if have["key_id"] not in trusted:
                raise ExecutionDenied("release_key_not_trusted_by_this_machine")
            installed = self.upgrader.installed_version()
        except ReleaseErrorTypes:
            raise ExecutionDenied("trusted_keys_unreadable") from None
        except UpgradeRefused as refused:
            raise ExecutionDenied(refused.code) from None
        if not self.upgrader.version_gt(have["version"], installed):
            raise ExecutionDenied("not_newer_than_installed")
        if have["from_min"] and not self.upgrader.version_ge(installed, have["from_min"]):
            raise ExecutionDenied("installed_version_too_old_for_this_release")
        self._release_gate(payload_hash(payload)[0])
        if self.runs.status(payload_hash(payload)[0])["state"] != "not_started":
            raise ExecutionDenied("already_decided_or_used")
        return have

    # The approval is RESERVED (challenge used, run recorded) before anything external happens. From then on the release is a
    # recorded transaction: authorized -> reserved -> signed -> drafted -> uploaded -> published -> started. An interruption at any
    # step leaves the transaction on disk and the approval spent; ``release_resume`` continues only that exact operation.
    TX_STATES = ("authorized", "reserved", "signed", "drafted", "uploaded", "published", "started")
    TX_LIFETIME = 24 * 3600

    def _tx_path(self, rid):
        if type(rid) is not str or not re.fullmatch(r"[0-9a-f]{64}", rid):
            raise ExecutionDenied("request_id_invalid")
        return self.dir / "release-tx" / (rid + ".json")

    def _tx_load(self, rid):
        try:
            tx = json.loads(self._tx_path(rid).read_text())
        except (OSError, ValueError):
            return None
        return tx if type(tx) is dict and tx.get("state") in self.TX_STATES + ("abandoned",) else None

    def _tx_save(self, tx):
        path = self._tx_path(tx["rid"])
        path.parent.mkdir(exist_ok=True, mode=0o700)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, json.dumps(tx, sort_keys=True).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def _tx_resumable(self, tx):
        return bool(tx and tx["state"] in self.TX_STATES[:-1] and self.clock_now() - tx["created"] <= self.TX_LIFETIME)

    def clock_now(self):
        return time.time()

    def _settle(self, rid):
        """Settle an upgrade run from its job folder - except a release whose worker was never launched: that one belongs to its
        transaction (it can still be resumed) and must not be blamed on a vanished worker."""
        if self._release_pending(rid) and not (self.upgrader.job_dir(rid) / "unit").exists():
            return False
        return self.upgrader.reconcile(rid)

    def _release_gate(self, rid):
        """No release step while the machine needs the owner or another change is running."""
        if self.needs_attention():
            raise ExecutionDenied("owner_intervention_required")
        self._settle_upgrades()
        if self.needs_attention():                        # settling an outstanding upgrade can itself raise attention
            raise ExecutionDenied("owner_intervention_required")
        if [r for r in self.runs.running() if r != rid]:
            raise ExecutionDenied("another_change_is_still_running")
        self._rotation_guard()

    def _tx_copy_path(self, rid):
        return self._tx_path(rid).with_suffix(".deb")

    def _tx_data(self, tx):
        """The approved package as this transaction pinned it. Re-checked against the approved hash and size every time it is used."""
        intent = tx["intent"]
        try:
            fd = os.open(self._tx_copy_path(tx["rid"]), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise AuthorityError("approved_package_missing") from None
        try:
            data = os.read(fd, intent["size"] + 1)
        finally:
            os.close(fd)
        if len(data) != intent["size"] or hashlib.sha256(data).hexdigest() != intent["sha256"]:
            raise AuthorityError("approved_package_changed")
        return data

    def _pending_release(self):
        d = self.dir / "release-tx"
        for p in (d.glob("*.json") if d.is_dir() else ()):
            if self.runs.status(p.stem)["state"] == "running" and self._release_pending(p.stem):
                return True
        return False

    def _release_pending(self, rid):
        """True for a spent release approval whose transaction is not finished (it stays 'running' and is not 'attention')."""
        tx = self._tx_load(rid)
        if tx is None or tx["state"] in ("started", "abandoned"):
            return False
        if self.clock_now() - tx["created"] > self.TX_LIFETIME:
            tx["state"] = "abandoned"
            self._tx_save(tx)
            self._tx_copy_path(rid).unlink(missing_ok=True)
            self.runs.finish(rid, "failed", {"ok": False, "approval_spent": True, "release_state": "abandoned_after_%s" % tx.get("last", "?"),
                                             "resumable": False})
            return False
        return True

    def release(self, payload, proof_token, challenge):
        """ONE approval. Order: validate everything that can be validated; check the owner's proof and that the challenge is fresh,
        unused and for this decision; do the checks that need no external effect; THEN reserve the approval durably; only then
        sign, publish (draft -> verified -> public) and start the protected upgrade. Never half-spends silently."""
        authority = self._need_authority()
        intent = self._check_release_payload(payload)
        rid, _ = payload_hash(payload)
        if type(challenge) is not str or len(challenge) != 64:
            raise ExecutionDenied("challenge_unknown")
        fingerprint, passkey = self._prove(rid, proof_token, challenge, "approve")
        self.runs.peek(challenge=challenge, request_id=rid, decision="approve")
        try:
            authority.preflight(intent)
            self._backup_records(rid)
            data = authority.package_bytes(intent["commit"])
            if len(data) != intent["size"] or hashlib.sha256(data).hexdigest() != intent["sha256"]:
                raise AuthorityError("verified_package_was_altered")
            with statelock.operation(self.dir):
                self._rotation_guard()                        # before anything is reserved or spent
                tx = {"rid": rid, "intent": intent, "state": "authorized", "created": self.clock_now(), "last": "authorized"}
                self._tx_path(rid).parent.mkdir(exist_ok=True, mode=0o700)
                self._tx_copy_path(rid).unlink(missing_ok=True)
                _write_private(self._tx_copy_path(rid), data)         # this release's own copy: rebuilds and pruning cannot touch it
                self._tx_save(tx)
                try:
                    self._used_passkey(passkey, rid, "approve")
                    self.runs.consume(challenge=challenge, request_id=rid, decision="approve", proof=fingerprint, kind="release")
                except BaseException:
                    if self.runs.status(rid)["state"] == "not_started":
                        self._tx_path(rid).unlink(missing_ok=True)       # nothing was spent: nothing to resume
                        self._tx_copy_path(rid).unlink(missing_ok=True)
                    raise
                tx.update(state="reserved", last="reserved")
                try:
                    self._tx_save(tx)
                except OSError:
                    pass                                              # the run record itself still says approval was spent
                return self._release_continue(tx)
        except statelock.Busy:
            raise ExecutionDenied("a_backup_or_restore_is_running_try_again") from None
        except AuthorityError as failed:
            raise ExecutionDenied("release_" + failed.code) from None
        except backup.BackupError as failed:
            raise ExecutionDenied("records_backup_failed_%s" % str(failed)[:40]) from None
        except OSError as error:
            raise ExecutionDenied("could_not_prepare_%s" % type(error).__name__) from None

    def release_resume(self, rid):
        """Continue a release whose approval was already spent and which stopped part-way. Needs no new approval and can do nothing
        but finish the exact operation the owner approved (the intent is re-derived and must still match)."""
        self._need_authority()
        tx = self._tx_load(rid)
        if tx is None or tx["state"] in ("started", "abandoned") or self.runs.status(rid)["state"] != "running":
            raise ExecutionDenied("nothing_to_resume")
        if not self._release_pending(rid):
            raise ExecutionDenied("release_approval_expired_start_again_with_a_new_approval")
        try:
            with statelock.operation(self.dir):
                self._rotation_guard()
                if tx["state"] == "authorized":              # the approval WAS spent (the run is 'running'); only the note was lost
                    tx.update(state="reserved", last="reserved")
                    self._tx_save(tx)
                return self._release_continue(tx)
        except statelock.Busy:
            raise ExecutionDenied("a_backup_or_restore_is_running_try_again") from None

    def _release_continue(self, tx):
        """Run the remaining steps of a RESERVED release. Any failure is reported as 'approval spent, here is where it stopped'."""
        authority, rid, intent = self.authority, tx["rid"], tx["intent"]

        def at(state):
            new = dict(tx, state=state, last=state)
            self._tx_save(new)                                 # only a state that reached the disk counts as reached
            tx.update(new)
        try:
            self._release_gate(rid)
            if intent["key_id"] not in self.upgrader.keys or authority.key_entry()["key_id"] != intent["key_id"]:
                raise ExecutionDenied("release_key_not_trusted_by_this_machine")
            installed = self.upgrader.installed_version()
            if not self.upgrader.version_gt(intent["version"], installed):
                raise ExecutionDenied("not_newer_than_installed")
            if intent["from_min"] and not self.upgrader.version_ge(installed, intent["from_min"]):
                raise ExecutionDenied("installed_version_too_old_for_this_release")
            data = self._tx_data(tx)
            if tx["state"] == "reserved":
                note = ["Release approved on the owner's phone; built from commit %s." % intent["commit"][:12],
                        "Tests: %d passed, %d failed; the package built identically twice." % (intent["tests_passed"], intent["tests_failed"])]
                manifest = authority.manifest_for(intent, note)
                tx.update(manifest=manifest, signature=authority.sign(manifest))
                at("signed")
            manifest, signature = tx["manifest"], tx["signature"]
            if tx["state"] == "signed":
                tx["release_id"] = authority.draft(manifest, intent["commit"], rid)
                at("drafted")
            if tx["state"] == "drafted":
                authority._inspect(self._tx_copy_path(rid), intent["version"])
                data = self._tx_data(tx)                           # the actual bytes, against the approved hash and size, right now
                authority.upload_and_verify(tx["release_id"], manifest, signature, data, intent["commit"], rid)
                at("uploaded")
            if tx["state"] == "uploaded":
                authority.make_public(tx["release_id"], manifest, signature, self._tx_data(tx), intent["commit"], rid)
                at("published")
            unit, installed = self._release_start_upgrade(tx, manifest, signature)
            at("started")
            self._tx_copy_path(rid).unlink(missing_ok=True)        # the pinned copy is only needed until the upgrade has its own
        except BaseException as failed:
            if isinstance(failed, (KeyboardInterrupt, SystemExit)):
                raise
            code = (failed.code if isinstance(failed, (AuthorityError, ExecutionDenied, UpgradeRefused)) else
                    "download_failed" if isinstance(failed, ReleaseErrorTypes) else type(failed).__name__)
            raise ExecutionDenied("release_approval_spent_stopped_after_%s_resumable_%s_%s" % (
                tx["state"], "yes" if self._tx_resumable(tx) else "no", str(code)[:60])) from None
        return {"ok": None, "pending": True, "started": True, "request_id": rid, "unit": unit,
                "from_version": installed, "to_version": manifest["version"],
                "backup_scope": "installer_records_and_a_full_copy_of_the_current_version"}

    def _release_start_upgrade(self, tx, manifest, signature):
        rid = tx["rid"]
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        upgrade_payload = {"kind": "upgrade", "software": "stynpilot-self", "owner": self.owner, "device": self.device,
                           "manifest": manifest, "signature": signature, "expires_at": expires}
        content, _, installed = self.upgrader.check(upgrade_payload)
        job = self.upgrader.job_dir(rid)
        if job.exists() and not (job / "job.json").exists():
            shutil.rmtree(job, ignore_errors=True)               # an interrupted preparation: start that part over
        if not job.exists():
            for attempt in range(6):                              # GitHub can take a few seconds to serve a new release
                try:
                    job = self.upgrader.prepare(rid, content, installed)
                    break
                except ReleaseErrorTypes:
                    if attempt == 5:
                        raise
                    self._sleep(5)
                except UpgradeRefused as refused:
                    if refused.code != "download_does_not_match_signed_manifest" or attempt == 5:
                        raise
                    self._sleep(5)
        unit_file = job / "unit"
        unit = unit_file.read_text() if unit_file.exists() else self.upgrader.start(rid, job)
        return unit, installed

    def _backup_records(self, rid):
        """The installer's own records (ledgers, snapshots) saved before an upgrade, hash-verified on the way."""
        out = self.dir / "upgrade-backups" / ("records-%s.tar" % rid[:16])
        if out.exists():
            return
        backup.make_backup(self.dir, out, kind="root")
        backup.read_backup(out, expected_kind="root")             # read back and verify every hash
        keep = sorted((self.dir / "upgrade-backups").glob("records-*.tar"), key=lambda p: p.stat().st_mtime)
        for old in keep[:-5]:
            old.unlink()

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

    def _rotation_guard(self):
        """No install, rollback, upgrade, release (or release resume) while the installer's backup key rotation is active or its
        journal is damaged - also between interrupted attempts, when no lock is held. Called UNDER the operation lock by every
        change path (a rotation takes the same lock and checks for running changes under it)."""
        vault_ = getattr(self, "vault", None)
        if vault_ is None:
            return
        try:
            rotating = vault_._rotation_active()
        except Exception:
            rotating = True
        if rotating:
            raise ExecutionDenied("key_rotation_in_progress")

    def attach_vault(self, vault_):
        """Wire the installer's own vault: rotations see running changes, and report their real final outcome here."""
        self.vault = vault_
        vault_.change_running = lambda own: (any(r != own for r in self.runs.running()) or self._pending_release()
                                             or any((self.dir / "attention").glob("*.json")))
        vault_.on_rotation_finished = self._rotation_finished
        vault_.tick_hooks.append(self.reconcile_rotations)
        self.reconcile_rotations()
        return vault_

    def _rotation_finished(self, rid, result):
        """A root rotation that was interrupted when its approval was handled finished later: replace the stale record."""
        record = self.runs.status(rid)
        old = record.get("result") or {}
        if record["state"] == "failed" and old.get("action") == "rotate_key" and old.get("side") == "root" \
                and old.get("rotation") == "in_progress":
            final = dict(old, ok=bool(result.get("ok")), rotation=result.get("rotation"), progress=None, finished_later=True)
            final.pop("stopped", None)
            if not result.get("ok"):
                final["stopped"] = result.get("stopped") or result.get("error") or "key_rotation_failed"
            for key in ("reencrypted", "left_with_old_key", "moved_unreadable", "generations_kept"):
                if key in result:
                    final[key] = result[key]
            self.runs.finish(rid, "done" if result.get("ok") else "failed", final)

    def reconcile_rotations(self):
        """At start and on every vault tick: a rotation whose completion was durably recorded by the vault but not yet here."""
        vault_ = getattr(self, "vault", None)
        if vault_ is None:
            return
        for rid in self.runs.unsettled_rotations():
            if vault_.rotation_outcome(rid) == "completed" and vault_.journal_request() is None:
                self._rotation_finished(rid, {"ok": True, "rotation": "completed"})

    def _no_other_change(self):
        if self.needs_attention():
            raise ExecutionDenied("owner_intervention_required")
        self._rotation_guard()
        self._settle_upgrades()
        if self.runs.running():
            raise ExecutionDenied("another_change_is_still_running")

    def _install_locked(self, payload, proof_token, challenge, *, now=None):
        self._no_other_change()
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
        self._no_other_change()
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
