"""Installer-side recovery. Only the selected ledger and snapshot/attention trees move.
The root vault, authority databases, service settings and recovery journal stay in place.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from . import backup, statelock, vault
from .broker.passkeys import _append_audit
from .requests import request_id

SCOPE = "root_install_records_preserve_settings"
KIND = "backup.restore_root"
MEMBERS = ("installs.sqlite3", "snapshots", "attention")
HEX = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {"archive", "sha256", "scope", "security_sha256", "generation", "created", "version", "settings_differences"}
ENVELOPE = {"kind", "action", "side", "device", "owner", "expires_at"}
ERROR = vault.VaultError


def control(state):
    return Path(state) / "restore-control"


def held(state):
    return any(os.path.lexists(control(state) / name) for name in ("pending.json", "safe.json"))


def _folder(path):
    folder = vault._private_folder(path)
    vault._fsync_dir(folder.parent)
    return folder


def _write(path, data):
    vault._write_atomic(path.parent, path.name, json.dumps(data, sort_keys=True).encode())


def _read(path):
    return json.loads(vault._read_private(path, 65536))


@contextlib.contextmanager
def admission(state, exclusive=False):
    """Serializes approval with other socket/console operations across processes."""
    fd = statelock._take(state, "restore-admission.lock", fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH,
                         "restore_admission_busy")
    try:
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def _db(path, writable=False):
    mode = "rw" if writable else "ro"
    db = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        with db:
            yield db
    finally:
        db.close()


def _generation(state):
    path = control(state) / "generation.json"
    if not os.path.lexists(path):
        if control(state).exists() and any(HEX.fullmatch(p.name) for p in control(state).iterdir()):
            raise ERROR("restore_generation_missing")
        return 0
    value = _read(path)
    if type(value) is not int or value < 1:
        raise ERROR("restore_generation_invalid")
    return value


def _security(v, skip=""):
    digest = hashlib.sha256()
    def feed(item):
        digest.update(json.dumps(item, separators=(",", ":")).encode() + b"\n")
    with _db(v.state_dir / "installs.sqlite3") as db:
        for row in db.execute("SELECT * FROM installs ORDER BY rollback_id"):
            feed(row)
    with _db(v.state_dir / "runs.sqlite3") as db:
        for row in db.execute("SELECT request_id,proof,kind,state FROM runs WHERE request_id!=? ORDER BY request_id", (skip,)):
            feed(row)
    keys = v.state_dir / "passkeys.sqlite3"
    if keys.exists():
        with _db(keys) as db:
            for row in db.execute("SELECT credential_id,pubhash,activated,revoked,quarantined FROM passkeys ORDER BY credential_id"):
                feed(row)
    for evidence in ("settings.json", "policy.log"):
        path = v.folder / evidence
        feed((evidence, vault._file_sha(path) if os.path.lexists(path) else None))
    for name, path, _, _, _ in v._extra_list():
        feed((name, vault._file_sha(path) if os.path.lexists(path) else None))
    return digest.hexdigest()


def _capacity(v, name):
    """Bound overlapping decode, safety backup and staging before opening either archive."""
    archive = (v.folder / name).lstat().st_size
    live, _ = vault._state_sizes(v.state_dir, "root")
    for _, path, _, _, _ in v._extra_list():
        try:
            live += os.lstat(path).st_size
        except FileNotFoundError:
            pass
    for name in backup.ROOT_DBS + backup.ROOT_OPTIONAL_DBS:
        sidecar = v.state_dir / (name + "-wal")
        if sidecar.exists():
            live += sidecar.stat().st_size
    combined = archive + live
    # The decrypted size is bounded by the ciphertext. Charging both whole input sets is conservative
    # when snapshots overlap and leaves room below the worker's memory limit for verification copies.
    if combined > min(v.limits["gather"], vault.MAX_GATHER):
        raise ERROR("combined_restore_too_large")
    if v.space(str(v.state_dir)).free < 4 * combined + vault.SPACE_MARGIN:
        raise ERROR("insufficient_combined_restore_storage")
    if shutil.disk_usage(tempfile.gettempdir()).free < combined + vault.SPACE_MARGIN:
        raise ERROR("insufficient_restore_scratch_storage")


def _eligible(v, stage, archive=None):
    """Check file sizes and the next backup's input budget before any state is replaced."""
    estimated = [p.stat().st_size for tree in MEMBERS[1:] for p in (stage / tree).rglob("*") if p.is_file()]
    estimated.append((stage / MEMBERS[0]).stat().st_size)
    for name in ("runs.sqlite3", "passkeys.sqlite3"):
        path = v.state_dir / name
        if path.exists():
            # Historical proof and key rows can grow the authoritative databases during the security merge.
            sidecar = path.with_name(name + "-wal")
            estimated.append(path.stat().st_size + (sidecar.stat().st_size if sidecar.exists() else 0))
            if archive is not None:
                estimated[-1] += len(archive.get(name, b"")) + (1 << 20)
    extras = [os.lstat(path).st_size for _, path, _, _, _ in v._extra_list() if os.path.lexists(path)]
    if (sum(estimated) + sum(extras) > v.limits["gather"]
            or max(estimated, default=0) > v.limits["file"]
            or max(extras, default=0) > v.limits["extra"]):
        raise ERROR("restored_state_exceeds_backup_limits")


def selected(v, name):
    if v.side != "root" or type(name) is not str or not vault.NAME.fullmatch(name) or not name.startswith("root-"):
        raise ERROR("invalid_root_archive")
    index = v._index()
    entry = index["backups"].get(name) or {}
    if index.get("damaged") or not entry.get("verified_at") or entry.get("incomplete") or entry.get("check_failed"):
        raise ERROR("complete_verified_archive_required")
    header, files, blobs, meta = v._verify(name, index, with_metadata=True)
    if meta.get("incomplete") != [] or any("extra/" + label not in blobs
                                           for label, _, _, required, _ in v._extra_list() if required):
        raise ERROR("complete_verified_archive_required")
    return header, files, blobs


def preview(v, name, *, skip="", generation=None):
    if type(name) is str and vault.NAME.fullmatch(name) and name.startswith("root-"):
        if (v.folder / name).exists():
            _capacity(v, name)
    header, _, blobs = selected(v, name)
    differences = []
    for label, path, _, _, _ in v._extra_list():
        if label.startswith("release-tx/"):
            continue
        archived = blobs.get("extra/" + label)
        if (vault._sha(archived) if archived is not None else None) != (vault._file_sha(path) if Path(path).exists() else None):
            differences.append(label)
        if label == "trusted-release-keys.json" and archived is not None:
            # A settings-preserving restore cannot discard a known revocation.
            old = json.loads(archived).get("revoked", [])
            current = json.loads(Path(path).read_bytes()).get("revoked", []) if Path(path).exists() else []
            if not set(old) <= set(current):
                raise ERROR("release_revocations_need_owner_reconciliation")
    return {"archive": name, "sha256": vault._file_sha(v.folder / name), "scope": SCOPE,
            "generation": _generation(v.state_dir) + 1 if generation is None else generation,
            "security_sha256": _security(v, skip), "settings_differences": sorted(differences),
            "created": header["created"], "version": header["version"]}


def matches(payload, details):
    return (set(details) == FIELDS and set(payload) == FIELDS | ENVELOPE and payload["action"] == "restore_root" and payload["kind"] == "backup"
            and payload["side"] == "root" and all(type(payload[k]) is type(val) and payload[k] == val
                                                  for k, val in details.items()))


def wake(state, rid, payload):
    """Durably reserve the gate. Only a matching atomic proof spend lets the worker advance."""
    root = _folder(control(state))
    if request_id(payload)[0] != rid or not HEX.fullmatch(rid):
        raise ERROR("restore_authorization_mismatch")
    pending = root / "pending.json"
    if os.path.lexists(pending):
        if _read(pending)["rid"] != rid:
            raise ERROR("restore_journal_conflict")
        return
    _write(pending, {"rid": rid, "phase": "approved"})


def _rename(source, dest):
    if os.path.lexists(dest):
        raise ERROR("restore_destination_occupied")
    os.rename(source, dest)
    vault._fsync_dir(dest.parent)
    vault._fsync_dir(source.parent)


def _trees(stage, files):
    for member in MEMBERS[1:]:
        _folder(stage / member)
    for name, data in files.items():
        if name.split("/")[0] in MEMBERS[1:]:
            parts = backup._safe_rel(name).split("/")
            dest = stage
            for part in parts[:-1]:
                dest = _folder(dest / part)
            vault._write_atomic(dest, parts[-1], data)


def _stage(v, payload, tx):
    _capacity(v, payload["archive"])
    if vault._file_sha(v.folder / payload["archive"]) != payload["sha256"]:
        raise ERROR("approved_archive_changed")
    index = v._index()
    name = v._create(index)
    _, live, safety_blobs, meta = v._verify(name, index, with_metadata=True)
    del safety_blobs
    _, archive, archive_blobs = selected(v, payload["archive"])
    del archive_blobs
    if meta.get("incomplete") != []:
        raise ERROR("incomplete_safety_backup")
    index["backups"][name]["verified_at"] = int(v.clock())
    v._save(index)
    # A separate hard link keeps the exact verified encrypted inode outside retention and key rotation.
    safety = tx / name
    os.link(v.folder / name, safety)
    vault._fsync_dir(tx)
    _write(tx / "safety.json", {"archive": name, "sha256": vault._file_sha(safety)})
    with tempfile.TemporaryDirectory(dir=tx) as tmp:
        stage = Path(tmp) / "new"
        _folder(stage)
        # Keep unresolved current attention and all snapshots needed by current or recovered ledger rows.
        trees = {name: data for name, data in archive.items() if "/" in name
                 and not (name.startswith("attention/") and (v.state_dir / "attention-resolved" / Path(name).name).exists())}
        for n, b in live.items():
            if "/" in n:
                if n in trees and trees[n] != b:
                    raise ERROR("conflicting_install_snapshot_or_attention")
                trees[n] = b
        _trees(stage, trees)
        vault._write_atomic(stage, MEMBERS[0], live[MEMBERS[0]])
        for dbname in ("runs.sqlite3", "passkeys.sqlite3", MEMBERS[0]):
            if dbname in archive:
                vault._write_atomic(Path(tmp), dbname, archive[dbname])
        with _db(stage / MEMBERS[0], True) as db, _db(Path(tmp) / MEMBERS[0]) as old:
            for row in old.execute("SELECT * FROM installs"):
                current = db.execute("SELECT * FROM installs WHERE rollback_id=?", (row[0],)).fetchone()
                if current is None:
                    db.execute("INSERT INTO installs VALUES (?,?,?,?,?,?,?,?,?)", row)
                elif current[:-1] != row[:-1]:
                    raise ERROR("conflicting_install_ledger")
                elif row[-1] is not None:
                    db.execute("UPDATE installs SET rolled_back=coalesce(rolled_back,?) WHERE rollback_id=?", (row[-1], row[0]))
        _eligible(v, stage, archive)
        # Validate each referenced snapshot against the merged ledger before allowing any switch.
        backup._validate_complete("root", {**trees, "installs.sqlite3": (stage / MEMBERS[0]).read_bytes(),
                                           "runs.sqlite3": live["runs.sqlite3"]})
        for name in ("runs.sqlite3", "passkeys.sqlite3"):
            source = Path(tmp) / name
            if source.exists():
                vault._write_atomic(tx, "archived-" + name, source.read_bytes())
        _rename(stage, tx / "new")


def _check_safety(tx):
    evidence = _read(tx / "safety.json")
    name = evidence["archive"]
    if (not vault.NAME.fullmatch(name) or not name.startswith("root-")
            or vault._file_sha(tx / name) != evidence["sha256"]):
        raise ERROR("verified_safety_backup_changed")


def _security_union(state, tx, rid):
    """Tighten live authority in place, independently of operational-state rollback."""
    with _db(tx / "archived-runs.sqlite3") as old, _db(state / "runs.sqlite3", True) as db:
        for req, proof, kind, started in old.execute("SELECT request_id,proof,kind,started FROM runs"):
            row = db.execute("SELECT request_id,proof FROM runs WHERE request_id=? OR proof=?", (req, proof)).fetchall()
            if not row:
                db.execute("INSERT INTO runs VALUES (?,?,?,'failed',?,?,?)",
                           (req, proof, kind, '{"ok":false,"stopped":"historical_approval_spent"}', started, started))
            elif row != [(req, proof)]:
                raise ERROR("conflicting_spent_proof")
        db.execute("UPDATE challenges SET used=expires WHERE used IS NULL")
    archived = tx / "archived-passkeys.sqlite3"
    current = state / "passkeys.sqlite3"
    if archived.exists() and not current.exists():
        raise ERROR("current_passkey_authority_unavailable")
    if not current.exists():
        return
    with _db(current, True) as db:
        db.execute("UPDATE windows SET closed=expires WHERE closed IS NULL")
        if archived.exists():
            with _db(archived) as old:
                for row in old.execute("SELECT * FROM passkeys"):
                    key = db.execute("SELECT kid,public_key FROM passkeys WHERE credential_id=?", (row[0],)).fetchone()
                    if key is None:
                        if row[13] is not None or row[10] is not None:
                            db.execute("INSERT INTO passkeys VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)", row[:-1])
                    elif key != row[1:3]:
                        raise ERROR("conflicting_passkey_identity")
                    else:
                        db.execute("UPDATE passkeys SET revoked=coalesce(revoked,?),sign_count=max(sign_count,?) "
                                   "WHERE credential_id=?", (row[10], row[7], row[0]))
        detail = json.dumps({"request_id": rid}, sort_keys=True, separators=(",", ":"))
        if not db.execute("SELECT 1 FROM audit WHERE event='root_restore' AND data=?", (detail,)).fetchone():
            db.row_factory = sqlite3.Row
            _append_audit(db, time.time(), "root_restore", {"request_id": rid})


def _switch(state, tx, undo):
    original, new, failed = (tx / name for name in ("original", "new", "failed"))
    for folder in (original, failed):
        _folder(folder)
    for suffix in ("-wal", "-shm", "-journal"):
        if os.path.lexists(state / (MEMBERS[0] + suffix)):
            raise ERROR("live_database_has_sidecars")
    for name in MEMBERS:
        live, saved, incoming = state / name, original / name, new / name
        if undo:
            if saved.exists():
                if live.exists():
                    _rename(live, failed / name)
                _rename(saved, live)
            elif not live.exists():
                raise ERROR("original_state_unavailable")
        else:
            if not saved.exists():
                _rename(live, saved)
            if incoming.exists():
                _rename(incoming, live)
            if not live.exists():
                raise ERROR("restored_member_missing")


def _manifest(folder):
    hashes = {}
    for name in MEMBERS:
        path = folder / name
        if path.is_symlink() or (not path.is_file() if name == MEMBERS[0] else not path.is_dir()):
            raise ERROR("invalid_restore_member")
        for p in ([path] if path.is_file() else sorted(path.rglob("*"))):
            if p.is_symlink() or not (p.is_file() or p.is_dir()):
                raise ERROR("invalid_restore_member")
            if p.is_file():
                hashes[str(p.relative_to(folder))] = vault._file_sha(p)
    return hashes


def _manifest_hash(folder):
    return vault._sha(json.dumps(_manifest(folder), sort_keys=True).encode())


def start_allowed(state):
    if not held(state):
        return True
    if os.path.lexists(control(state) / "safe.json"):
        return False
    return _read(control(state) / "pending.json")["phase"] in ("approved", "verify", "verify_original", "done", "rolled_back")


def worker(v, services, checkpoint=lambda phase: None):
    """Resume one spent authorization. Power loss (including during rename) leaves a retryable phase."""
    state, root = v.state_dir, control(v.state_dir)
    pending = root / "pending.json"
    if not pending.exists():
        return
    fd = statelock._take(root, "worker.lock", fcntl.LOCK_EX, "restore_worker_running")
    try:
        if (root / "safe.json").exists():
            services.start_safe()
            _rename(pending, root / "stalled.json")
            return
        # The path unit can wake immediately after the intent is written, before the SQLite proof spend.
        # Wait for the approving socket call (or its death) before inspecting its durable decision.
        barrier = statelock._open(state, "restore-admission.lock")
        try:
            fcntl.flock(barrier, fcntl.LOCK_SH)
        finally:
            os.close(barrier)
        journal = _read(pending)
        rid = journal["rid"]
        if type(rid) is not str or not HEX.fullmatch(rid):
            raise ERROR("invalid_restore_journal")
        def phase(name, **evidence):
            if name in ("verify", "verify_original"):
                evidence["probe"] = secrets.token_hex(32)
            else:
                journal.pop("probe", None)
            journal.update(phase=name, **evidence)
            _write(pending, journal)
            checkpoint(name)
        def settle(success, outcome):
            result = {"ok": success, "action": "restore_root", "side": "root", "restore": outcome,
                      "generation": journal.get("generation"), "stopped": journal.get("error")}
            with _db(state / "runs.sqlite3", True) as db:
                db.execute("UPDATE runs SET state=?,result=?,finished=? WHERE request_id=? AND kind=? AND state='restore_queued'",
                           ("done" if success else "failed", json.dumps(result), time.time(), rid, KIND))
            _write(root / rid / "outcome.json", result)
            pending.unlink()
            vault._fsync_dir(root)

        with _db(state / "runs.sqlite3") as db:
            row = db.execute("SELECT state,result FROM runs WHERE request_id=? AND kind=?", (rid, KIND)).fetchone()
        if not row and journal["phase"] == "approved":
            pending.unlink()    # process died before spending the proof. Nothing was stopped or replaced.
            vault._fsync_dir(root)
            return
        if not row:
            raise ERROR("missing_spent_restore_authorization")
        step = journal["phase"]
        if step in ("done", "rolled_back") and row[0] in ("done", "failed"):
            settle(step == "done", step)
            return
        payload = json.loads(row[1])
        if row[0] != "restore_queued" or request_id(payload)[0] != rid:
            raise ERROR("restore_authorization_mismatch")
        generation = payload["generation"]
        tx = root / rid
        if step == "approved":
            previous = _generation(state)
            if previous not in (generation - 1, generation):
                raise ERROR("stale_restore_generation")
            _write(root / "generation.json", generation)
            _folder(tx)
            phase("prepare", generation=generation)
        if _generation(state) != generation:
            raise ERROR("restore_generation_mismatch")
        while True:
            step = journal["phase"]
            try:
                if step == "prepare":
                    services.stop()
                    details = v._locked(lambda: preview(v, payload["archive"], skip=rid, generation=generation))
                    if not matches(payload, details):
                        raise ERROR("approved_restore_changed")
                    # make_backup takes the operation lock itself. Exclude a live installer during the whole preparation.
                    alive = statelock._take(state, statelock.ALIVE, fcntl.LOCK_EX, "installer_still_running")
                    try:
                        if not (tx / "new").exists():
                            v._locked(lambda: _stage(v, payload, tx))
                        phase("secure", original=_manifest_hash(state), candidate=_manifest_hash(tx / "new"))
                    finally:
                        os.close(alive)
                elif step == "secure":
                    services.stop()
                    with statelock.exclusive_for_restore(state):
                        _check_safety(tx)
                        _security_union(state, tx, rid)
                        _eligible(v, tx / "new")
                        phase("switch")
                elif step == "switch":
                    services.stop()
                    with statelock.exclusive_for_restore(state):
                        _check_safety(tx)
                        _switch(state, tx, False)
                        if _manifest_hash(state) != journal["candidate"]:
                            raise ERROR("restored_state_verification_failed")
                        phase("verify")
                elif step in ("verify", "verify_original"):
                    services.start()
                    if not services.healthy(journal["probe"]):
                        raise ERROR("service_or_confinement_verification_failed")
                    expected = journal.get("candidate" if step == "verify" else "original")
                    if expected is not None and _manifest_hash(state) != expected:
                        raise ERROR("online_state_verification_failed")
                    phase("done" if step == "verify" else "rolled_back")
                elif step == "rollback":
                    services.stop()
                    with statelock.exclusive_for_restore(state):
                        _switch(state, tx, True)
                        if _manifest_hash(state) != journal["original"]:
                            raise ERROR("rollback_verification_failed")
                        phase("verify_original")
                elif step in ("done", "rolled_back"):
                    settle(step == "done", step)
                    return
                else:
                    raise ERROR("invalid_restore_phase")
            except Exception as error:
                if step not in ("prepare", "secure", "switch", "verify"):
                    raise
                phase("rollback" if step in ("switch", "verify") else "verify_original",
                      error=getattr(error, "code", "restore_" + type(error).__name__))
    except Exception as error:
        safe = {"error": getattr(error, "code", "recovery_" + type(error).__name__), "rid": locals().get("rid")}
        _write(root / "safe.json", safe)
        # The safe marker is sufficient for status even if the authorization database is unreadable.
        # Keep the trigger until the recovery socket can be started.
        services.start_safe()
        if pending.exists():
            _rename(pending, root / "stalled.json")
        raise
    finally:
        os.close(fd)


def safe_reply(state, message):
    """Limited read-only status even when opening the operational databases would be unsafe."""
    if message.get("op") == "status":
        safe = _read(control(state) / "safe.json")
        rid = message.get("request_id")
        if isinstance(rid, str) and HEX.fullmatch(rid) and rid == safe.get("rid"):
            return {"ok": True, "status": {"state": "needs_owner_intervention", "result": {
                "action": "restore_root", "side": "root", "ok": False, "restore": "safe_recovery",
                "stopped": "recovery_requires_owner", "needs_owner_intervention": True}}}
    if message.get("op") == "vault_status":
        return {"ok": True, "result": {"side": "root", "healthy": False, "problems": ["safe_recovery"]}}
    if message.get("op") == "runner" and message.get("call") == "status":
        return {"ok": True, "result": {"gate_open": False, "reason": "safe_recovery"}}
    return {"ok": False, "error": "safe_recovery_requires_owner"}


def still_current(v, payload):
    """Lightweight final check under the same vault lock that reserves the gate."""
    index = v._index()
    entry = index["backups"].get(payload["archive"]) or {}
    return (not index.get("damaged") and entry.get("verified_at") and not entry.get("incomplete")
            and not entry.get("check_failed") and _security(v) == payload["security_sha256"]
            and _generation(v.state_dir) + 1 == payload["generation"]
            and vault._file_sha(v.folder / payload["archive"]) == payload["sha256"])


def probe_allowed(state, token):
    if type(token) is not str or not HEX.fullmatch(token):
        return False
    journal = _read(control(state) / "pending.json")
    expected = journal.get("probe")
    return (journal["phase"] in ("verify", "verify_original") and isinstance(expected, str)
            and secrets.compare_digest(token, expected))
