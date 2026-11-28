"""The root installer's local door: a private UNIX socket that only the owner's account can use.

The owner's StyNpilot service (which talks to ChatGPT and Claude) runs as his normal user.
It talks to the installer with one JSON line per call:

  {"op": "challenge",    "payload": {...}, "decision": "approve"|"deny"}   -> challenge, nonce, summary
  {"op": "install",      "payload": {...}, "proof": "<ID token>", "challenge": "<64 hex>"}
  {"op": "rollback",     "payload": {...}, "proof": "<ID token>", "challenge": "<64 hex>"}
  {"op": "upgrade",      "payload": {...}, "proof": "<ID token>", "challenge": "<64 hex>"}   -> returns at once (pending)
  {"op": "deny",         "payload": {...}, "proof": "<ID token>", "challenge": "<64 hex>"}
  {"op": "passkey_list" | "passkey_begin" | "passkey_complete" | "passkey_precheck" | "passkey_admin", ...}   (dev15 passkeys)
  {"op": "status",       "request_id": "<64 hex>"}
  {"op": "rollbackable", "rollback_id": "<hex>", "software": "<catalog id>"}

The software name always comes from inside the hashed plan, never from the caller.
``rollbackable`` is the narrow, read-only view G3 needs: yes, or a refusal code. It never
returns the root ledger's contents.

The caller is identified by the kernel (SO_PEERCRED), not by anything it says: only the
enrolled owner UID is served. The installer trusts nothing in the message beyond what it
re-checks itself (plan hash, Auth0 signature, one-time use, the root ledger), so even a
compromised owner service can only ask for an exact, owner-approved plan to run once.
A separate AI runner account (Phase B) is a different UID and is refused at the door.
Requests run one at a time. Messages are capped at 256 KiB.
"""
from __future__ import annotations

import json
import hashlib
import hmac
import logging
import os
import re
import secrets
import selectors
import socket
import stat
import struct
import threading
from pathlib import Path

from ..ledger import LedgerError
from .executor import ExecutionDenied
from .lab import CALLS as LAB_CALLS
from .repository_auth import ACTIONS as REPOSITORY_ACTIONS

MAX_MESSAGE = 256 * 1024
_HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


def _read_line(conn):
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_MESSAGE:
            raise ValueError("message_too_large")
    return data.split(b"\n", 1)[0]


READ_TIMEOUT = 15
MAX_CONNECTIONS = 16
_SYSTEM_SOCKET = Path("/run/stynpilot/installer.sock")
_TRANSPORT_KEY = "installer-transport.key"


def _transport_address(key):
    return "\0stynpilot-installer-" + hashlib.sha256(key).hexdigest()


def _transport_proof(key, nonce):
    return hmac.digest(key, b"stynpilot-installer-v1\0" + nonce, "sha256").hex().encode()


def _transport_key(socket_path):
    parent = Path(socket_path).parent
    top = os.open(parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if os.fstat(top).st_mode & 0o022:
            raise PermissionError("untrusted installer directory")
        fd = os.open(_TRANSPORT_KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=top)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o377 or info.st_size != 32 or info.st_nlink != 1):
                raise PermissionError("untrusted installer connection key")
            key = file.read(33)
            if len(key) != 32:
                raise PermissionError("invalid installer connection key")
            return key
    finally:
        os.close(top)


class BrokerService:
    def __init__(self, *, socket_path, executor, allowed_uid):
        if type(allowed_uid) is not int or allowed_uid == 0 and os.geteuid() != 0:
            raise ValueError("The enrolled owner UID is required")
        self.path, self.executor, self.allowed_uid = Path(socket_path), executor, allowed_uid
        self._busy = threading.Lock()
        self._sock = None
        self._abstract = None
        self._transport = None
        self._lab_boot_pending = False

    def handle(self, message):
        from .. import root_restore, statelock
        state = getattr(self.executor, "dir", None)
        if state is None:
            return self._handle(message)
        msg = message if isinstance(message, dict) else {}
        payload = msg.get("payload")
        approving = isinstance(payload, dict) and (
            (msg.get("op") == "backup_admin" and payload.get("action") == "restore_root")
            or (msg.get("op") == "runner_admin" and payload.get("action") in
                ("settle_inference", "lab_enroll", "repo_push", "deckplay_checkout", *REPOSITORY_ACTIONS))
            or (msg.get("op") == "repository_credential_install" and payload.get("action") == "repo_credential"))
        exclusive = approving or (msg.get("op") == "runner" and msg.get("call") in
                                  ("inference_claim", "inference_finish", "lab_start", "lab_cancel", "lab_checkout", "lab_fetch"))
        try:
            with root_restore.admission(state, exclusive=exclusive):
                if (root_restore.control(state) / "safe.json").exists():
                    return root_restore.safe_reply(state, msg)
                if root_restore.held(state):
                    read = msg.get("op") in ("status", "vault_status")
                    if msg.get("op") == "restore_check":
                        if root_restore.probe_allowed(state, msg.get("probe")):
                            return self._handle({"op": "runner", "call": "selftest", "args": {}})
                        return {"ok": False, "error": "recovery_probe_not_authorized"}
                    runner = msg.get("op") == "runner" and msg.get("call") == "status"
                    if not read and not runner:
                        return {"ok": False, "error": "root_restore_in_progress"}
                return self._handle(message)
        except statelock.Busy as error:
            return {"ok": False, "error": error.code}

    def _handle(self, message):
        op = message.get("op") if isinstance(message, dict) else None
        try:
            if op == "status":
                rid = message.get("request_id")
                if type(rid) is not str or not _HEX64.fullmatch(rid):
                    return {"ok": False, "error": "invalid_request"}
                return {"ok": True, "status": self.executor.status(rid)}
            if op == "challenge":
                if not self._busy.acquire(blocking=False):
                    return {"ok": False, "error": "busy"}          # no new decisions while a change is running
                try:
                    return {"ok": True, "challenge": self.executor.challenge(message.get("payload"),
                                                                             message.get("decision"))}
                finally:
                    self._busy.release()
            if op == "rollbackable":
                if message.get("owner") != self.executor.owner or message.get("device") != self.executor.device:
                    return {"ok": False, "error": "unknown_rollback_id"}
                try:
                    entry = self.executor.ledger.rollbackable(message.get("rollback_id"),
                                                              software=message.get("software"),
                                                              owner=self.executor.owner, device=self.executor.device)
                except LedgerError as refused:
                    return {"ok": False, "error": refused.code}
                return {"ok": True, "request_id": entry["request_id"], "snapshot_id": entry["snapshot_id"]}
            if op == "passkey_list":
                return {"ok": True, "result": self.executor.passkey_list()}
            if op == "passkey_begin":
                return {"ok": True, "result": self.executor.passkey_begin(message.get("request_id"))}
            if op == "passkey_complete":
                return {"ok": True, "result": self.executor.passkey_complete(message.get("request_id"), message.get("response"))}
            if op == "passkey_precheck":
                kwargs = {"credential_sha256": message["credential_sha256"]} if "credential_sha256" in message else {}
                return {"ok": True, "result": self.executor.passkey_precheck(message.get("payload"), message.get("proof"),
                                                                              message.get("challenge"), message.get("decision"),
                                                                              **kwargs)}
            if op == "release_prepare":
                return {"ok": True, "result": self.executor.release_prepare(message.get("commit"), message.get("version"))}
            if op == "release_status":
                return {"ok": True, "result": self.executor.release_status(message.get("commit"))}
            if op == "release_intent":
                return {"ok": True, "result": self.executor.release_intent(message.get("commit"), message.get("version"),
                                                                           message.get("review_note", ""))}
            if op == "release_resume":
                if not self._busy.acquire(blocking=False):
                    return {"ok": False, "error": "busy"}
                try:
                    return {"ok": True, "result": self.executor.release_resume(message.get("request_id"))}
                finally:
                    self._busy.release()
            if op in ("vault_status", "vault_backup", "vault_drill"):
                vault = getattr(self, "vault", None)
                if vault is None:
                    return {"ok": True, "result": {"side": "root", "healthy": False, "problems": ["root_vault_not_running"]}}
                call = {"vault_status": vault.status, "vault_backup": lambda: vault.backup_now(manual=True),
                        "vault_drill": lambda: vault.drill(manual=True)}[op]
                return {"ok": True, "result": call()}
            if op == "runner":
                if self._lab_boot_pending and message.get("call") in ("lab_start", "lab_prepare"):
                    return {"ok": False, "error": "lab_restart_reconciling"}
                return {"ok": True, "result": self.executor.runner_call(message.get("call"), message.get("args"))}
            if op == "restore_preview":
                details = self.executor.vault._run("restore_preview", args={"archive": message.get("archive")})
                if "error" in details:
                    return {"ok": False, "error": details["error"]}
                return {"ok": True, "result": details}
            if op == "vault_settings":
                vault = getattr(self, "vault", None)
                return {"ok": True, "result": vault.effective_retention() if vault is not None else None}
            if op == "repository_credential_install":
                if set(message) != {"op", "payload", "proof", "challenge", "credential"}:
                    return {"ok": False, "error": "repository_credential_invalid"}
                if not self._busy.acquire(blocking=False):
                    return {"ok": False, "error": "busy"}
                try:
                    result = self.executor.repository_credential_install(message["payload"], message["proof"],
                                                                        message["challenge"], message["credential"])
                finally:
                    self._busy.release()
                return {"ok": True, "result": result}
            if op in ("install", "rollback", "upgrade", "release", "deny", "runner_admin", "passkey_admin", "backup_admin"):
                if not self._busy.acquire(blocking=False):
                    return {"ok": False, "error": "busy"}          # one change at a time
                try:
                    method = {"install": self.executor.install, "rollback": self.executor.rollback,
                              "upgrade": self.executor.upgrade, "release": self.executor.release,
                              "deny": self.executor.deny,
                              "runner_admin": self.executor.runner_admin,
                              "passkey_admin": self.executor.passkey_admin,
                              "backup_admin": self.executor.backup_admin}[op]
                    result = method(message.get("payload"), message.get("proof"), message.get("challenge"))
                finally:
                    self._busy.release()
                return {"ok": True, "result": result}
        except ExecutionDenied as denied:
            return {"ok": False, "error": denied.code}
        except Exception as error:
            return {"ok": False, "error": "unexpected_%s" % type(error).__name__}
        return {"ok": False, "error": "unknown_op"}

    def bind(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if self.path.exists() or self.path.is_symlink():
            self.path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            sock.bind(str(self.path))
        finally:
            os.umask(old)
        if os.geteuid() == 0:
            os.chown(self.path, self.allowed_uid, -1)
        os.chmod(self.path, 0o600)
        sock.listen(8)
        self._sock = sock
        if os.geteuid() == 0 and self.path == _SYSTEM_SOCKET and self.allowed_uid != 0:
            self._bind_alternate()
        return sock

    def _bind_alternate(self):
        """The same owner-UID boundary across differing mount namespaces.

        The key authenticates the installer to its owner before any approval or
        request is transmitted. It never appears in the abstract socket name or
        goes over the socket. The pathname socket remains available.
        """
        key = secrets.token_bytes(32)
        alternate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        temp = self.path.parent / (".transport-" + secrets.token_hex(8))
        try:
            alternate.bind(_transport_address(key))
            alternate.listen(8)
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(fd, "wb") as file:
                file.write(key)
                if os.geteuid() != self.allowed_uid:
                    os.fchown(file.fileno(), self.allowed_uid, -1)
            os.replace(temp, self.path.parent / _TRANSPORT_KEY)
        except OSError:
            alternate.close()
            temp.unlink(missing_ok=True)
            logging.getLogger("stynpilot.broker").warning("alternate installer transport unavailable")
        else:
            self._transport, self._abstract = key, alternate

    def serve_one(self, conn, alternate=False):
        with conn:
            try:
                if peer_uid(conn) != self.allowed_uid:
                    conn.sendall(json.dumps({"ok": False, "error": "caller_not_enrolled_owner"}).encode() + b"\n")
                    return
                conn.settimeout(READ_TIMEOUT)             # a slow or silent client can't hold a worker
                if alternate:
                    nonce = _read_line(conn)
                    if not re.fullmatch(rb"[0-9a-f]{64}", nonce):
                        return
                    conn.sendall(_transport_proof(self._transport, nonce) + b"\n")
                line = _read_line(conn)
                conn.settimeout(None)                     # the work itself (an install) may take a long time
                try:
                    message = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeError):
                    reply = {"ok": False, "error": "invalid_message"}
                else:
                    reply = self.handle(message)
            except ValueError as error:
                reply = {"ok": False, "error": str(error)}
            conn.sendall(json.dumps(reply, sort_keys=True).encode() + b"\n")

    def serve_forever(self):
        """One thread per connection (bounded). Read-only status checks stay available while an install
        runs; the ``_busy`` lock still allows only ONE change (and no new decisions) at a time."""
        sock = self._sock or self.bind()
        lab = getattr(self.executor, "lab", None)
        if lab is not None or getattr(self.executor, "jobs", None) is not None:
            self._lab_boot_pending = True
            threading.Thread(target=self._watch_lab, args=(sock, lab), name="stynpilot-lab-reconcile", daemon=True).start()
        slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        with selectors.DefaultSelector() as listeners:
            listeners.register(sock, selectors.EVENT_READ, False)
            if self._abstract is not None:
                listeners.register(self._abstract, selectors.EVENT_READ, True)
            while sock.fileno() >= 0:
                for listener, _ in listeners.select(1):
                    try:
                        conn, _ = listener.fileobj.accept()
                        if peer_uid(conn) != self.allowed_uid:
                            with conn:
                                conn.sendall(b'{"error": "caller_not_enrolled_owner", "ok": false}\n')
                            continue
                        if not slots.acquire(blocking=False):
                            with conn:
                                conn.sendall(b'{"error": "too_many_connections", "ok": false}\n')
                            continue
                    except OSError:
                        continue

                    def work(conn=conn, alternate=listener.data):
                        try:
                            self.serve_one(conn, alternate)
                        except OSError:
                            pass
                        finally:
                            slots.release()
                    threading.Thread(target=work, name="stynpilot-broker-conn", daemon=True).start()

    def _watch_lab(self, sock, lab):
        from .. import managed_activity, root_restore, statelock
        import time

        startup = True
        previous_error = None
        while sock.fileno() >= 0:
            try:
                state = self.executor.dir
                if startup or managed_activity.held(state):
                    with root_restore.admission(state, exclusive=True):
                        if self.executor.jobs is not None:
                            self.executor.jobs.reconcile_deckplay_checkout()
                        if lab is not None:
                            lab.reconcile(startup=startup)
                        startup = False
                        self._lab_boot_pending = False
                        previous_error = None
            except statelock.Busy:
                pass
            except Exception as error:
                code = getattr(error, "code", type(error).__name__)
                if code != previous_error:
                    logging.getLogger("stynpilot.lab").warning("lab reconciliation held: %s", code)
                    previous_error = code
            time.sleep(1)


class BrokerLedger:
    """G3's view of the root ledger: asks the installer, never reads root files."""

    def __init__(self, socket_path):
        self.socket_path = socket_path

    def rollbackable(self, rollback_id, *, software, owner, device):
        try:
            reply = call(self.socket_path, {"op": "rollbackable", "rollback_id": rollback_id, "software": software,
                                            "owner": owner, "device": device}, timeout=10)
        except (OSError, ValueError):
            raise LedgerError("installer_unavailable") from None
        if not reply.get("ok"):
            raise LedgerError(str(reply.get("error", "unknown_rollback_id")))
        return {"rollback_id": rollback_id, "software": software,
                "request_id": reply["request_id"], "snapshot_id": reply["snapshot_id"]}


def call(socket_path, message, timeout=1800):
    """Client side, used by the owner's StyNpilot service."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        try:
            conn.connect(str(socket_path))
        except PermissionError:
            if Path(socket_path) != _SYSTEM_SOCKET:
                raise
            key = _transport_key(socket_path)
            nonce = secrets.token_hex(32).encode()
            conn.connect(_transport_address(key))
            conn.sendall(nonce + b"\n")
            if not hmac.compare_digest(_read_line(conn), _transport_proof(key, nonce)):
                raise PermissionError("installer transport authentication failed")
        conn.sendall(json.dumps(message).encode() + b"\n")
        return json.loads(_read_line(conn).decode("utf-8"))


class BrokerRefused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BrokerClient:
    """What the owner-side approval flow uses to talk to the root installer over its socket."""

    def __init__(self, socket_path):
        self.socket_path = str(socket_path)

    def _ask(self, message, timeout=1800):
        try:
            reply = call(self.socket_path, message, timeout=timeout)
        except (OSError, ValueError) as error:
            logging.getLogger("stynpilot.broker").warning("installer socket unavailable type=%s errno=%s",
                                                        type(error).__name__, getattr(error, "errno", None))
            raise BrokerRefused("installer_unavailable") from None
        if not reply.get("ok"):
            raise BrokerRefused(str(reply.get("error", "installer_refused")))
        return reply

    def status(self, request_id):
        return self._ask({"op": "status", "request_id": request_id}, 30)["status"]

    def challenge(self, payload, decision):
        return self._ask({"op": "challenge", "payload": payload, "decision": decision}, 30)["challenge"]

    def install(self, payload, proof, challenge):
        return self._ask({"op": "install", "payload": payload, "proof": proof, "challenge": challenge})["result"]

    def rollback(self, payload, proof, challenge):
        return self._ask({"op": "rollback", "payload": payload, "proof": proof, "challenge": challenge})["result"]

    def upgrade(self, payload, proof, challenge):
        return self._ask({"op": "upgrade", "payload": payload, "proof": proof, "challenge": challenge}, 600)["result"]

    def release(self, payload, proof, challenge):
        return self._ask({"op": "release", "payload": payload, "proof": proof, "challenge": challenge}, 900)["result"]

    def release_resume(self, request_id):
        return self._ask({"op": "release_resume", "request_id": request_id}, 900)["result"]

    def release_prepare(self, commit, version):
        return self._ask({"op": "release_prepare", "commit": commit, "version": version}, 30)["result"]

    def restore_preview(self, archive):
        return self._ask({"op": "restore_preview", "archive": archive}, 120)["result"]

    def vault_settings(self):
        return self._ask({"op": "vault_settings"}, 30)["result"]

    def backup_admin(self, payload, proof, challenge):
        return self._ask({"op": "backup_admin", "payload": payload, "proof": proof, "challenge": challenge}, 60)["result"]

    def vault_status(self):
        return self._ask({"op": "vault_status"}, 30)["result"]

    def vault_backup(self):
        return self._ask({"op": "vault_backup"}, 900)["result"]

    def vault_drill(self):
        return self._ask({"op": "vault_drill"}, 900)["result"]

    def release_status(self, commit):
        return self._ask({"op": "release_status", "commit": commit}, 30)["result"]

    def release_intent(self, commit, version, review_note=""):
        return self._ask({"op": "release_intent", "commit": commit, "version": version, "review_note": review_note}, 30)["result"]

    def runner_admin(self, payload, proof, challenge):
        return self._ask({"op": "runner_admin", "payload": payload, "proof": proof, "challenge": challenge}, 300)["result"]

    def runner(self, call, args=None):
        """GREEN runner operations on the owner-only socket (no approval): status, self-test, run, jobs, output, cancel."""
        timeout = 5 if call == "inference_validate" else 45 if call in LAB_CALLS else 120
        return self._ask({"op": "runner", "call": call, "args": args or {}}, timeout)["result"]

    def passkey_admin(self, payload, proof, challenge):
        return self._ask({"op": "passkey_admin", "payload": payload, "proof": proof, "challenge": challenge}, 60)["result"]

    def passkey_list(self):
        return self._ask({"op": "passkey_list"}, 30)["result"]

    def passkey_begin(self, request_id):
        return self._ask({"op": "passkey_begin", "request_id": request_id}, 30)["result"]

    def passkey_complete(self, request_id, response):
        return self._ask({"op": "passkey_complete", "request_id": request_id, "response": response}, 30)["result"]

    def passkey_precheck(self, payload, proof, challenge, decision, *, credential_sha256=None):
        request = {"op": "passkey_precheck", "payload": payload, "proof": proof, "challenge": challenge, "decision": decision}
        if credential_sha256 is not None:
            request["credential_sha256"] = credential_sha256
        return self._ask(request, 30)["result"]

    def repository_credential_install(self, payload, proof, challenge, *, credential):
        request = {"op": "repository_credential_install", "payload": payload, "proof": proof,
                   "challenge": challenge, "credential": credential}
        return self._ask(request, 90)["result"]

    def deny(self, payload, proof, challenge):
        return self._ask({"op": "deny", "payload": payload, "proof": proof, "challenge": challenge}, 60)["result"]
