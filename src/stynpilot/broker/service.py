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
import os
import re
import socket
import struct
import threading
from pathlib import Path

from ..ledger import LedgerError
from .executor import ExecutionDenied

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


class BrokerService:
    def __init__(self, *, socket_path, executor, allowed_uid):
        if type(allowed_uid) is not int or allowed_uid == 0 and os.geteuid() != 0:
            raise ValueError("The enrolled owner UID is required")
        self.path, self.executor, self.allowed_uid = Path(socket_path), executor, allowed_uid
        self._busy = threading.Lock()
        self._sock = None

    def handle(self, message):
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
                return {"ok": True, "result": self.executor.passkey_precheck(message.get("payload"), message.get("proof"),
                                                                              message.get("challenge"), message.get("decision"))}
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
                return {"ok": True, "result": self.executor.runner_call(message.get("call"), message.get("args"))}
            if op == "vault_prune_lease":
                vault = getattr(self, "vault", None)
                if vault is None:
                    return {"ok": True, "result": None}
                return {"ok": True, "result": {"lease": self.executor.take_prune_lease(), "policy": vault.effective_retention()}}
            if op == "vault_prune_release":
                self.executor.release_prune_lease(message.get("lease"))
                return {"ok": True, "result": True}
            if op == "vault_settings":
                vault = getattr(self, "vault", None)
                return {"ok": True, "result": vault.effective_retention() if vault is not None else None}
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
        return sock

    def serve_one(self, conn):
        with conn:
            try:
                if peer_uid(conn) != self.allowed_uid:
                    conn.sendall(json.dumps({"ok": False, "error": "caller_not_enrolled_owner"}).encode() + b"\n")
                    return
                conn.settimeout(READ_TIMEOUT)             # a slow or silent client can't hold a worker
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
        slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            if not slots.acquire(blocking=False):
                with conn:
                    conn.sendall(b'{"error": "too_many_connections", "ok": false}\n')
                continue

            def work(conn=conn):
                try:
                    self.serve_one(conn)
                except Exception:
                    pass
                finally:
                    slots.release()
            threading.Thread(target=work, name="stynpilot-broker-conn", daemon=True).start()


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
        conn.connect(str(socket_path))
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
        except (OSError, ValueError):
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

    def vault_prune_lease(self):
        return self._ask({"op": "vault_prune_lease"}, 30)["result"]

    def vault_prune_release(self, lease):
        return self._ask({"op": "vault_prune_release", "lease": lease}, 30)["result"]

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
        return self._ask({"op": "runner", "call": call, "args": args or {}}, 120)["result"]

    def passkey_admin(self, payload, proof, challenge):
        return self._ask({"op": "passkey_admin", "payload": payload, "proof": proof, "challenge": challenge}, 60)["result"]

    def passkey_list(self):
        return self._ask({"op": "passkey_list"}, 30)["result"]

    def passkey_begin(self, request_id):
        return self._ask({"op": "passkey_begin", "request_id": request_id}, 30)["result"]

    def passkey_complete(self, request_id, response):
        return self._ask({"op": "passkey_complete", "request_id": request_id, "response": response}, 30)["result"]

    def passkey_precheck(self, payload, proof, challenge, decision):
        return self._ask({"op": "passkey_precheck", "payload": payload, "proof": proof, "challenge": challenge,
                          "decision": decision}, 30)["result"]

    def deny(self, payload, proof, challenge):
        return self._ask({"op": "deny", "payload": payload, "proof": proof, "challenge": challenge}, 60)["result"]
