"""The root installer's local door: a private UNIX socket that only the owner's account can use.

The owner's StyNpilot service (which talks to ChatGPT and Claude) runs as his normal user.
It forwards an approved request here as one JSON line:

  {"op": "install",  "payload": {...exact plan...}, "proof": "<Auth0 ID token>", "software": "htop"}
  {"op": "rollback", "payload": {...rollback request...}, "proof": "<Auth0 ID token>"}
  {"op": "status",   "request_id": "<64 hex>"}

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
                return {"ok": True, "status": self.executor.runs.status(rid)}
            if op in ("install", "rollback"):
                if not self._busy.acquire(blocking=False):
                    return {"ok": False, "error": "busy"}          # one change at a time
                try:
                    if op == "install":
                        result = self.executor.install(message.get("payload"), message.get("proof"),
                                                       software=message.get("software"))
                    else:
                        result = self.executor.rollback(message.get("payload"), message.get("proof"))
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
                line = _read_line(conn)
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
        sock = self._sock or self.bind()
        while True:
            conn, _ = sock.accept()
            self.serve_one(conn)


def call(socket_path, message, timeout=1800):
    """Client side, used by the owner's StyNpilot service."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(socket_path))
        conn.sendall(json.dumps(message).encode() + b"\n")
        return json.loads(_read_line(conn).decode("utf-8"))
