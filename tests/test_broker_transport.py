"""The pathname fallback authenticates both ends of the local broker connection."""
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from stynpilot.broker import service


class TransportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "installer.sock"
        patcher = patch.object(service, "_SYSTEM_SOCKET", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def connect_without_pathname(self):
        connect = socket.socket.connect

        def denied(sock, address):
            if address == str(self.path):
                raise PermissionError("fixture pathname not available")
            return connect(sock, address)

        return patch.object(socket.socket, "connect", denied)

    def test_alternate_reaches_same_owner_broker(self):
        executor = SimpleNamespace(status=lambda rid: {"state": "done"})
        broker = service.BrokerService(socket_path=self.path, executor=executor, allowed_uid=os.geteuid())
        sock = broker.bind()
        if broker._abstract is None:
            broker._bind_alternate()
        worker = threading.Thread(target=broker.serve_forever, daemon=True)
        worker.start()
        try:
            with self.connect_without_pathname():
                reply = service.call(self.path, {"op": "status", "request_id": "a" * 64}, timeout=2)
            self.assertEqual(reply, {"ok": True, "status": {"state": "done"}})
        finally:
            sock.close()
            worker.join(3)
            broker._abstract.close()

    def test_rogue_listener_receives_no_request_before_server_proof(self):
        key = os.urandom(32)
        path = self.path.parent / service._TRANSPORT_KEY
        path.write_bytes(key)
        path.chmod(0o400)
        seen = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as rogue:
            rogue.bind(service._transport_address(key))
            rogue.listen(1)

            def fake_server():
                conn, _ = rogue.accept()
                with conn:
                    conn.settimeout(2)
                    seen.append(service._read_line(conn))
                    conn.sendall(b"0" * 64 + b"\n")
                    seen.append(conn.recv(1024))

            worker = threading.Thread(target=fake_server, daemon=True)
            worker.start()
            with self.connect_without_pathname(), self.assertRaisesRegex(PermissionError, "authentication failed"):
                service.call(self.path, {"op": "status", "request_id": "a" * 64}, timeout=2)
            worker.join(3)
        self.assertEqual(len(seen[0]), 64)
        self.assertEqual(seen[1], b"")
