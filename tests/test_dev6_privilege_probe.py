"""dev6 regression: the upgrade worker runs as ROOT but the installer admits only the enrolled OWNER (SO_PEERCRED).
The dev5 live failure was a health probe that connected as root and was refused. These tests use the REAL broker
service code on a REAL unix socket and REAL uid switching (they need root, as the sandbox and the worker have)."""
import os
import tempfile
import threading
import unittest

from stynpilot.broker.service import BrokerService
from stynpilot.upgrade_worker import socket_answers

OWNER, OTHER = (65534, 65534), (65533, 65533)
ROOT_ONLY = unittest.skipUnless(os.geteuid() == 0, "needs root to switch users for real")


class Executor:
    owner, device = "o", "d"

    def status(self, rid):
        return {"state": "not_started"}


@ROOT_ONLY
class PrivilegeSeparatedProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o755)
        self.path = os.path.join(self.tmp.name, "installer.sock")
        self.service = BrokerService(socket_path=self.path, executor=Executor(), allowed_uid=OWNER[0])
        self.service.bind()
        threading.Thread(target=self.service.serve_forever, daemon=True).start()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.service._sock.close)

    def test_the_installer_really_refuses_root_which_was_the_dev5_bug(self):
        import json
        import socket
        with socket.socket(socket.AF_UNIX) as c:
            c.settimeout(5)
            c.connect(self.path)
            c.sendall(json.dumps({"op": "status", "request_id": "0" * 64}).encode() + b"\n")
            self.assertEqual(json.loads(c.recv(4096))["error"], "caller_not_enrolled_owner")

    def test_the_probe_as_the_owner_succeeds(self):
        self.assertTrue(socket_answers(self.path, *OWNER))

    def test_the_probe_as_anyone_else_is_refused(self):
        self.assertFalse(socket_answers(self.path, *OTHER))

    def test_no_identity_means_not_proven_and_nothing_is_widened(self):
        self.assertFalse(socket_answers(self.path))
        self.assertFalse(socket_answers(self.path, OWNER[0], None))
        self.assertEqual(oct(os.stat(self.path).st_mode & 0o777), "0o600")      # the door is exactly as narrow as before
        self.assertEqual(os.stat(self.path).st_uid, OWNER[0])

    def test_a_missing_socket_or_a_dead_installer_is_not_proven(self):
        self.assertFalse(socket_answers(os.path.join(self.tmp.name, "nope.sock"), *OWNER))

    def test_the_probe_does_not_leave_the_worker_changed(self):
        socket_answers(self.path, *OWNER)
        self.assertEqual((os.geteuid(), os.getegid()), (0, 0))


@ROOT_ONLY
class WorkerUsesTheOwnerIdentity(unittest.TestCase):
    """End to end through the Worker with the REAL probe: only the job's owner_uid/owner_gid can make it healthy."""
    def test_healthy_with_the_real_probe_needs_the_owner_identity_in_the_job(self):
        import test_dev4_upgrade as up
        from stynpilot.upgrade_worker import Worker
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o755)
        path = os.path.join(tmp.name, "installer.sock")
        service = BrokerService(socket_path=path, executor=Executor(), allowed_uid=OWNER[0])
        service.bind()
        threading.Thread(target=service.serve_forever, daemon=True).start()
        self.addCleanup(service._sock.close)

        def run(job_changes):
            base = up.WorkerTests("run_job")
            base.setUp()
            self.addCleanup(base.tmp.cleanup) if hasattr(base, "tmp") else None
            return base.run_job(answers=socket_answers_real, socket_path=path, **job_changes)

        def socket_answers_real(p, uid=None, gid=None):
            return socket_answers(p, uid, gid, timeout=2)
        good = run({"owner_uid": OWNER[0], "owner_gid": OWNER[1], "health_wait": 6})
        self.assertTrue(good["ok"], good)
        bad = run({"health_wait": 6})                                   # job without an owner identity: fail closed
        self.assertEqual((bad["ok"], bad["stopped"]), (False, "health_check_failed"))
        wrong = run({"owner_uid": OTHER[0], "owner_gid": OTHER[1], "health_wait": 6})
        self.assertFalse(wrong["ok"])


if __name__ == "__main__":
    unittest.main()
