"""Read-only software status: fake filesystem roots and fake loopback HTTP, no real host changes."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from stynpilot import service_status as status

UID = os.getuid()
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
V4_LOOP = "0100007F:0BB8"                                  # 127.0.0.1:3000
V4_ANY = "00000000:0BB8"                                   # 0.0.0.0:3000
V6_LOOP = "00000000000000000000000001000000:0BB8"          # [::1]:3000
V6_ANY = "00000000000000000000000000000000:0BB8"           # [::]:3000
V6_OTHER = "B80D0120000000000000000001000000:0BB8"         # [2001:db8::1]:3000

HEALTH_PASS = (200, json.dumps({"status": "pass", "description": "Forgejo", "checks": {"cache:ping": []}}))
VERSION = (200, json.dumps({"version": "15.0.3+gitea-1.22.0"}))
INSTALLER = (200, "<html><title>Installation - Forgejo</title><form action='/'>"
                  "<select name='db_type'></select></form></html>")


def row(local, uid=UID, state="0A"):
    return "   0: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 %5d 0 1 1\n" % (local, state, uid)


def http(routes):
    """Fake loopback GET: routes maps path -> (status, body); a missing path means connection refused."""
    seen = []

    def get(host, port, path):
        seen.append((host, port, path))
        hit = routes.get(path)
        return None if hit is None else (hit[0], {}, hit[1].encode())
    get.seen = seen
    return get


class ServiceStatusTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "proc/net").mkdir(parents=True)
        (self.root / "etc/systemd/system/multi-user.target.wants").mkdir(parents=True)
        (self.root / "usr/local/bin").mkdir(parents=True)
        (self.root / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\n")
        self.tables()

    def tables(self, v4="", v6=""):
        (self.root / "proc/net/tcp").write_text(HEADER + v4)
        (self.root / "proc/net/tcp6").write_text(HEADER + v6)

    def install(self, unit="[Unit]\n", enable=True, user_uid=UID):
        (self.root / "usr/local/bin/forgejo").write_bytes(b"\x7fELF")
        (self.root / "etc/systemd/system/forgejo.service").write_text(unit)
        if enable:
            os.symlink("/etc/systemd/system/forgejo.service",
                       self.root / "etc/systemd/system/multi-user.target.wants/forgejo.service")
        (self.root / "etc/passwd").write_text(
            "root:x:0:0::/root:/bin/bash\nforgejo:x:%d:%d::/var/lib/forgejo:/usr/sbin/nologin\n" % (user_uid, user_uid))

    def check(self, routes, **kw):
        return status.service_status("forgejo", root=str(self.root), get=http(routes), **kw)

    # --- installed / not installed -------------------------------------------------------
    def test_not_installed(self):
        report = self.check({})
        self.assertEqual(report["state"], "not_installed")
        self.assertFalse(report["verified_running"])

    def test_installed_but_not_listening(self):
        self.install(enable=False)
        report = self.check({})
        self.assertEqual(report["state"], "installed_not_listening")
        self.assertFalse(report["service_enabled_at_boot"])

    # --- positive proof ------------------------------------------------------------------
    def test_running_needs_forgejo_to_answer_for_itself(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        report = self.check({"/api/healthz": HEALTH_PASS, "/api/v1/version": VERSION})
        self.assertEqual(report["state"], "running")
        self.assertTrue(report["verified_running"])
        self.assertTrue(report["identified_as_forgejo"])
        self.assertEqual(report["version"], "15.0.3+gitea-1.22.0")
        self.assertIs(report["setup_required"], False)

    def test_setup_page_is_positively_identified(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        report = self.check({"/api/healthz": (302, ""), "/api/v1/version": (302, ""), "/": INSTALLER})
        self.assertEqual(report["state"], "setup_required")
        self.assertIn("127.0.0.1:3000", report["summary"])

    def test_forgejo_reporting_fail_is_unhealthy(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        fail = (200, json.dumps({"status": "fail", "checks": {"database:ping": []}}))
        self.assertEqual(self.check({"/api/healthz": fail})["state"], "unhealthy")

    # --- regressions: unrelated answers must never read as success (PR #7 review) --------
    def test_unrelated_answers_are_unverified_not_running(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        cases = {
            "404 everywhere": {"/api/healthz": (404, "not found"), "/api/v1/version": (404, "nope"), "/": (404, "")},
            "redirects only": {"/api/healthz": (302, ""), "/api/v1/version": (301, ""), "/": (302, "")},
            "malformed json": {"/api/healthz": (200, "{not json"), "/api/v1/version": (200, "[1,2]")},
            "other app's health": {"/api/healthz": (200, '{"status":"ok"}'), "/api/v1/version": (200, '{"v":1}')},
            "status without checks": {"/api/healthz": (200, '{"status":"pass"}')},
            "someone else's front page": {"/api/healthz": (404, ""), "/api/v1/version": (404, ""),
                                          "/": (200, "<html>Welcome to nginx! install db_type</html>")},
            "json version wrong type": {"/api/v1/version": (200, '{"version": 15}')},
        }
        for label, routes in cases.items():
            with self.subTest(label):
                report = self.check(routes)
                self.assertEqual(report["state"], "unverified")
                self.assertFalse(report["verified_running"])
                self.assertFalse(report["identified_as_forgejo"])

    def test_hostile_version_string_is_not_proof(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        report = self.check({"/api/v1/version": (200, json.dumps({"version": "<script>" + "x" * 200}))})
        self.assertEqual(report["state"], "unverified")
        self.assertIsNone(report["version"])

    def test_nothing_answering(self):
        self.install()
        self.tables(v4=row(V4_LOOP))
        self.assertEqual(self.check({})["state"], "listening_not_answering")

    # --- regressions: listener matching (PR #7 review) ----------------------------------
    def test_ipv6_loopback_counts(self):
        self.install()
        self.tables(v6=row(V6_LOOP))
        self.assertEqual(self.check({"/api/healthz": HEALTH_PASS})["state"], "running")

    def test_other_ipv6_address_on_same_port_is_ignored(self):
        self.install()
        self.tables(v6=row(V6_OTHER))
        self.assertEqual(self.check({"/api/healthz": HEALTH_PASS})["state"], "installed_not_listening")

    def test_any_address_listener_is_flagged_as_exposed(self):
        self.install()
        for v4, v6 in ((row(V4_ANY), ""), ("", row(V6_ANY))):
            with self.subTest(v4=bool(v4)):
                self.tables(v4=v4, v6=v6)
                report = self.check({"/api/healthz": HEALTH_PASS})
                self.assertEqual(report["state"], "exposed_beyond_loopback")
                self.assertTrue(report["listening_beyond_loopback"])

    def test_port_owned_by_another_account(self):
        self.install(user_uid=UID + 1000)
        self.tables(v4=row(V4_LOOP, uid=UID))
        report = self.check({"/api/healthz": HEALTH_PASS})
        self.assertEqual(report["state"], "port_used_by_another_program")
        self.assertFalse(report["listener_owned_by_service_account"])

    def test_non_listen_rows_and_other_ports_ignored(self):
        self.install()
        self.tables(v4=row(V4_LOOP, state="01") + row("0100007F:0BB9"))
        self.assertEqual(self.check({})["state"], "installed_not_listening")

    def test_unreadable_proc_is_unknown_not_false(self):
        self.install()
        (self.root / "proc/net/tcp").unlink()
        (self.root / "proc/net/tcp6").unlink()
        self.assertIsNone(self.check({})["listening"])

    # --- files ----------------------------------------------------------------------------
    def test_unit_unchanged_check(self):
        self.install(unit="exact text\n")
        self.assertTrue(self.check({}, unit_content="exact text\n")["checks"]["unit_file"]["matches_catalog"])
        self.assertFalse(self.check({}, unit_content="other\n")["checks"]["unit_file"]["matches_catalog"])

    def test_wrong_symlink_target_is_not_enabled(self):
        self.install(enable=False)
        os.symlink("/tmp/evil.service", self.root / "etc/systemd/system/multi-user.target.wants/forgejo.service")
        self.assertFalse(self.check({})["service_enabled_at_boot"])

    # --- boundaries ----------------------------------------------------------------------
    def test_only_catalog_ids_and_only_loopback_requests(self):
        for bad in ("../etc", "ssh", "", None, 3, "FORGEJO", "x" * 40):
            with self.assertRaises(status.UnknownSoftware):
                status.service_status(bad, root=str(self.root), get=http({}))
        self.install()
        get = http({"/api/healthz": (404, "")})
        status.service_status("forgejo", root=str(self.root), get=get)
        self.assertTrue(get.seen)
        self.assertTrue(all(host == "127.0.0.1" and port == 3000 for host, port, _ in get.seen))

    def test_every_state_has_a_plain_summary_and_report_is_small(self):
        self.assertTrue(all(isinstance(text, str) and text for text in status.STATES.values()))
        self.install()
        self.tables(v4=row(V4_LOOP))
        report = self.check({"/api/healthz": HEALTH_PASS, "/api/v1/version": VERSION})
        self.assertLess(len(json.dumps(report)), 4096)


if __name__ == "__main__":
    unittest.main()
