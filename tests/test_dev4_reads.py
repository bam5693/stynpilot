"""dev4 read tools: secret redaction, protected places, symlink escapes, logs and diagnostics, and the MCP tools."""
import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from stynpilot import redact, safefs
from stynpilot.diagnostics import Diagnostics, DiagnosticsError
from stynpilot.safefs import FileDenied, Policy


# Fake secret shapes are assembled at run time so no secret-looking literal sits in the repository.
AWS_ID = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
JWT = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0", "abcdefghijklmnop"])
GH = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
RANDOM = "Zx9Qm2LpV8nR4t" + "Yw7KjH3sBd6FgC1aEu0XoI5MvN"


class RedactTests(unittest.TestCase):
    def test_common_secret_shapes_are_removed_and_counted(self):
        text = ("author = Bob\ntoken refresh failed\npassword = \"hunter2hunter2\"\nDB_PASSWORD=abc123\n"
                "u=https://me:pw123@host/x\nk " + AWS_ID + "\nAuthorization: Bearer abcdefghijklmnop1234567890\n"
                "jwt " + JWT + "\n"
                "gh " + GH + "\n")
        clean, found = redact.redact(text)
        for secret in ("hunter2hunter2", "abc123", "pw123", AWS_ID, "abcdefghijklmnop1234567890",
                       JWT[:8], GH[:10]):
            self.assertNotIn(secret, clean)
        self.assertIn("author = Bob", clean)                    # ordinary words are left alone
        self.assertIn("token refresh failed", clean)
        self.assertTrue({"jwt", "aws-key", "github-token", "url-password", "secret-assignment"} <= set(found))

    def test_hashes_placeholders_and_normal_text_survive(self):
        text = "commit 3f786850e387550fdab836ed7e6dc881de23001b\napi_key: YOUR_KEY\npassword=\nsha256 " + "ab" * 32
        clean, found = redact.redact(text)
        self.assertEqual(clean, text)
        self.assertEqual(found, {})

    def test_random_looking_strings_and_private_keys(self):
        clean, found = redact.redact("x " + RANDOM + " y")
        self.assertEqual(found, {"random-string": 1})
        block = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n"          # unterminated on purpose
        clean, found = redact.redact("before\n" + block)
        self.assertNotIn("b3Blbn", clean)
        self.assertTrue(redact.mostly_secret(len(block), clean, found))


class SafeFsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(os.path.realpath(tmp.name))
        self.home, self.etc, self.outside = base / "home", base / "etc", base / "outside"
        for d in (self.home / ".ssh", self.home / "proj", self.home / ".config/stynpilot", self.etc, self.outside,
                  self.home / ".local/state/stynpilot"):
            d.mkdir(parents=True)
        (self.home / ".ssh/id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        (self.home / ".config/stynpilot/owner.json").write_text('{"client":"x"}')
        (self.home / ".local/state/stynpilot/requests.sqlite3").write_text("state")
        (self.home / "proj/readme.txt").write_text("hello world\nsecond line\n")
        (self.home / "proj/.env").write_text("TOKEN=abc\n")
        (self.home / "proj/server.pem").write_text("x")
        (self.home / "proj/notes.txt").write_text("db password = SuperSecret99\nother text\n")
        (self.home / "proj/vault.bin").write_bytes(b"\x00\x01\x02binary")
        (self.etc / "shadow").write_text("root:$6$hash:::\n")
        (self.etc / "hosts").write_text("127.0.0.1 localhost\n")
        (self.outside / "secret.txt").write_text("outside\n")
        self.state = self.home / ".local/state/stynpilot"
        self.policy = Policy(home=self.home, roots=(self.etc,), extra_deny=[self.etc / "shadow", self.state])

    def code(self, call, *args, **kw):
        with self.assertRaises(FileDenied) as caught:
            call(self.policy, *args, **kw)
        return caught.exception.code

    def test_reads_ordinary_text_and_expands_home(self):
        out = safefs.read_text(self.policy, "~/proj/readme.txt")
        self.assertEqual(out["text"], "hello world\nsecond line\n")
        self.assertIn("untrusted", out["note"])
        self.assertEqual(safefs.read_text(self.policy, str(self.etc / "hosts"))["text"], "127.0.0.1 localhost\n")

    def test_protected_locations_names_and_binaries_are_refused(self):
        for path, code in ((self.home / ".ssh/id_ed25519", "protected_location"),
                           (self.home / ".config/stynpilot/owner.json", "protected_location"),
                           (self.state / "requests.sqlite3", "protected_location"),
                           (self.home / "proj/.env", "protected_file_name"),
                           (self.home / "proj/server.pem", "protected_file_name"),
                           (self.etc / "shadow", "protected_location"),
                           (self.outside / "secret.txt", "outside_allowed_places"),
                           (self.home / "proj/vault.bin", "binary_file_refused")):
            self.assertEqual(self.code(safefs.read_text, str(path)), code, path)

    def test_symlinks_cannot_escape(self):
        (self.home / "proj/link-key").symlink_to(self.home / ".ssh/id_ed25519")
        (self.home / "proj/link-dir").symlink_to(self.home / ".ssh")
        (self.home / "proj/link-out").symlink_to(self.outside / "secret.txt")
        (self.home / "proj/link-shadow").symlink_to(self.etc / "shadow")
        (self.home / "proj/innocent.txt").symlink_to(self.home / "proj/.env")
        for name in ("link-key", "link-out", "link-shadow", "innocent.txt"):
            self.assertIn(self.code(safefs.read_text, str(self.home / "proj" / name)),
                          ("protected_location", "outside_allowed_places", "protected_file_name"), name)
        self.assertIn(self.code(safefs.list_dir, str(self.home / "proj/link-dir")), ("protected_location",))
        self.assertIn(self.code(safefs.read_text, str(self.home / "proj/link-dir/id_ed25519")), ("protected_location",))
        self.assertIn(self.code(safefs.read_text, str(self.home / "proj/../.ssh/id_ed25519")), ("protected_location",))

    def test_a_path_swapped_for_a_link_after_the_check_is_not_followed(self):
        real = safefs.Policy.judge(self.policy, str(self.home / "proj/readme.txt"))
        os.replace(self.home / "proj/readme.txt", self.home / "proj/moved.txt")
        (self.home / "proj/readme.txt").symlink_to(self.outside / "secret.txt")
        with self.assertRaises(FileDenied):
            safefs._open_checked(real)                           # O_NOFOLLOW: the swapped-in link is refused

    def test_fifos_and_devices_are_not_opened(self):
        fifo = self.home / "proj/pipe"
        os.mkfifo(fifo)
        self.assertEqual(self.code(safefs.read_text, str(fifo)), "not_a_regular_file")

    def test_secret_values_inside_readable_files_are_redacted(self):
        out = safefs.read_text(self.policy, str(self.home / "proj/notes.txt"))
        self.assertNotIn("SuperSecret99", out["text"])
        self.assertIn("other text", out["text"])
        self.assertEqual(out["redactions"], {"secret-assignment": 1})

    def test_a_file_that_holds_a_private_key_is_refused_whole(self):
        (self.home / "proj/doc.txt").write_text("notes\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n")
        self.assertEqual(self.code(safefs.read_text, str(self.home / "proj/doc.txt")), "file_is_mostly_secret")

    def test_listing_marks_protected_entries_and_stops_at_the_limit(self):
        names = {e["name"]: e for e in safefs.list_dir(self.policy, str(self.home / "proj"))["entries"]}
        self.assertTrue(names[".env"].get("protected"))
        self.assertTrue(names["server.pem"].get("protected"))
        self.assertNotIn("protected", names["readme.txt"])
        top = {e["name"]: e for e in safefs.list_dir(self.policy, str(self.home))["entries"]}
        self.assertTrue(top[".ssh"].get("protected"))
        self.assertTrue(safefs.list_dir(self.policy, str(self.home), limit=2)["truncated"])

    def test_search_skips_protected_files_and_cannot_probe_secret_values(self):
        hits = safefs.search(self.policy, str(self.home), "second line")["hits"]
        self.assertEqual([h["path"] for h in hits], [str(self.home / "proj/readme.txt")])
        self.assertEqual(safefs.search(self.policy, str(self.home), "AAAA")["hits"], [])        # inside ~/.ssh: skipped
        self.assertEqual(safefs.search(self.policy, str(self.home), "TOKEN=abc")["hits"], [])    # .env: skipped
        self.assertEqual(safefs.search(self.policy, str(self.home), "SuperSecret99")["hits"], [])  # redacted before matching
        named = safefs.search(self.policy, str(self.home), "readme", name_only=True)["hits"]
        self.assertEqual(len(named), 1)

    def test_invalid_input_is_refused(self):
        for path in ("", "relative/path", "a\x00b", "x" * 5000):
            self.code(safefs.read_text, path)
        self.code(safefs.read_text, str(self.home / "proj/readme.txt"), offset=-1)
        self.code(safefs.read_text, str(self.home / "proj/readme.txt"), max_bytes=10 ** 9)
        self.code(safefs.search, str(self.home), "")
        self.code(safefs.search, str(self.home), "x", glob="../*")

    def test_reading_in_pieces_continues_where_it_stopped(self):
        first = safefs.read_text(self.policy, str(self.home / "proj/readme.txt"), 0, 5)
        self.assertEqual((first["text"], first["truncated"]), ("hello", True))
        rest = safefs.read_text(self.policy, str(self.home / "proj/readme.txt"), 5, 100)
        self.assertEqual(rest["text"], " world\nsecond line\n")
        self.assertFalse(rest["truncated"])


class FakeRun:
    def __init__(self, journal="", code=0):
        self.calls, self.journal, self.code = [], journal, code

    def __call__(self, argv, timeout=10):
        self.calls.append(argv)
        if argv[0] == "journalctl":
            return self.code, self.journal
        if argv[0] == "df":
            return 0, ("Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
                       "/dev/nvme0n1p2 ext4 1000000 400000 600000 40% /\n")
        if argv[0] == "ps":
            return 0, "PID %CPU %MEM COMMAND\n1 0.1 0.2 systemd\n"
        if argv[0] == "ss":
            return 0, "LISTEN 0 4096 127.0.0.1:8443 0.0.0.0:*\nLISTEN 0 4096 *:22 *:*\n"
        if argv[0] == "dpkg-query":
            return 0, "0.1.0~dev4"
        if argv[0] == "systemctl" and "--failed" in argv:
            return 0, "foo.service loaded failed failed Foo\n"
        if argv[0] == "systemctl":
            return 0, "active\n"
        if argv[0] == "apt":
            return 0, "Listing...\nhtop/noble-updates 3.3 amd64 [upgradable from: 3.2]\n"
        if argv[0] == "dpkg":
            return 0, ""
        return 127, ""


class DiagnosticsTests(unittest.TestCase):
    def test_report_has_every_section_and_no_command_lines(self):
        report = Diagnostics(run=FakeRun(), proc="/proc").report()
        for section in ("memory", "system", "disks", "top_processes", "listening_tcp", "failed_units", "stynpilot",
                        "updates", "package_database", "reboot_required"):
            self.assertIn(section, report)
        self.assertEqual(report["disks"][0]["used_percent"], 40)
        self.assertEqual(report["stynpilot"]["installed_version"], "0.1.0~dev4")
        self.assertEqual(report["updates"]["upgradable_count"], 1)
        self.assertEqual(report["failed_units"]["system"], ["foo.service"])
        self.assertEqual(report["top_processes"][0]["program"], "systemd")

    def test_one_failing_probe_does_not_hide_the_rest(self):
        class Broken(FakeRun):
            def __call__(self, argv, timeout=10):
                if argv[0] == "df":
                    raise RuntimeError("boom")
                return super().__call__(argv, timeout)
        report = Diagnostics(run=Broken(), proc="/proc").report()
        self.assertEqual(report["disks"], {"unavailable": True})
        self.assertIn("memory", report)

    def test_log_requests_are_validated_and_arguments_are_fixed(self):
        run = FakeRun(journal="2026-11-23T10:00:00 svc[1]: ok\n2026-11-23T10:00:01 svc[1]: password=Hunter2Hunter2\n")
        out = Diagnostics(run=run).logs("stynpilot-installer.service", lines=50, since="6h", priority="err",
                                        contains="svc")
        argv = run.calls[-1]
        self.assertEqual(argv[:2], ["journalctl", "--no-pager"])
        self.assertIn("-u", argv)
        self.assertIn("stynpilot-installer.service", argv)
        self.assertNotIn("Hunter2Hunter2", out["text"])
        self.assertEqual(out["redactions"], {"secret-assignment": 1})
        Diagnostics(run=run).logs("stynpilot-owner.service")
        self.assertIn("--user-unit", run.calls[-1])
        Diagnostics(run=run).logs("kernel", since="boot")
        self.assertIn("-k", run.calls[-1])
        for bad in ("--vacuum-size=1M", "-u", "x;rm -rf /", "../x.service", "a b.service", "", "ssh", None):
            with self.assertRaises(DiagnosticsError, msg=bad):
                Diagnostics(run=run).logs(bad)
        for kw in ({"since": "forever"}, {"priority": "loud"}, {"contains": ""}, {"contains": "x" * 101}):
            with self.assertRaises(DiagnosticsError):
                Diagnostics(run=run).logs("ssh.service", **kw)

    def test_log_size_is_bounded(self):
        big = "\n".join("line %d %s" % (i, "x" * 100) for i in range(5000))
        out = Diagnostics(run=FakeRun(journal=big)).logs("ssh.service", lines=9999)
        self.assertLessEqual(out["lines_returned"], 500)
        self.assertLessEqual(len(out["text"].encode()), 64 * 1024)

    def test_unreadable_journal_is_reported_honestly(self):
        with self.assertRaises(DiagnosticsError) as caught:
            Diagnostics(run=FakeRun(journal="No journal files were opened due to insufficient permissions.")).logs("ssh.service")
        self.assertEqual(caught.exception.code, "journal_permission_denied")


# ------------------------------------------------------------------------------ the tools, through the real MCP server
try:
    from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
    from mcp.server.auth.provider import AccessToken
    from stynpilot.server.app import create_server
    from tests.test_propose_tools import AUDIENCE, DEVICE, OWNER, Grants, Tokens
    from stynpilot.server.diag_tools import RateLimit
    from stynpilot.server.router import LocalOwnership, ReadRouter
except ImportError:          # pragma: no cover
    create_server = None


@unittest.skipIf(create_server is None, "MCP SDK not installed")
class DiagToolTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = Path(os.path.realpath(tmp.name)) / "home"
        (home / "proj").mkdir(parents=True)
        (home / "proj/a.txt").write_text("hello\n")
        (home / ".ssh").mkdir()
        (home / ".ssh/id_rsa").write_text("secret")
        self.home = home
        self.limiter = RateLimit(per_minute=5)
        router = ReadRouter(tokens=Tokens(), ownership=LocalOwnership(grants=Grants(), owner_id=OWNER, device_id=DEVICE),
                            read_health=lambda: {"cpu_usage_percent": 1.0})
        self.server = create_server(router=router, resource_url=AUDIENCE, diag=dict(
            policy=Policy(home=home, roots=()), diagnostics=Diagnostics(run=FakeRun(journal="ok line\n")),
            limiter=self.limiter))

    def call(self, name, arguments, token="readonly"):
        who = Tokens.valid[token]
        marker = auth_context_var.set(AuthenticatedUser(AccessToken(token=token, client_id="x", scopes=sorted(who.scopes))))
        try:
            result = asyncio.run(self.server.call_tool(name, arguments))
        finally:
            auth_context_var.reset(marker)
        if isinstance(result, tuple) and isinstance(result[1], dict) and "ok" in result[1]:
            return result[1]
        content = result[0] if isinstance(result, tuple) else result
        return json.loads(content[0].text)

    def test_tools_exist_and_work_with_only_the_read_scope(self):
        names = {t.name for t in asyncio.run(self.server.list_tools())}
        self.assertTrue({"computer_diagnostics", "computer_logs", "files_list", "files_stat", "files_read",
                         "files_search"} <= names)
        out = self.call("files_read", {"device_id": DEVICE, "path": str(self.home / "proj/a.txt")})
        self.assertEqual(out["result"]["text"], "hello\n")
        self.assertTrue(self.call("computer_diagnostics", {"device_id": DEVICE})["ok"])
        self.assertEqual(self.call("computer_logs", {"device_id": DEVICE, "unit": "ssh.service"})["result"]["text"], "ok line")

    def test_protected_files_are_refused_through_the_tool(self):
        out = self.call("files_read", {"device_id": DEVICE, "path": str(self.home / ".ssh/id_rsa")})
        self.assertEqual(out, {"ok": False, "error": "protected_location"})

    def test_wrong_device_or_missing_scope_is_not_authorized(self):
        out = self.call("files_read", {"device_id": "dtdev_NOTMINE1234", "path": str(self.home / "proj/a.txt")})
        self.assertEqual(out, {"ok": False, "error": "device_unavailable_or_not_authorized"})
        out = self.call("files_read", {"device_id": DEVICE, "path": str(self.home / "proj/a.txt")}, token="stranger")
        self.assertEqual(out["error"], "device_unavailable_or_not_authorized")

    def test_rate_limit(self):
        results = [self.call("files_stat", {"device_id": DEVICE, "path": str(self.home / "proj")}) for _ in range(7)]
        self.assertEqual([r["ok"] for r in results], [True] * 5 + [False] * 2)
        self.assertEqual(results[-1]["error"], "rate_limited_try_again_in_a_minute")


if __name__ == "__main__":
    unittest.main()
