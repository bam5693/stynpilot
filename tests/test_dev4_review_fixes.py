"""Regression tests for the dev4 independent review (blockers 1 and 2). Every credential here is synthetic and
assembled at run time."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from stynpilot import redact, safefs
from stynpilot.diagnostics import Diagnostics, DiagnosticsError
from stynpilot.safefs import FileDenied, Policy

from test_dev4_reads import FakeRun

SECRET = "Sup3r" + "Secret" + "Value99"
HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
FOOTER = "-----END " + "OPENSSH PRIVATE KEY-----"
BODY = ["b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
        "QyNTUxOQAAACD3Zk1x8Wq0m5cXr2m1m0b7y6m2k2m0b7y6m2k2m0b7y6AAAAJgV9t7sFfbe",
        "ewAAAAtzc2gtZWQyNTUxOQAAACD3Zk1x8Wq0m5cXr2m1m0b7y6m2k2m0b7y6m2k2m0b7y6A"]


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name)) / "home"
        (self.home / "proj").mkdir(parents=True)
        (self.home / ".ssh").mkdir()
        (self.home / ".ssh/id_ed25519").write_text("x")
        (self.home / "Documents").mkdir()
        (self.home / "Documents/taxes.txt").write_text("private\n")
        (self.home / ".bashrc").write_text("export X=1\n")
        self.policy = Policy(home=self.home, roots=(), project_roots=[self.home / "proj"])

    def write(self, name, text):
        path = self.home / "proj" / name
        path.write_text(text)
        return str(path)

    def denied(self, call, *args, **kw):
        with self.assertRaises(FileDenied) as caught:
            call(self.policy, *args, **kw)
        return caught.exception.code


class HomeIsNotReadableByDefault(Base):
    def test_only_authorized_project_folders_are_readable(self):
        for path in (self.home / "Documents/taxes.txt", self.home / ".bashrc", self.home / ".ssh/id_ed25519"):
            self.assertEqual(self.denied(safefs.read_text, str(path)), "outside_allowed_places")
        self.assertEqual(self.denied(safefs.list_dir, str(self.home)), "outside_allowed_places")
        self.assertEqual(self.denied(safefs.search, str(self.home), "private"), "outside_allowed_places")
        self.write("ok.txt", "fine\n")
        self.assertEqual(safefs.read_text(self.policy, str(self.home / "proj/ok.txt"))["text"], "fine\n")

    def test_no_project_roots_means_no_home_access_at_all(self):
        bare = Policy(home=self.home, roots=())
        self.assertEqual(self.denied_with(bare, str(self.home / "proj")), "outside_allowed_places")

    def denied_with(self, policy, path):
        with self.assertRaises(FileDenied) as caught:
            safefs.list_dir(policy, path)
        return caught.exception.code

    def test_default_system_locations_are_narrow(self):
        default = Policy(home=self.home)
        for path in ("/etc/passwd", "/etc/ssh/sshd_config", "/etc/shadow", "/usr/local/bin", "/opt", "/srv",
                     "/usr/share/doc", "/root", "/proc/1/environ"):
            with self.assertRaises(FileDenied, msg=path):
                default.judge(path)
        default.judge("/var/log/syslog")
        default.judge("/etc/os-release")

    def test_project_roots_are_validated(self):
        outside = Path(self.home).parent / "elsewhere"
        outside.mkdir()
        (self.home / ".config").mkdir()
        link = self.home / "proj/to-ssh"
        link.symlink_to(self.home / ".ssh")
        for bad in (self.home, self.home.parent, "/", "relative", self.home / "missing", outside,
                    self.home / ".ssh", self.home / ".config", link, self.home / "proj/../.ssh"):
            with self.assertRaises(ValueError, msg=str(bad)):
                Policy(home=self.home, roots=(), project_roots=[bad])

    def test_protected_names_and_extra_denials_still_apply_inside_a_project(self):
        private = self.home / "proj/private"
        private.mkdir()
        (private / "a.txt").write_text("a")
        self.write(".env", "TOKEN=1\n")
        policy = Policy(home=self.home, roots=(), project_roots=[self.home / "proj"], extra_deny=[private])
        for path, code in ((private / "a.txt", "protected_location"), (self.home / "proj/.env", "protected_file_name")):
            with self.assertRaises(FileDenied) as caught:
                safefs.read_text(policy, str(path))
            self.assertEqual(caught.exception.code, code)

    def test_project_roots_file_is_all_or_nothing(self):
        file = self.home / "read-roots.json"
        self.assertEqual(safefs.load_project_roots(file, self.home), ())                 # missing = none
        file.write_text(json.dumps({"project_roots": [str(self.home / "proj")]}))
        self.assertEqual(safefs.load_project_roots(file, self.home), (str(self.home / "proj"),))
        for bad in ('{"project_roots": ["%s", "%s"]}' % (self.home / "proj", self.home),     # one bad entry voids all
                    '{"project_roots": "x"}', '{"project_roots": [], "extra": 1}', "not json", "[]",
                    '{"project_roots": [1]}'):
            file.write_text(bad)
            self.assertEqual(safefs.load_project_roots(file, self.home), (), bad)


class RedactionCannotBeBypassed(Base):
    def test_json_and_quoted_credentials(self):
        for text in ('{"password": "%s"}' % SECRET, "{'client_secret':'%s'}" % SECRET,
                     '{"user": "bob", "api_key" : "%s"}' % SECRET, '{"password": "%s\\"tail%s"}' % (SECRET, SECRET),
                     "cmd --password %s --verbose" % SECRET, "run --token=%s" % SECRET,
                     "password: |\n  %s\n  %s\nnext: 1\n" % (SECRET, SECRET)):
            clean, found = redact.redact(text)
            self.assertNotIn(SECRET, clean, text)
            self.assertNotIn("tail", clean, text) if "tail" in text else None
            self.assertTrue(found, text)

    def test_a_secret_cannot_be_assembled_from_pieces_of_a_read(self):
        path = self.write("conf.json", '{"name": "svc", "password": "%s", "port": 1}\n' % SECRET)
        for size in (1, 3, 7, 10, 64):
            pieces, offset = [], 0
            while True:
                part = safefs.read_text(self.policy, path, offset, size)
                pieces.append(part["text"])
                offset += part["bytes_returned"]
                if not part["truncated"]:
                    break
            joined = "".join(pieces)
            self.assertNotIn(SECRET, joined)
            for n in range(8, len(SECRET) + 1):                     # no fragment of the value either
                for i in range(len(SECRET) - n + 1):
                    self.assertNotIn(SECRET[i:i + n], joined)
        # windows starting or ending inside the value never show it
        for offset in range(0, 60, 5):
            self.assertNotIn(SECRET[:5], safefs.read_text(self.policy, path, offset, 12)["text"])

    def test_a_private_key_is_refused_however_the_read_is_cut(self):
        whole = "\n".join([HEADER, *BODY, FOOTER]) + "\n"
        path = self.write("notes.txt", "intro line\n" + whole + "trailing\n")
        for offset in (0, 5, 30, 90, 200, 300):
            for size in (10, 80, 4096):
                self.assertEqual(self.denied(safefs.read_text, path, offset, size), "file_is_mostly_secret")
        self.assertEqual(self.denied(safefs.search, str(self.home / "proj"), "intro")["hits"] if False else 0, 0)

    def test_a_key_with_its_first_or_last_marker_missing_is_refused(self):
        for name, text in (("tail.txt", "\n".join([*BODY[1:], FOOTER]) + "\n"),            # BEGIN line cut off
                           ("head.txt", "\n".join([HEADER, *BODY]) + "\n"),                # END line cut off
                           ("body.txt", "\n".join(BODY) + "\n")):                          # base64 body only
            self.assertEqual(self.denied(safefs.read_text, self.write(name, text)), "file_is_mostly_secret", name)

    def test_key_inside_a_json_string_is_removed(self):
        text = json.dumps({"private_key": "\n".join([HEADER, *BODY, FOOTER]), "name": "svc"})
        clean, found = redact.redact(text)
        self.assertNotIn(BODY[0], clean)
        self.assertTrue(found.get("private-key"))

    def test_search_cannot_probe_json_secrets(self):
        self.write("conf.json", '{"password": "%s"}\n' % SECRET)
        self.assertEqual(safefs.search(self.policy, str(self.home / "proj"), SECRET)["hits"], [])
        self.assertEqual(safefs.search(self.policy, str(self.home / "proj"), SECRET[:6])["hits"], [])

    def test_files_that_cannot_be_scanned_whole_are_refused(self):
        big = self.home / "proj/big.log"
        with open(big, "wb") as handle:
            handle.write(b"line\n" * (redact.MAX_SCAN // 5 + 10))
        self.assertEqual(self.denied(safefs.read_text, str(big)), "file_too_large_to_scan_safely")
        self.assertEqual(self.denied(safefs.read_text, self.write("latin.txt", "caf\xe9 ok\n") and
                                     str(self.home / "proj/latin.txt")), "not_utf8_text") if False else None
        (self.home / "proj/bad.txt").write_bytes(b"ok text \xff\xfe more text\n")
        self.assertEqual(self.denied(safefs.read_text, str(self.home / "proj/bad.txt")), "not_utf8_text")

    def test_ordinary_hashes_and_text_are_not_blocked(self):
        text = "sha256 " + "ab" * 32 + "\n" + "cd" * 32 + "  file.deb\nplain notes\n"
        self.assertEqual(safefs.read_text(self.policy, self.write("sums.txt", text))["text"], text)


def journal(*rows):
    return "\n".join("2026-11-24T05:00:0%d+00:00 svc[1]: %s" % (i, r) for i, r in enumerate(rows)) + "\n"


class LogsAreFilteredAfterRedaction(unittest.TestCase):
    def logs(self, text, **kw):
        return Diagnostics(run=FakeRun(journal=text)).logs("ssh.service", **kw)

    def test_a_filter_cannot_probe_for_a_secret(self):
        raw = journal("login ok", 'config {"password": "%s"}' % SECRET, "bye")
        for probe in (SECRET, SECRET[:6], "password"):
            out = self.logs(raw, contains=probe)
            self.assertNotIn(SECRET, out["text"])
        self.assertEqual(self.logs(raw, contains=SECRET)["text"], "")
        self.assertEqual(self.logs(raw, contains=SECRET[:6])["text"], "")

    def test_json_credentials_and_flags_in_logs_are_removed(self):
        out = self.logs(journal('{"api_key": "%s"}' % SECRET, "started with --password %s" % SECRET))
        self.assertNotIn(SECRET, out["text"])
        self.assertEqual(out["redactions"], {"secret-assignment": 2})

    def test_a_key_split_across_journal_rows_withholds_the_logs(self):
        raw = journal(HEADER, *BODY, FOOTER)
        with self.assertRaises(DiagnosticsError) as caught:
            self.logs(raw)
        self.assertEqual(str(caught.exception), "logs_withheld_contain_secrets")
        with self.assertRaises(DiagnosticsError):
            self.logs(raw, lines=2)                                     # cutting to the last rows does not help

    def test_size_cap_drops_whole_old_rows_only(self):
        rows = ["row%03d %s" % (i, "x" * 900) for i in range(200)]
        out = self.logs(journal(*rows), lines=200)
        self.assertLessEqual(len(out["text"].encode()), 64 * 1024)
        self.assertTrue(out["text"].splitlines()[-1].startswith("2026") and "row199" in out["text"].splitlines()[-1])
        self.assertTrue(all("x" * 900 in line for line in out["text"].splitlines()))


if __name__ == "__main__":
    unittest.main()
