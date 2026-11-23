"""M1: package search and analysis helpers (local indexes only; fake machine)."""
import unittest

from stynpilot.broker import apt
from tests.fake_machine import FakeMachine


def machine(**kw):
    return FakeMachine(installed=kw.get("installed", {"bash": "5"}),
                       available=kw.get("available", {"ncdu": "2.3-1", "libncurses6": "6.4", "tree": "2.1-1"}),
                       deps=kw.get("deps", {"ncdu": ["libncurses6"]}))


class SearchTests(unittest.TestCase):
    def test_finds_ubuntu_packages_with_installed_state(self):
        m = machine(installed={"bash": "5", "tree": "2.1-1"})
        found = apt.search("tree", m)
        self.assertEqual([f["name"] for f in found], ["tree"])
        self.assertEqual(found[0]["installed"], "2.1-1")
        self.assertEqual(found[0]["version"], "2.1-1")

    def test_third_party_source_excluded(self):
        m = machine()
        m.origin["ncdu"] = "Evil"
        self.assertEqual(apt.search("ncdu", m), [])

    def test_exact_name_first_and_bounded(self):
        m = machine(available={"ncdu": "1", **{"ncdu%d" % i: "1" for i in range(30)}})
        found = apt.search("ncdu", m, limit=5)
        self.assertEqual(found[0]["name"], "ncdu")
        self.assertEqual(len(found), 5)

    def test_bad_query_never_reaches_a_command(self):
        m = machine()
        for bad in ("", " ", "a;rm -rf /", "$(x)", "-o", "a|b", "x" * 41, None, 5, "a\nb", "ncdu\x00"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                apt.search(bad, m)
        self.assertEqual(m.commands, [])

    def test_query_is_after_double_dash(self):
        m = machine()
        apt.search("tree", m)
        argv = [c for c in m.commands if c[:2] == ["apt-cache", "search"]][0]
        self.assertEqual(argv[-2:], ["--", "tree"])

    def test_no_match(self):
        self.assertEqual(apt.search("zzzz", machine()), [])


class AnalyzeTests(unittest.TestCase):
    def test_closure_versions_and_meta(self):
        m = machine()
        m.meta["libncurses6"] = {"Priority": "important"}
        a = apt.analyze(["ncdu"], m)
        self.assertEqual(a["installs"], {"ncdu": "2.3-1", "libncurses6": "6.4"})
        self.assertEqual(a["upgrades"], {})
        self.assertEqual(a["removals"], [])
        self.assertEqual(a["meta"]["libncurses6"]["priority"], "important")
        self.assertEqual(a["meta"]["ncdu"]["version"], "2.3-1")
        self.assertEqual(m.changes(), [])

    def test_upgrade_and_removal_reported(self):
        m = machine(installed={"ncdu": "1.0"})
        m.removes_on_install = ["vim"]
        a = apt.analyze(["ncdu"], m)
        self.assertEqual(a["upgrades"], {"ncdu": "1.0"})
        self.assertEqual(a["removals"], ["vim"])

    def test_essential_flag(self):
        m = machine()
        m.meta["libncurses6"] = {"Essential": "yes"}
        self.assertTrue(apt.analyze(["ncdu"], m)["meta"]["libncurses6"]["essential"])

    def test_unknown_package_fails(self):
        with self.assertRaises(RuntimeError):
            apt.analyze(["nosuch"], machine())

    def test_bad_names_refused_before_any_command(self):
        m = machine()
        for bad in ("-o", "A", "x;y", ""):
            with self.assertRaises(ValueError):
                apt.analyze([bad], m)
        self.assertEqual(m.commands, [])


if __name__ == "__main__":
    unittest.main()
