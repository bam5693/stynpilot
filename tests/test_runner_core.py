"""S3a: workspace rules, recipe argument validation and the sandbox unit, attacked the way a hostile workspace or a
manipulated AI request would. Pure policy tests; the real-systemd behaviour is proven by the S3b self-test job."""
import os
import random
import tempfile
import unittest
from pathlib import Path

from stynpilot import runner
from stynpilot.runner import RunnerError, build_argv, check_workspace, unit_command


def refused(test, fn, *args, **kw):
    with test.assertRaises(RunnerError) as caught:
        fn(*args, **kw)
    return caught.exception.code


class Workspaces(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.realpath(tmp.name)
        os.chmod(self.home, 0o755)
        self.ws = os.path.join(self.home, "projects", "app")
        os.makedirs(self.ws, mode=0o755)

    def test_a_normal_project_folder_is_accepted_exactly_as_written(self):
        self.assertEqual(check_workspace(self.ws, home=self.home), self.ws)

    def test_the_home_folder_things_outside_it_and_hidden_places_are_refused(self):
        for bad in (self.home, os.path.dirname(self.home), "/etc", "/", "/tmp", os.path.join(self.home, "..")):
            refused(self, check_workspace, bad, home=self.home)
        hidden = os.path.join(self.home, ".config", "app")
        os.makedirs(hidden)
        refused(self, check_workspace, hidden, home=self.home)
        inner = os.path.join(self.home, "projects", ".git-stuff")
        os.makedirs(inner)
        refused(self, check_workspace, inner, home=self.home)

    def test_paths_that_are_not_canonical_or_carry_odd_characters_are_refused(self):
        for bad in (self.ws + "/", self.ws + "/.", self.ws + "/../app", "projects/app", self.ws + " x", self.ws + ";id",
                    self.ws + "\n", self.ws + ",x", self.ws + ":/etc", self.ws + "$HOME", "", None, 5, "x" * 300):
            refused(self, check_workspace, bad, home=self.home)

    def test_symlinks_are_refused_in_any_component(self):
        link = os.path.join(self.home, "link")
        os.symlink(self.ws, link)
        refused(self, check_workspace, link, home=self.home)
        refused(self, check_workspace, os.path.join(link, "x"), home=self.home)
        os.makedirs(os.path.join(self.ws, "sub"))
        os.symlink("/etc", os.path.join(self.ws, "etc-link"))
        refused(self, check_workspace, os.path.join(self.ws, "etc-link"), home=self.home)

    def test_credential_named_folders_and_stynpilot_state_are_refused(self):
        for name in ("credentials", "id_rsa", "secrets.d", "token"):
            p = os.path.join(self.home, name)
            os.makedirs(p, exist_ok=True)
            refused(self, check_workspace, p, home=self.home)
        state = os.path.join(self.home, "state")
        os.makedirs(state)
        refused(self, check_workspace, state, home=self.home, extra_deny=[state])
        refused(self, check_workspace, os.path.join(state, "x"), home=self.home, extra_deny=[state])

    def test_world_writable_and_foreign_owned_folders_are_refused(self):
        os.chmod(self.ws, 0o777)
        refused(self, check_workspace, self.ws, home=self.home)
        os.chmod(self.ws, 0o755)
        if os.geteuid() == 0:
            os.chown(self.ws, 65534, 65534)
            refused(self, check_workspace, self.ws, home=self.home)


class Recipes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ws = os.path.realpath(tmp.name)
        (Path(self.ws) / "tests").mkdir()
        (Path(self.ws) / "tests" / "test_a.py").write_text("")

    def test_every_recipe_builds_with_no_arguments_and_uses_an_absolute_binary(self):
        for rid, recipe in runner.RECIPES.items():
            argv = build_argv(rid, [], self.ws)
            self.assertTrue(os.path.isabs(argv[0]), rid)
            expected = recipe.argv if recipe.argv[0] != "/usr/bin/git" else (
                recipe.argv[:1] + ("-c", "safe.directory=" + self.ws) + recipe.argv[1:])
            self.assertEqual(argv, expected)

    def test_valid_arguments_are_passed_through_in_order(self):
        self.assertEqual(build_argv("make", ["-j4", "-k", "test"], self.ws)[-3:], ("-j4", "-k", "test"))
        self.assertEqual(build_argv("pytest", ["-q", "-k", "login and not slow", "tests/test_a.py"], self.ws)[-4:],
                         ("-q", "-k", "login and not slow", "tests/test_a.py"))
        self.assertEqual(build_argv("python-unittest", ["-v", "tests.test_a"], self.ws)[-2:], ("-v", "tests.test_a"))
        self.assertEqual(build_argv("git-log", ["--oneline", "-n", "5"], self.ws)[-3:], ("--oneline", "-n", "5"))

    def test_hostile_arguments_are_all_refused(self):
        cases = {
            "make": [["-f", "/etc/passwd"], ["-C", "/"], ["--file=x"], ["VAR=x"], ["CC=/bin/sh"], ["-j4;id"], ["$(id)"],
                     ["a b"], ["`id`"], ["-j999"], ["--eval=x"], ["test", "--"], ["-"]],
            "pytest": [["-c", "evil.ini"], ["-p", "evil"], ["--rootdir=/"], ["/etc/passwd"], ["../x"], ["tests/../../etc"],
                       ["-k", "-x"], ["-k"], ["--maxfail", "x"], ["--maxfail", "100"], ["--co", "x"], ["--import-mode=x"]],
            "python-unittest": [["-c", "import os"], ["os.system('id')"], ["-m", "x"], ["tests;id"], ["-s", "/etc"], ["-s", ".."],
                                ["--help;"], ["a" * 300]],
            "git-diff": [["--output=/tmp/x"], ["--ext-diff"], ["--no-index"], ["-c", "core.pager=sh"], ["/etc/shadow"],
                         ["--exec-path=/x"], ["--textconv"], ["-O/tmp/x"], [".."], ["--"]],
            "git-log": [["--output=x"], ["-n", "-1"], ["-n", "1000"], ["--format=%H"], ["--all-match", "x"], ["-n"]],
            "git-status": [["--porcelain"]], "npm-test": [["--ignore-scripts"], ["run", "x"]],
            "cargo-test": [["--manifest-path", "/x"], ["--config", "x"], ["-Z", "x"], ["--target-dir=/x"]],
            "ruff-check": [["--fix"], ["--config", "x"], ["--output-file=/x"], ["/etc"]],
        }
        for rid, lists in cases.items():
            for args in lists:
                refused(self, build_argv, rid, args, self.ws)

    def test_malformed_requests_are_refused(self):
        refused(self, build_argv, "rm", [], self.ws)
        refused(self, build_argv, None, [], self.ws)
        refused(self, build_argv, "make", "test", self.ws)
        refused(self, build_argv, "make", [None], self.ws)
        refused(self, build_argv, "make", [""], self.ws)
        refused(self, build_argv, "make", ["a\nb"], self.ws)
        refused(self, build_argv, "make", ["a\x00"], self.ws)
        refused(self, build_argv, "make", ["t"] * 30, self.ws)

    def test_a_path_argument_that_escapes_through_a_link_is_refused(self):
        os.symlink("/etc", os.path.join(self.ws, "tests", "escape"))
        refused(self, build_argv, "pytest", ["tests/escape"], self.ws)
        os.symlink("/etc/hostname", os.path.join(self.ws, "tests", "f.py"))
        refused(self, build_argv, "pytest", ["tests/f.py"], self.ws)

    def test_fuzz_nothing_option_like_or_unlisted_ever_gets_through(self):
        rng = random.Random(7)
        alphabet = ["-", "--", "=", "/", ".", "..", "a", "Z", "9", " ", ";", "|", "&", "$", "(", ")", "`", "'", '"', "\\", "~", "*", "%",
                    "-j", "tests", "x.py", "\t", "é", "{", "}", "<", ">"]
        for _ in range(4000):
            rid = rng.choice(sorted(runner.RECIPES))
            args = ["".join(rng.choice(alphabet) for _ in range(rng.randint(1, 5))) for _ in range(rng.randint(0, 4))]
            try:
                argv = build_argv(rid, args, self.ws)
            except RunnerError:
                continue
            recipe = runner.RECIPES[rid]
            extra = argv[len(recipe.argv) + (2 if recipe.argv[0] == '/usr/bin/git' else 0):]
            valued = dict(recipe.valued)
            skip = False
            for i, a in enumerate(extra):
                if skip:
                    skip = False
                    continue
                if a.startswith("-"):
                    self.assertTrue(a in recipe.flags or a in valued or any(p.fullmatch(a) for p in recipe.flag_patterns), (rid, args, a))
                    skip = a in valued
                else:
                    self.assertFalse(set(a) & set(";|&$`'\"\\*<>{}\t\n"), (rid, args, a))
                    self.assertFalse(a.startswith(("/", "~", ".")) or ".." in a.split("/"), (rid, args, a))


class SandboxUnit(unittest.TestCase):
    JOB = "0123456789abcdef0123456789abcdef"

    def cmd(self, **kw):
        base = dict(seconds=60, memory_mb=512, tasks=64)
        base.update(kw)
        return unit_command(self.JOB, ("/usr/bin/make", "test"), "/home/o/projects/app", **base)

    def props(self, cmd):
        return [cmd[i + 1] for i, a in enumerate(cmd) if a == "-p"]

    def test_the_command_is_a_list_with_the_workload_after_a_double_dash(self):
        cmd = self.cmd()
        self.assertEqual(cmd[0], "systemd-run")
        self.assertEqual(cmd[cmd.index("--") + 1:], ["/usr/bin/make", "test"])
        self.assertIn("stynpilot-job-" + self.JOB, cmd)

    def test_every_hardening_property_is_present(self):
        props = self.props(self.cmd())
        for want in ("User=stynpilot-run", "Group=stynpilot-run", "SupplementaryGroups=", "ProtectSystem=strict", "ProtectHome=tmpfs",
                     "BindPaths=/home/o/projects/app", "PrivateDevices=yes", "ProtectProc=invisible",
                     "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "RestrictNamespaces=yes",
                     "RestrictSUIDSGID=yes", "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX", "UMask=0077", "LimitCORE=0",
                     "TemporaryFileSystem=/tmp:mode=1777,nosuid,nodev,size=256M", "LimitFSIZE=512M", "RuntimeMaxSec=60", "MemoryMax=512M", "MemorySwapMax=0", "TasksMax=64", "KillMode=control-group",
                     "WorkingDirectory=/home/o/projects/app", "SystemCallFilter=@system-service"):
            self.assertIn(want, props)
        hidden = next(p for p in props if p.startswith("InaccessiblePaths="))
        for path in ("/etc/stynpilot", "/var/lib/stynpilot", "/run/stynpilot", "/run/user", "/root", "/etc/shadow"):
            self.assertIn("-" + path, hidden.split("=", 1)[1].split(" "))   # "-": a missing path is not an error

    def test_it_never_runs_as_root_or_the_owner_and_the_environment_is_fixed(self):
        cmd = self.cmd()
        users = [p for p in self.props(cmd) if p.startswith(("User=", "Group="))]
        self.assertEqual(users, ["User=stynpilot-run", "Group=stynpilot-run"])
        self.assertFalse([a for a in cmd if a.startswith("--uid") or a in ("--user", "--scope", "--shell", "-t", "--pty")])
        envs = {a.split("=", 2)[1] for a in cmd if a.startswith("--setenv=")}
        self.assertEqual(envs, set(runner.ENV))
        self.assertFalse({"SSH_AUTH_SOCK", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} & envs)

    def test_read_only_recipes_get_a_read_only_bind_and_network_is_opt_in(self):
        props = self.props(self.cmd(writes=False))
        self.assertIn("BindReadOnlyPaths=/home/o/projects/app", props)
        self.assertNotIn("BindPaths=/home/o/projects/app", props)
        self.assertIn("PrivateNetwork=no", self.props(self.cmd(network=True)))

    def test_no_value_can_smuggle_a_property_or_an_option(self):
        for bad in ("/home/o/a b", "/home/o/a,b", "/home/o/a:/etc", "/home/o/a\nUser=root", "home/o", "/home/o/../etc", "/home/o/a;b"):
            refused(self, unit_command, self.JOB, ("/usr/bin/make",), bad, seconds=1, memory_mb=1, tasks=1)
        for bad in ("zz", "../x", "a" * 40, "0123456789abcdef\n", 5):
            refused(self, unit_command, bad, ("/usr/bin/make",), "/home/o/p", seconds=1, memory_mb=1, tasks=1)
        for field in ("seconds", "memory_mb", "tasks"):
            for v in (0, -1, "9", 10 ** 9, True):
                limits = dict(seconds=1, memory_mb=1, tasks=1)
                limits[field] = v
                if v is True:
                    continue
                refused(self, unit_command, self.JOB, ("/usr/bin/make",), "/home/o/p", **limits)
        refused(self, unit_command, self.JOB, ("make",), "/home/o/p", seconds=1, memory_mb=1, tasks=1)
        refused(self, unit_command, self.JOB, (), "/home/o/p", seconds=1, memory_mb=1, tasks=1)
        for p in self.props(self.cmd()):
            self.assertNotIn("\n", p)


if __name__ == "__main__":
    unittest.main()
