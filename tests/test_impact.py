"""Impact gate: pure rules for which package sets an AI may ask the owner to approve."""
import unittest

from stynpilot import impact


def tx(installs=None, upgrades=None, removals=None, meta=None):
    return {"installs": installs or {}, "upgrades": upgrades or {}, "removals": removals or [], "meta": meta or {}}


class ImpactTests(unittest.TestCase):
    def test_ordinary_tool_allowed(self):
        self.assertEqual(impact.check_transaction(["ncdu"], tx({"ncdu": "1", "libncurses6": "6"})), (None, []))

    def test_refused_families(self):
        cases = {"linux-image-generic": "kernel_or_boot", "grub-efi-amd64": "kernel_or_boot", "fwupd": "kernel_or_boot",
                 "sudo": "login_or_privilege", "libpam-modules": "login_or_privilege", "polkitd": "login_or_privilege",
                 "openssh-server": "remote_access", "xrdp": "remote_access", "systemd-sysv": "core_system",
                 "libc6": "core_system", "apt": "core_system", "ufw": "network_or_firewall",
                 "network-manager": "network_or_firewall", "docker.io": "container_runtime", "containerd": "container_runtime",
                 "stynpilot": "stynpilot_itself", "cryptsetup": "disk_or_encryption", "sddm": "login_or_privilege"}
        for name, code in cases.items():
            self.assertEqual(impact.check_transaction([name], tx({name: "1"}))[0], code, name)

    def test_dependency_in_refused_family_is_refused(self):
        self.assertEqual(impact.check_transaction(["tool"], tx({"tool": "1", "openssh-server": "1"}))[0], "remote_access")

    def test_removals_refused(self):
        self.assertEqual(impact.check_transaction(["ncdu"], tx({"ncdu": "1"}, removals=["vim"]))[0], "would_remove_packages")

    def test_core_upgrade_refused(self):
        meta = {"libfoo": {"priority": "important"}}
        self.assertEqual(impact.check_transaction(["ncdu"], tx({"ncdu": "1", "libfoo": "2"}, {"libfoo": "1"}, meta=meta))[0],
                         "would_upgrade_core_package")
        meta = {"libfoo": {"essential": True}}
        self.assertEqual(impact.check_transaction(["ncdu"], tx({"ncdu": "1", "libfoo": "2"}, {"libfoo": "1"}, meta=meta))[0],
                         "would_upgrade_core_package")

    def test_new_essential_package_refused(self):
        self.assertEqual(impact.check_transaction(["x"], tx({"x": "1", "y": "1"}, meta={"y": {"essential": True}}))[0], "core_system")

    def test_notes(self):
        code, notes = impact.check_transaction(["nginx"], tx({"nginx": "1"}, meta={"nginx": {"installed_size_kb": 900 * 1024}}))
        self.assertIsNone(code)
        self.assertEqual(len(notes), 2)
        code, notes = impact.check_transaction(["ncdu"], tx({"ncdu": "2"}, {"ncdu": "1"}))
        self.assertIsNone(code)
        self.assertIn("upgrades", notes[0])

    def test_explain_is_plain(self):
        for code in ("kernel_or_boot", "login_or_privilege", "would_remove_packages", "package_touches_login_or_boot_files", "unknown"):
            self.assertTrue(impact.explain(code).endswith("."))

    LISTING = (
        "drwxr-xr-x root/root         0 2026-01-01 00:00 ./\n"
        "-rwxr-xr-x root/root     12345 2026-01-01 00:00 ./usr/bin/tool\n"
        "-rwsr-xr-x root/root     12345 2026-01-01 00:00 ./usr/bin/helper\n"
        "-rw-r--r-- root/root       200 2026-01-01 00:00 ./usr/lib/systemd/system/tool.service\n"
        "lrwxrwxrwx root/root         0 2026-01-01 00:00 ./usr/bin/t -> tool\n")

    def test_listing_notes(self):
        code, notes = impact.inspect_listing(self.LISTING)
        self.assertIsNone(code)
        self.assertEqual(len(notes), 2)
        self.assertIn("tool.service", notes[0])
        self.assertIn("helper", notes[1])

    def test_listing_forbidden_paths(self):
        for path in ("./boot/vmlinuz", "./etc/sudoers.d/x", "./etc/pam.d/login", "./etc/ssh/sshd_config", "./etc/apt/sources.list.d/x.list",
                     "./usr/share/polkit-1/rules.d/a.rules", "./lib/modules/6/x.ko", "./etc/shadow"):
            line = "-rw-r--r-- root/root 1 2026-01-01 00:00 %s\n" % path
            self.assertEqual(impact.inspect_listing(line)[0], "package_touches_login_or_boot_files", path)

    def test_listing_directories_alone_are_fine(self):
        self.assertEqual(impact.inspect_listing("drwxr-xr-x root/root 0 2026-01-01 00:00 ./etc/ssh/\n"), (None, []))


if __name__ == "__main__":
    unittest.main()
