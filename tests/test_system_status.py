"""Phase S1: read-only system-management status. Fixed commands only, secrets never asked for, every section independent."""
import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from stynpilot.system_status import SystemStatus, _nmcli_fields

WIFI = "11111111-2222-3333-4444-555555555555"
ETH = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeRun:
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, argv, timeout=10):
        self.calls.append(list(argv))
        key = argv[0]
        if key in self.fail:
            return 127, ""
        if argv[:2] == ["systemctl", "is-enabled"]:
            return 1, {"sleep.target": "masked\n", "suspend.target": "masked\n", "hybrid-sleep.target": "static\n",
                       "suspend-then-hibernate.target": "static\n"}.get(argv[2], "enabled\n")
        if argv[:3] == ["systemctl", "--user", "is-enabled"]:
            return 0, "enabled\n"
        if argv[:2] == ["systemctl", "--failed"]:
            return 0, ""
        if argv[0] == "systemd-analyze" and argv[-1] == "systemd/logind.conf":
            return 0, "# /etc/systemd/logind.conf\n[Login]\n#HandleLidSwitch=suspend\nHandleLidSwitch=ignore\nIdleAction=ignore\n"
        if argv[0] == "systemd-analyze":
            return 0, "[Sleep]\nAllowSuspend=no\n"
        if argv[0] == "gsettings":
            return 0, "'nothing'\n" if argv[-1].endswith("type") else "uint32 0\n"
        if argv[:5] == ["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,AUTOCONNECT,AUTOCONNECT-PRIORITY", "connection"]:
            return 0, "Home\\: 5G:%s:802-11-wireless:wlp3s0:yes:0\nWired:%s:802-3-ethernet::yes:-999\n" % (WIFI, ETH)
        if argv[:2] == ["nmcli", "-g"]:
            return 0, "0\n"
        if argv[:3] == ["nmcli", "-t", "networking"]:
            return 0, "full\n"
        if argv[0] == "loginctl":
            return 0, "yes\n"
        if argv[0] == "ethtool":
            return 0, "Settings for enp4s0:\n\tSupports Wake-on: pumbg\n\tWake-on: d\n"
        return 1, ""


class SystemStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        s = self.tmp / "sys"
        for p, v in {"power/state": "freeze mem disk\n", "power/mem_sleep": "s2idle [deep]\n", "power/disk": "[platform] shutdown\n",
                     "class/power_supply/AC/type": "Mains\n", "class/power_supply/AC/online": "1\n",
                     "class/net/enp4s0/device/power/wakeup": "enabled\n", "class/net/wlp3s0/device/power/wakeup": "disabled\n",
                     "class/dmi/id/sys_vendor": "ACME\n", "class/dmi/id/product_name": "Box\n"}.items():
            (s / p).parent.mkdir(parents=True, exist_ok=True)
            (s / p).write_text(v)
        (s / "class/net/wlp3s0/wireless").mkdir()
        (s / "class/net/lo").mkdir()
        self.run = FakeRun()
        self.st = SystemStatus(run=self.run, sys_root=s, reboot_flag=str(self.tmp / "reboot-required"), backup_dir=self.tmp, uid=1000)

    def test_sleep_reports_masking_and_effective_settings(self):
        got = self.st.sleep()
        self.assertTrue(got["sleep_blocked_by_masking"])
        self.assertEqual(got["targets"]["hibernate.target"], "enabled")
        self.assertEqual(got["targets"]["hybrid-sleep.target"], "static")
        self.assertEqual(got["logind"], {"HandleLidSwitch": "ignore", "IdleAction": "ignore"})      # the commented default is ignored
        self.assertEqual(got["sleep_conf"], {"AllowSuspend": "no"})
        self.assertEqual(got["kernel_supports"], ["freeze", "mem", "disk"])
        self.assertEqual(got["desktop_idle"]["sleep-inactive-ac-type"], "nothing")

    def test_network_reports_reconnect_policy_and_never_asks_for_secrets(self):
        got = self.st.network()
        wifi = got["connections"][0]
        self.assertEqual((wifi["name"], wifi["autoconnect"], wifi["autoconnect_retries"], wifi["reconnects_forever"]), ("Home: 5G", True, "0", True))
        self.assertNotIn("autoconnect_retries", got["connections"][1])          # only Wi-Fi is asked about retries
        asked = " ".join(" ".join(c) for c in self.run.calls)
        for secret in ("psk", "password", "secret", "--show-secrets", "-s "):
            self.assertNotIn(secret, asked)
        self.assertEqual(got["connectivity"], "full")

    def test_startup_power_firmware_and_reboot(self):
        boot = self.st.boot()
        self.assertEqual(boot["system_units"]["tailscaled.service"], "enabled")
        self.assertTrue(boot["linger"])
        power = self.st.power()
        cards = {r["interface"]: r for r in power["wake_on_lan"]}
        self.assertNotIn("lo", cards)
        self.assertTrue(cards["enp4s0"]["magic_packet_supported"])
        self.assertFalse(cards["enp4s0"]["magic_packet_enabled"])
        self.assertTrue(cards["wlp3s0"]["wireless"])
        self.assertEqual(power["supplies"][0]["online"], "1")
        fw = self.st.firmware()
        self.assertFalse(fw["power_loss_recovery"]["readable"])
        self.assertEqual(fw["machine"]["sys_vendor"], "ACME")
        self.assertFalse(self.st.reboot()["reboot_required"])
        (self.tmp / "reboot-required").write_text("")
        (self.tmp / "reboot-required.pkgs").write_text("linux-image-6.17\nlinux-image-6.17\n")
        self.assertEqual(self.st.reboot(), {"reboot_required": True, "because_of": ["linux-image-6.17"]})

    def test_backups_are_listed_and_the_newest_verified(self):
        from stynpilot import backup
        state = self.tmp / "state"
        state.mkdir()
        try:
            backup.make_backup(state, str(self.tmp / "stynpilot-backup-20261125-000000.tar"))
        except Exception:
            (self.tmp / "stynpilot-backup-20261125-000000.tar").write_bytes(b"not a tar")
        got = self.st.backups()
        self.assertEqual(got["count"], 1)
        self.assertIn(got["newest"]["verified"], (True, False))
        (self.tmp / "stynpilot-backup-20991231-000000.tar").write_bytes(b"damaged")
        os.utime(self.tmp / "stynpilot-backup-20991231-000000.tar", (time.time() + 10, time.time() + 10))
        got = self.st.backups()
        self.assertEqual(got["newest"]["verified"], False)
        self.assertEqual(got["owner_state_backups"][0]["name"], "stynpilot-backup-20991231-000000.tar")

    def test_one_broken_section_does_not_hide_the_others(self):
        st = SystemStatus(run=FakeRun(fail={"nmcli"}), sys_root=self.tmp / "nope", backup_dir=None, uid=1000)
        got = st.report()
        self.assertEqual(got["network"], {"unavailable": "nmcli_not_answering"})
        self.assertEqual(got["backups"], {"unavailable": "no_backup_folder_configured"})
        self.assertIn("targets", got["sleep"])
        self.assertEqual(set(got), {"sleep", "network", "startup", "power", "firmware", "reboot", "backups"})

    def test_every_command_is_fixed_and_no_shell_is_used(self):
        self.st.report()
        allowed = {"systemctl", "systemd-analyze", "gsettings", "nmcli", "loginctl", "ethtool"}
        self.assertTrue(all(c[0] in allowed for c in self.run.calls))
        self.assertFalse([c for c in self.run.calls if c[0] in ("sh", "bash") or any(";" in a or "|" in a for a in c)])

    def test_nmcli_escaped_colons(self):
        self.assertEqual(_nmcli_fields("a\\:b:c::d"), ["a:b", "c", "", "d"])


class ToolTests(unittest.TestCase):
    def test_the_tool_is_listed_read_only_and_gated_like_diagnostics(self):
        import test_dev4_reads as reads
        h = reads.DiagToolTests("test_tools_exist_and_work_with_only_the_read_scope")
        h.setUp()
        names = {t.name: t for t in asyncio.run(h.server.list_tools())}
        self.assertIn("computer_system_status", names)
        self.assertTrue(names["computer_system_status"].annotations.readOnlyHint)
        out = h.call("computer_system_status", {"device_id": reads.DEVICE})
        self.assertTrue(out["ok"])
        self.assertIn("sleep", out["result"])
        out = h.call("computer_system_status", {"device_id": "dtdev_NOTMINE1234"})
        self.assertEqual(out, {"ok": False, "error": "device_unavailable_or_not_authorized"})


if __name__ == "__main__":
    unittest.main()
