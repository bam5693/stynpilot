"""C5 hardware inventory: reads fake /proc and /sys trees; never returns identifiers; each section fails alone."""
import json
import tempfile
import unittest
from pathlib import Path

from stynpilot import inventory

CPUINFO = ("processor\t: 0\nmodel name\t: AMD Ryzen 7 5800X 8-Core Processor\nphysical id\t: 0\ncpu cores\t: 8\n\n"
           "processor\t: 1\nmodel name\t: AMD Ryzen 7 5800X 8-Core Processor\nphysical id\t: 0\ncpu cores\t: 8\n")
LSBLK = json.dumps({"blockdevices": [
    {"name": "nvme0n1", "model": "Samsung SSD 980", "size": "1000204886016", "rota": False, "tran": "nvme", "type": "disk",
     "children": [{"name": "nvme0n1p1", "size": "536870912", "fstype": "vfat", "mountpoints": ["/boot/efi"], "type": "part"},
                  {"name": "nvme0n1p2", "size": "999000000000", "fstype": "ext4", "mountpoints": ["/", "/home/coty/secret-mount"], "type": "part"}]},
    {"name": "sda", "model": "WDC WD40", "size": "4000787030016", "rota": True, "tran": "sata", "type": "disk"},
    {"name": "loop0", "size": "100", "type": "loop"}, {"name": "zram0", "size": "100", "type": "disk"}]})
LSPCI = ('00:02.0 "VGA compatible controller" "NVIDIA Corporation" "GA104 [GeForce RTX 3070]" -ra1 "Gigabyte" "x"\n'
         '00:03.0 "Ethernet controller" "Realtek" "RTL8111"\n')
DPKG = "bash\t5.2\tii \nhtop\t3.3\tii \nold\t1\trc \n"


def fake_run(argv):
    return {"lspci": (0, LSPCI), "lsblk": (0, LSBLK), "dpkg-query": (0, DPKG), "apt-mark": (0, "bash\nhtop\nghost\n")}[argv[0]]


class InventoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "proc/sys/kernel").mkdir(parents=True)
        (root / "proc/cpuinfo").write_text(CPUINFO)
        (root / "proc/meminfo").write_text("MemTotal:       33554432 kB\nMemAvailable: 1 kB\n")
        (root / "proc/sys/kernel/osrelease").write_text("6.8.0-test\n")
        dmi = root / "sys/class/dmi/id"
        dmi.mkdir(parents=True)
        for name, value in (("board_vendor", "ASUSTeK"), ("board_name", "TUF GAMING B550"), ("bios_version", "3001"),
                            ("board_serial", "SECRET-SERIAL"), ("product_uuid", "SECRET-UUID"), ("sys_vendor", "System manufacturer")):
            (dmi / name).write_text(value + "\n")
        cpu = root / "sys/devices/system/cpu/cpu0/cpufreq"
        cpu.mkdir(parents=True)
        (cpu / "cpuinfo_max_freq").write_text("4700000\n")
        (root / "os-release").write_text('PRETTY_NAME="Kubuntu 26.04.1 LTS"\nVERSION_ID="26.04"\nHOME_URL="x"\n')
        self.root = root
        self.snap = inventory.snapshot(fake_run, proc=str(root / "proc"), sys_root=str(root / "sys"),
                                       os_release=str(root / "os-release"))

    def test_sections(self):
        s = self.snap
        self.assertEqual(s["os"]["name"], "Kubuntu 26.04.1 LTS")
        self.assertEqual(s["os"]["kernel"], "6.8.0-test")
        self.assertEqual((s["cpu"]["model"], s["cpu"]["logical_cpus"], s["cpu"]["physical_cores"], s["cpu"]["max_mhz"]),
                         ("AMD Ryzen 7 5800X 8-Core Processor", 2, 8, 4700))
        self.assertEqual((s["motherboard"]["motherboard_vendor"], s["motherboard"]["motherboard"]), ("ASUSTeK", "TUF GAMING B550"))
        self.assertEqual(s["memory"]["total_gib"], 32.0)
        self.assertIsNone(s["memory"]["modules"])
        self.assertEqual(s["gpu"]["adapters"], [{"vendor": "NVIDIA Corporation", "device": "GA104 [GeForce RTX 3070]"}])
        d = s["storage"]["drives"]
        self.assertEqual([x["kind"] for x in d], ["nvme", "hdd"])
        self.assertEqual(d[0]["partitions"][1]["system_mounts"], ["/"])
        self.assertEqual(s["software"]["apt_package_count"], 2)
        self.assertEqual([p["name"] for p in s["software"]["apt_manual"]], ["bash", "htop"])

    def test_no_identifiers_leak(self):
        text = json.dumps(self.snap)
        for secret in ("SECRET-SERIAL", "SECRET-UUID", "secret-mount", "/home/coty"):
            self.assertNotIn(secret, text)

    def test_each_section_fails_alone(self):
        def broken(argv):
            raise OSError("boom")
        snap = inventory.snapshot(broken, proc="/nonexistent", sys_root="/nonexistent", os_release="/nonexistent")
        self.assertEqual(set(snap), {"os", "cpu", "motherboard", "memory", "gpu", "storage", "software"})
        self.assertTrue(snap["gpu"].get("unavailable") or snap["gpu"].get("adapters") == [])
        self.assertIsNone(snap["memory"]["total_bytes"])

    def test_output_is_bounded(self):
        many = "".join("pkg%d\t1\tii \n" % i for i in range(1000))
        out = inventory.software_info(lambda argv: (0, many if argv[0] == "dpkg-query" else " ".join("pkg%d" % i for i in range(1000))))
        self.assertEqual(len(out["apt_manual"]), inventory.MAX_PACKAGES)
        self.assertTrue(out["apt_manual_truncated"])

    def test_garbage_command_output_is_tolerated(self):
        self.assertIsNone(inventory.drive_info(lambda a: (0, "not json"))["drives"])
        self.assertIsNone(inventory.drive_info(lambda a: (1, ""))["drives"])
        self.assertEqual(inventory.gpu_info(lambda a: (0, '"unterminated'))["adapters"], [])

    def test_control_characters_stripped(self):
        self.assertEqual(inventory._clean("A\x1b[31mB\x00"), "A[31mB")


if __name__ == "__main__":
    unittest.main()
