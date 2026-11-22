"""Health snapshot from fake /proc, /sys and statvfs."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from stynpilot import health


class HealthTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "proc").mkdir()
        (self.root / "proc/meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
        (self.root / "proc/uptime").write_text("7200.5 100.0\n")
        zone = self.root / "sys/class/hwmon/hwmon0"
        zone.mkdir(parents=True)
        (zone / "temp1_input").write_text("42900\n")
        (zone / "temp2_input").write_text("999999\n")   # implausible, ignored

    def snap(self, **kw):
        stat = SimpleNamespace(f_blocks=100, f_frsize=1, f_bavail=92)
        return health.snapshot(proc=self.root / "proc", sys_root=self.root / "sys",
                               statvfs=lambda p: stat, getloadavg=lambda: (0.4, 0, 0),
                               cpu_count=lambda: 8, **kw)

    def test_all_five_metrics(self):
        self.assertEqual(self.snap(), {"cpu_temperature_c": 42.9, "cpu_usage_percent": 5.0,
                                       "uptime_hours": 7200.5 / 3600, "memory_used_percent": 75.0,
                                       "disk_used_percent": 8.0})

    def test_missing_sources_are_left_out_not_invented(self):
        (self.root / "proc/meminfo").unlink()
        (self.root / "proc/uptime").unlink()
        result = health.snapshot(proc=self.root / "proc", sys_root=self.root / "nothing",
                                 statvfs=lambda p: (_ for _ in ()).throw(OSError()),
                                 getloadavg=lambda: (_ for _ in ()).throw(OSError()))
        self.assertEqual(result, {})

    def test_load_is_capped_at_100(self):
        result = health.snapshot(proc=self.root / "proc", sys_root=self.root / "sys",
                                 getloadavg=lambda: (64.0, 0, 0), cpu_count=lambda: 4,
                                 statvfs=os.statvfs)
        self.assertEqual(result["cpu_usage_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
