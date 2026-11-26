"""Host-side evidence checks for the offline guest launcher."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "dev_guest", Path(__file__).resolve().parents[1] / "tools/dev/guest.py"
)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestEvidenceTests(unittest.TestCase):
    def boot(self, program, *, cut_power=False, seconds=5):
        with tempfile.TemporaryDirectory() as scratch:
            serial = Path(scratch) / "serial.log"
            diagnostics = Path(scratch) / "qemu.log"
            with diagnostics.open("wb") as log:
                status = guest.boot([sys.executable, "-I", "-c", program], {}, serial, log,
                                    "GUEST_OK", time.monotonic() + seconds, cut_power=cut_power)
            return status, serial.read_bytes(), diagnostics.read_bytes()

    def test_requires_complete_serial_line_and_successful_exit(self):
        self.assertEqual(self.boot("print('GUEST_OK')")[0], 0)
        self.assertEqual(self.boot("print('GUEST_OK', end='')")[0], 1)
        self.assertEqual(self.boot("print('before GUEST_OK')")[0], 1)
        self.assertEqual(self.boot("print('GUEST_OK'); raise SystemExit(3)")[0], 3)
        self.assertEqual(self.boot("import sys; print('GUEST_OK', file=sys.stderr)")[0], 1)

    def test_marker_can_cross_read_boundary(self):
        prefix = "import os, time; os.write(1, b'GUEST'); time.sleep(0.05); "
        self.assertEqual(self.boot(prefix + "os.write(1, b'_OK\\r\\n')")[0], 0)
        self.assertEqual(self.boot(prefix + "os.write(1, b'_' * 70000 + b'GUEST_OK\\n')")[0], 1)

    def test_caps_both_output_streams(self):
        with patch.object(guest, "LOG_LIMIT", 1024):
            status, serial, diagnostics = self.boot("import os; os.write(1, b'a' * 2048)")
            self.assertEqual((status, len(serial), len(diagnostics)), (125, 1024, 0))
            status, serial, diagnostics = self.boot("import os; os.write(2, b'a' * 2048)")
            self.assertEqual((status, len(serial), len(diagnostics)), (125, 0, 1024))

    def test_power_cut_requires_live_process_at_marker(self):
        self.assertEqual(self.boot("import time; print('GUEST_OK', flush=True); time.sleep(30)",
                                  cut_power=True)[0], 0)
        self.assertEqual(self.boot("print('unrelated')", cut_power=True)[0], 1)

    def test_deadline_covers_wait_after_console_closes(self):
        self.assertEqual(self.boot("import os, time; os.close(1); os.close(2); time.sleep(30)",
                                  seconds=0.25)[0], 124)
