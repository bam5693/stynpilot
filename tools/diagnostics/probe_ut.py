"""Second probe (stdlib unittest, no pytest needed to START). Copy into an authorized folder and run with the approved recipe:
    job_run(recipe="python-unittest", args=["-v", "probe_ut"])
Each step runs as a CHILD process inside the same sandbox, so a step killed by the seccomp filter shows here as a negative return
code (-31 = SIGSYS) instead of silently killing everything. Always passes; read the printed lines."""
import os
import subprocess
import sys
import tempfile
import unittest

STEPS = [
    ("python starts", [sys.executable, "-c", "print('ok')"]),
    ("faulthandler on", [sys.executable, "-X", "faulthandler", "-c", "print('ok')"]),
    ("import pytest", [sys.executable, "-c", "import pytest;print(pytest.__version__)"]),
    ("pytest --version", [sys.executable, "-m", "pytest", "--version"]),
    ("pytest no faulthandler", [sys.executable, "-m", "pytest", "-p", "no:faulthandler", "--version"]),
    ("pytest no cacheprovider", [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--version"]),
    ("pytest run tiny", None),
    ("pytest run tiny no faulthandler", None),
]


class Probe(unittest.TestCase):
    def test_probe(self):
        out = sys.__stdout__
        print("\n=== PROBE2 === python", sys.version.split()[0], "uid", os.getuid(), file=out, flush=True)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "test_tiny.py"), "w") as f:
                f.write("def test_ok():\n    print('inside')\n")
            for name, argv in STEPS:
                if argv is None:
                    argv = [sys.executable, "-m", "pytest", "-s", "-q", "-p", "no:cacheprovider"] + (
                        ["-p", "no:faulthandler"] if "no faulthandler" in name else []) + [os.path.join(d, "test_tiny.py")]
                try:
                    got = subprocess.run(argv, capture_output=True, text=True, timeout=120, cwd=d)
                    print("%-32s rc=%s out=%r err=%r" % (name, got.returncode, got.stdout[-300:], got.stderr[-300:]), file=out, flush=True)
                except Exception as e:
                    print("%-32s %s %s" % (name, type(e).__name__, e), file=out, flush=True)
        print("=== END PROBE2 ===", file=out, flush=True)


if __name__ == "__main__":
    unittest.main()
