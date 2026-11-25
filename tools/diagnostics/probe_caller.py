"""Third probe: WHO makes the forbidden setfsuid call (x86-64 syscall 122) under pytest on the Ryzen. Copy into an authorized folder:
    job_run(recipe="python-unittest", args=["-v", "probe_caller"])
A child runs a tiny pytest with a profile hook that writes every Python->C call (and its Python caller) straight to a file with
os.write, so the last lines survive the seccomp kill. This prints those last lines. Always passes."""
import os
import subprocess
import sys
import tempfile
import unittest

HOOK = r'''
import os, sys
fd = os.open(os.environ["PROBE_LOG"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
def prof(frame, event, arg):
    if event == "c_call":
        try:
            os.write(fd, ("%s.%s <- %s:%d\n" % (getattr(arg, "__module__", "?"), getattr(arg, "__qualname__", repr(arg)),
                          frame.f_code.co_filename, frame.f_lineno)).encode("utf-8", "replace"))
        except Exception:
            pass
sys.setprofile(prof)
import threading; threading.setprofile(prof)
import pytest
sys.exit(pytest.main(sys.argv[1:]))
'''


class Probe(unittest.TestCase):
    def test_probe(self):
        out = sys.__stdout__
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "test_tiny.py"), "w") as f:
                f.write("def test_ok():\n    print('inside')\n")
            log = os.path.join(d, "calls.log")
            got = subprocess.run([sys.executable, "-c", HOOK, "-s", "-q", "-p", "no:cacheprovider", os.path.join(d, "test_tiny.py")],
                                 capture_output=True, text=True, timeout=300, cwd=d, env=dict(os.environ, PROBE_LOG=log))
            print("\n=== PROBE3 === rc=%s out=%r err=%r" % (got.returncode, got.stdout[-200:], got.stderr[-300:]), file=out)
            try:
                lines = open(log, encoding="utf-8", errors="replace").read().splitlines()
            except OSError as e:
                lines = ["no log: %s" % e]
            print("calls logged:", len(lines), file=out)
            for line in lines[-45:]:
                print("  " + line[:230], file=out)
            print("=== END PROBE3 ===", file=out, flush=True)


if __name__ == "__main__":
    unittest.main()
