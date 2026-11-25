"""Probe for the Dev18 'tests' phase that exits 1 with no output. Copy this ONE file into any folder the owner already authorized and run
it with the existing approved recipe:  job_run(recipe="pytest", args=["-s", "-q", "test_release_phase_probe.py"])
It runs inside the same locked-down sandbox the release builder uses (no root, no network, nothing outside the folder's private /tmp). It
replays the authority's exact test command on a tiny fake source tree and prints what happens. It always passes; read the printed lines."""
import os
import resource
import subprocess
import sys
import zipfile

TEST_SCRIPT = ("mkdir -p vendor && for w in cache/*.whl; do /usr/bin/python3 -m zipfile -e \"$w\" vendor || exit 97; done && "
               "cd src && PYTHONPATH=src:../vendor exec /usr/bin/python3 -m pytest -q -p no:cacheprovider tests")


def _sh(cmd, cwd=None):
    got = subprocess.run(["/usr/bin/sh", "-c", cmd], cwd=cwd, capture_output=True, text=True, timeout=120)
    return "exit=%d out=%r err=%r" % (got.returncode, got.stdout[-600:], got.stderr[-600:])


def test_probe(tmp_path):
    print("\n=== PROBE ===")
    print("python", sys.version.split()[0], "uid", os.getuid(), "cwd", os.getcwd())
    print("nofile", resource.getrlimit(resource.RLIMIT_NOFILE), "fsize", resource.getrlimit(resource.RLIMIT_FSIZE))
    print("tools:", _sh("readlink -f /usr/bin/sh /usr/bin/mkdir /usr/bin/python3; /usr/bin/python3 -m pytest --version"))
    (tmp_path / "cache").mkdir()
    with zipfile.ZipFile(tmp_path / "cache/probe_vendor-1.0-py3-none-any.whl", "w") as z:
        z.writestr("probe_vendor/__init__.py", "X = 1\n")
    (tmp_path / "src/src").mkdir(parents=True)
    (tmp_path / "src/tests").mkdir()
    (tmp_path / "src/tests/test_ok.py").write_text("import probe_vendor\n\ndef test_ok():\n    assert probe_vendor.X == 1\n")
    print("step mkdir:", _sh("mkdir -p vendor", tmp_path))
    print("step unzip:", _sh("/usr/bin/python3 -m zipfile -e cache/probe_vendor-1.0-py3-none-any.whl vendor", tmp_path))
    print("step pytest-only:", _sh("cd src && PYTHONPATH=src:../vendor /usr/bin/python3 -m pytest -q -p no:cacheprovider tests", tmp_path))
    print("FULL authority command:", _sh(TEST_SCRIPT, tmp_path))
    print("FULL under sh -x:", _sh("sh -x -c '%s' 2>&1" % TEST_SCRIPT.replace("'", "'\\''"), tmp_path))
    print("=== END PROBE ===")
