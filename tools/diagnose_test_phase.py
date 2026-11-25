#!/usr/bin/env python3
"""READ-ONLY-ish diagnostic for a release 'tests' phase that exits without output. Run as root on the machine:
    sudo python3 tools/diagnose_test_phase.py <40-hex commit>
It fetches that commit and the vendored wheels as the build account into a scratch folder under /var/lib/stynpilot-build (the same two
network steps the authority does, outside any secret), then runs the SAME test command through the SAME systemd sandbox the authority uses
(properties come from the installed runner.unit_command), with `sh -x` and an environment probe, and prints the end of the output and the
exit code. It signs, publishes and installs nothing, touches no key or token, and deletes its scratch folder when done."""
import re
import shutil
import subprocess
import sys

LIB = "/usr/lib/stynpilot"
BUILD_USER = "stynpilot-build"
ROOT = "/var/lib/stynpilot-build"
TEST_SCRIPT = ("mkdir -p vendor && for w in cache/*.whl; do /usr/bin/python3 -m zipfile -e \"$w\" vendor || exit 97; done && "
               "cd src && PYTHONPATH=src:../vendor exec /usr/bin/python3 -m pytest -q -p no:cacheprovider tests")
PROBE = ('echo "id=$(id -u) py=$(/usr/bin/python3 -V 2>&1) sh=$(readlink -f /usr/bin/sh)"; '
         '/usr/bin/python3 -c "import sys,pytest;print(\'pytest\',pytest.__version__,sys.version_info[:3])" 2>&1; '
         'sh -x -c "$0" >/tmp/diag.out 2>&1; echo "EXIT=$?"; echo "bytes=$(wc -c </tmp/diag.out)"; tail -n 60 /tmp/diag.out')


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=900, **kw)


def main(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("give the 40-hex commit")
    work = "%s/diag-%s" % (ROOT, commit[:12])
    shutil.rmtree(work, ignore_errors=True)
    as_build = ["runuser", "-u", BUILD_USER, "--"]
    try:
        run(["install", "-d", "-o", BUILD_USER, "-m", "0700", work])
        sys.path[:0] = [LIB + "/lib", LIB + "/vendor"]
        from stynpilot import runner                                            # the installed one: same sandbox as the authority
        for argv in (["git", "init", "-q", "src"],
                     ["git", "-C", "src", "remote", "add", "origin", "https://github.com/bam5693/stynpilot.git"],
                     ["git", "-C", "src", "fetch", "-q", "--depth", "1", "origin", commit],
                     ["git", "-C", "src", "checkout", "-q", "--detach", "FETCH_HEAD"]):
            got = run(as_build + ["env", "HOME=" + work, "GIT_TERMINAL_PROMPT=0"] + argv, cwd=work)
            print("setup", argv[:3], "exit", got.returncode, got.stderr[-200:])
        lock = open(work + "/src/packaging/vendor.lock").read().splitlines()
        for line in lock:
            if line.strip() and not line.startswith("#"):
                spec = line.split()[0]
                got = run(as_build + ["env", "HOME=" + work, "/usr/bin/python3", "-m", "pip", "download", "--no-deps", "--only-binary=:all:",
                                      "--no-input", "--no-cache-dir", "-d", work + "/cache", spec], cwd=work)
                print("wheel", spec, "exit", got.returncode, got.stderr[-200:])
        cmd = runner.unit_command("d1a9" + "0" * 20, ["/usr/bin/sh", "-c", PROBE, TEST_SCRIPT], work, seconds=600, memory_mb=2048,
                                  tasks=256, writes=True, network=False, run_user=BUILD_USER)
        got = run(cmd)
        print("sandboxed test phase: systemd-run exit", got.returncode)
        print("stdout tail:\n" + got.stdout[-3500:])
        print("stderr tail:\n" + got.stderr[-1500:])
    finally:
        run(["systemctl", "stop", "stynpilot-job-d1a9" + "0" * 20 + ".service"])
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
