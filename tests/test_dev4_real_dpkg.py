"""Real-dpkg drill for the self-upgrade worker. Needs root and two built packages; otherwise it skips.
Set STYN_DEV3_DEB (older package) and STYN_DEV4_DEB (newer package). Installs into a throwaway --root."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from stynpilot import upgrade_worker  # noqa: E402

OLD, NEW = os.environ.get("STYN_DEV3_DEB"), os.environ.get("STYN_DEV4_DEB")     # "older" and "newer" package


def deb_version(path):
    if not path or not os.path.exists(path):
        return None
    return subprocess.run(["dpkg-deb", "-f", path, "Version"], capture_output=True, text=True).stdout.strip()


OLD_V, NEW_V = deb_version(OLD), deb_version(NEW)


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def tree_hashes(root):
    out = {}
    base = os.path.join(root, "usr/lib/stynpilot")
    for d, _, files in os.walk(base):
        for n in files:
            p = os.path.join(d, n)
            out[os.path.relpath(p, root)] = sha(p)
    return out


@unittest.skipUnless(os.geteuid() == 0 and OLD and NEW and os.path.exists(OLD or "") and os.path.exists(NEW or ""),
                     "needs root and STYN_DEV3_DEB / STYN_DEV4_DEB")
class RealDpkgDrill(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="drill-")
        self.addCleanup(shutil.rmtree, self.root, True)
        os.makedirs(os.path.join(self.root, "var/lib/dpkg"))
        for f in ("status", "available"):
            open(os.path.join(self.root, "var/lib/dpkg", f), "w").close()
        self.extra = ["--root=" + self.root, "--force-depends", "--no-triggers"]
        self.query = ["--admindir=" + self.root + "/var/lib/dpkg"]
        self.dpkg(["-i", OLD])
        self.job_dir = os.path.join(self.root, "job")
        os.makedirs(self.job_dir)

    def dpkg(self, args):
        r = subprocess.run(["dpkg", *self.extra, *args], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def version(self):
        return subprocess.run(["dpkg-query", *self.query, "-W", "-f", "${Version}", "stynpilot"],
                              capture_output=True, text=True).stdout

    def job(self, **more):
        conf = os.path.join(self.root, "etc-stynpilot.conf")
        with open(conf, "w") as f:
            f.write("owner-config\n")
        self.conf = conf
        job = {"job_dir": self.job_dir, "new_deb": NEW, "new_sha256": sha(NEW), "old_deb": OLD, "old_sha256": sha(OLD),
               "from_version": OLD_V, "to_version": NEW_V, "restart_installer": False,
               "restart_owner": False, "config_hashes": {conf: sha(conf)}, "dpkg_extra": self.extra,
               "query_extra": self.query, "health_wait": 1, "settle_seconds": 0}
        job.update(more)
        return job

    def worker(self, job):
        return upgrade_worker.Worker(job, sleep=lambda s: None)

    def test_upgrade_then_every_program_file_changes_and_config_survives(self):
        before = tree_hashes(self.root)
        result = self.worker(self.job()).execute()
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.version(), NEW_V)
        self.assertNotEqual(before, tree_hashes(self.root))
        with open(self.conf) as f:
            self.assertEqual(f.read(), "owner-config\n")

    def test_failed_health_check_rolls_back_to_byte_identical_dev3(self):
        before = tree_hashes(self.root)
        job = self.job()

        def faulty(path):       # the configuration looks changed only while the NEW version is installed
            return "0" * 64 if path == self.conf and self.version() == NEW_V else sha(path)
        result = upgrade_worker.Worker(job, sleep=lambda s: None, hash_file=faulty).execute()
        self.assertFalse(result["ok"])
        self.assertEqual(result["stopped"], "health_check_failed")
        self.assertTrue(result["rolled_back"], result)
        self.assertFalse(result.get("needs_owner_intervention"))
        self.assertEqual(self.version(), OLD_V)
        self.assertEqual(before, tree_hashes(self.root))

    def test_tampered_package_changes_nothing(self):
        job = self.job(new_sha256="f" * 64)
        result = self.worker(job).execute()
        self.assertFalse(result["ok"])
        self.assertFalse(result["changed_anything"])
        self.assertEqual(self.version(), OLD_V)


if __name__ == "__main__":
    unittest.main()
