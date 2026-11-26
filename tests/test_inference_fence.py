import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from stynpilot import inference_fence as fence, managed_activity as activity


class WorkerFenceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder=Path(tmp.name)/"fence"
        self.gid=os.getegid()
        self.uid=os.geteuid()
        self.provision()
    def provision(self,create=True):
        fence._provision(self.folder,self.gid,self.uid,allow_create=create)
    def lock(self,exclusive):
        return fence._lease(self.folder,self.gid,self.uid,exclusive=exclusive)
    def test_stable_inode_and_exclusion(self):
        before=(self.folder/fence.NAME).stat().st_ino
        with self.lock(False):
            self.provision()
            self.assertEqual((self.folder/fence.NAME).stat().st_ino,before)
            with self.assertRaisesRegex(activity.ActivityError,"inference_worker_busy"):
                with self.lock(True):pass
        with self.lock(True):
            with self.assertRaisesRegex(activity.ActivityError,"inference_worker_busy"):
                with self.lock(False):pass
    def test_missing_or_untrusted_refused(self):
        path=self.folder/fence.NAME
        path.chmod(0o666)
        with self.assertRaises(activity.ActivityError):
            with self.lock(False):pass
        path.unlink()
        with self.assertRaises(OSError):self.provision(False)
        with self.assertRaises(activity.ActivityError):
            with self.lock(True):pass
        self.assertFalse(path.exists())
    def test_symlink_refused(self):
        path=self.folder/fence.NAME
        path.unlink()
        path.symlink_to("/dev/null")
        with self.assertRaises(activity.ActivityError):
            with self.lock(True):pass
    def test_child_death_releases_kernel_lease(self):
        root=str(Path(fence.__file__).resolve().parent.parent)
        script="""import sys,os
from pathlib import Path
from stynpilot import inference_fence as f
with f._lease(Path(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]),exclusive=False):
    print("held",flush=True)
    sys.stdin.read(1)
    os._exit(17)
"""
        with subprocess.Popen([sys.executable,"-c",script,str(self.folder),str(self.gid),str(self.uid)],
                env={"PATH":"/usr/bin:/bin","PYTHONPATH":root},stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,text=True) as child:
            try:
                self.assertEqual(child.stdout.readline().strip(),"held")
                with self.assertRaises(activity.ActivityError):
                    with self.lock(True):pass
                child.stdin.write("x")
                child.stdin.flush()
                self.assertEqual(child.wait(5),17)
                with self.lock(True):pass
            finally:
                if child.poll() is None:child.kill()
