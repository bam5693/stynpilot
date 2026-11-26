import os
import tempfile
import unittest
from pathlib import Path
from stynpilot import dev_lab_policy as lab

class LabPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home=Path(tmp.name)
        self.uid=os.geteuid()
        self.root=self.home/".local/share/stynpilot-dev"
        (self.root/"work").mkdir(parents=True)
        for path in lab.CACHE_FILES.values():
            target=self.root/path
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(b"synthetic")
        # Model an enrolled private cache regardless of the developer's umask.
        for entry in self.home.rglob("*"):
            entry.chmod(0o700 if entry.is_dir() else 0o600)
    def report(self,**overrides):
        args=dict(home=self.home,uid=self.uid,kvm=lambda:True,
                  memory=lambda:lab.MIN_RAM,disk=lambda _:lab.MIN_DISK)
        args.update(overrides)
        return lab.inspect(**args)
    def test_exact_commit_and_fixed_scenario_only(self):
        for scenario in lab.SCENARIOS:
            self.assertEqual(lab.scenario_request("a"*40,scenario),
                             {"commit":"a"*40,"scenario":scenario})
        for bad in ("HEAD","main","a"*39,"A"*40,"--help","../x",None):
            with self.assertRaises(lab.LabError):
                lab.scenario_request(bad,"guest_boot_smoke")
        for bad in ("shell","guest_restore --seed /etc/shadow","../guest",{},None):
            with self.assertRaises(lab.LabError):
                lab.scenario_request("a"*40,bad)
    def test_positive_preflight_is_never_launch_authority(self):
        report=self.report()
        if self.uid!=0:
            self.assertTrue(report["preflight_checks_passed"],report)
        self.assertFalse(report["launch_enabled"])
        self.assertFalse(report["cache_integrity_verified"])
        self.assertNotIn(str(self.home),repr(report))
    def test_headroom_and_kvm_fail_closed(self):
        report=self.report(memory=lambda:lab.MIN_RAM-1,disk=lambda _:lab.MIN_DISK-1,kvm=lambda:False)
        self.assertFalse(report["checks"]["memory_headroom"])
        self.assertFalse(report["checks"]["disk_headroom"])
        self.assertFalse(report["checks"]["kvm_access"])
    def test_missing_and_symlink_cache_not_present(self):
        path=self.root/lab.CACHE_FILES["emulator"]
        path.unlink()
        self.assertFalse(self.report()["cache_files_present"]["emulator"])
        path.symlink_to("/dev/null")
        self.assertFalse(self.report()["cache_files_present"]["emulator"])
    def test_writable_cache_parent_refused(self):
        (self.root/"cache").chmod(0o777)
        self.assertFalse(self.report()["checks"]["guest_cache_present"])
    def test_root_cannot_claim_owner_readiness(self):
        report=self.report(uid=0)
        self.assertFalse(report["checks"]["kvm_access"])
        self.assertFalse(report["launch_enabled"])
