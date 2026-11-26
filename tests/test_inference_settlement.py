import tempfile
import unittest
from pathlib import Path
from stynpilot import inference_settlement as s
from stynpilot.managed_activity import ActivityError


class SettlementTests(unittest.TestCase):
    def setUp(self):
        self.uid=1000
        self.group=s.service_cgroup(self.uid)
        self.cg=str(self.group).removeprefix("/sys/fs/cgroup")
        self.active=True
        self.calls=[]
        self.populated=False
        self.port=b""
        self.override=None
    def command(self,uid,op):
        self.assertEqual(uid,self.uid)
        self.calls.append(op)
        if op=="stop":
            self.active=False
            return ""
        state="active" if self.active else "inactive"
        pid="123" if self.active else "0"
        group=self.cg if self.active else ""
        return f"LoadState=loaded\nActiveState={state}\nMainPID={pid}\nControlGroup={self.override if self.override is not None else group}\n"
    def empty(self,group):
        self.assertEqual(group,self.group)
        return not self.populated
    def settle(self):
        return s.stop_and_verify(self.uid,command=self.command,scan=lambda:self.port,empty=self.empty)
    def test_fixed_stop_and_two_checks(self):
        self.settle()
        self.assertEqual(self.calls,["show","stop","show","show"])
    def test_already_inactive(self):
        self.active=False
        self.settle()
        self.assertNotIn("stop",self.calls)
    def test_remaining_descendants_or_listener(self):
        for populated,port in ((True,b""),(False,b"other listener")):
            self.active=True
            self.populated,self.port=populated,port
            with self.assertRaises(ActivityError):
                self.settle()
    def test_unexpected_cgroup_refused_before_stop(self):
        self.override="/other.service"
        with self.assertRaises(ActivityError):
            self.settle()
        self.assertNotIn("stop",self.calls)
    def test_restart_during_verification(self):
        def scan():
            self.active=True
            return b""
        with self.assertRaises(ActivityError):
            s.stop_and_verify(self.uid,command=self.command,scan=scan,empty=self.empty)
    def test_invalid_uid_and_failed_stop(self):
        with self.assertRaises(ActivityError):
            s.stop_and_verify(0,command=self.command)
        def command(uid,op):
            if op=="stop":raise OSError("not stopped")
            return self.command(uid,op)
        with self.assertRaises(ActivityError):
            s.stop_and_verify(self.uid,command=command,scan=lambda:b"",empty=self.empty)
    def test_cgroup_population_includes_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            group=Path(tmp)/"unit"
            self.assertTrue(s.empty_group(group))
            group.mkdir()
            self.assertFalse(s.empty_group(group))
            (group/"cgroup.events").write_text("populated 1\nfrozen 0\n")
            self.assertFalse(s.empty_group(group))
            (group/"cgroup.events").write_text("populated 0\nfrozen 0\n")
            self.assertTrue(s.empty_group(group))
