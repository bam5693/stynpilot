import os
import tempfile
import threading
import unittest
from pathlib import Path
from stynpilot import managed_activity as activity

class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state=Path(self.tmp.name)
        self.job="a"*32
    def test_exact_finish_and_no_implicit_expiry(self):
        activity.claim(self.state,"inference",self.job)
        self.assertTrue(activity.held(self.state))
        for kind,job in (("dev_lab",self.job),("inference","b"*32)):
            with self.assertRaises(activity.ActivityError):
                activity.finish(self.state,kind,job)
        with self.assertRaises(activity.ActivityError):
            activity.require_idle(self.state)
        activity.finish(self.state,"inference",self.job)
        activity.require_idle(self.state)
    def test_recovery_reservation_and_safe_mode(self):
        control=self.state/"restore-control"
        control.mkdir()
        for name in ("pending.json","safe.json"):
            (control/name).touch()
            with self.assertRaises(activity.ActivityError):
                activity.claim(self.state,"inference",self.job)
            self.assertFalse(activity.held(self.state))
            (control/name).unlink()
    def test_competing_claims(self):
        gate=threading.Barrier(3)
        outcomes=[]
        def run(kind,job):
            gate.wait()
            try:
                activity.claim(self.state,kind,job)
                outcomes.append("claimed")
            except activity.ActivityError as error:
                outcomes.append(error.code)
        threads=[threading.Thread(target=run,args=(kind,job)) for kind,job in
                 (("inference","a"*32),("dev_lab","b"*32))]
        for t in threads:t.start()
        gate.wait()
        for t in threads:t.join(3)
        self.assertEqual(sorted(outcomes),["claimed","managed_activity_busy"])
    def test_corrupt_or_dangling_claim_stays_held(self):
        p=activity.path(self.state)
        p.write_text("broken")
        p.chmod(0o600)
        self.assertTrue(activity.held(self.state))
        with self.assertRaises(activity.ActivityError):
            activity.finish(self.state,"inference",self.job)
        p.unlink()
        p.symlink_to(self.state/"absent")
        self.assertTrue(activity.held(self.state))
        with self.assertRaises(activity.ActivityError):
            activity.claim(self.state,"inference",self.job)
        with self.assertRaises(activity.ActivityError):
            activity.finish(self.state,"inference",self.job)
    def test_permissive_claim_refused(self):
        activity.claim(self.state,"inference",self.job)
        activity.path(self.state).chmod(0o644)
        with self.assertRaises(activity.ActivityError):
            activity.finish(self.state,"inference",self.job)
        self.assertTrue(activity.held(self.state))
    def test_invalid_kind_or_id(self):
        for kind,job in (("shell",self.job),("inference","../x"),("inference",None)):
            with self.assertRaises(activity.ActivityError):
                activity.claim(self.state,kind,job)
        self.assertFalse(activity.held(self.state))

    def test_current_claim_is_exact_and_corruption_is_not_absence(self):
        self.assertIsNone(activity.current(self.state))
        activity.claim(self.state,"inference",self.job)
        self.assertEqual(activity.current(self.state),{"kind":"inference","job_id":self.job})
        activity.path(self.state).write_text("inference:"+self.job+"\n\n")
        with self.assertRaises(activity.ActivityError):
            activity.current(self.state)
        self.assertTrue(activity.held(self.state))
