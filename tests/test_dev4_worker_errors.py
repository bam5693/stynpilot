"""Review blocker 3: an unexpected error inside the upgrade worker must lead to a verified rollback once the
package may have been changed, and 'rolled back' is claimed only when reinstall AND health checks both succeeded."""
import unittest

from test_dev4_upgrade import FakeSystem, WorkerTests as _Base

NEW, OLD = "0.1.0~dev4", "0.1.0~dev3"


class Flaky(FakeSystem):
    """Raises an unexpected error for chosen commands while a chosen version is installed."""

    def __init__(self, *args, boom=None, when_version=None, once=False):
        super().__init__(*args)
        self.boom, self.when_version, self.once = boom, when_version, once

    def __call__(self, argv, timeout=120):
        if self.boom and self.boom(argv) and (self.when_version is None or self.version == self.when_version):
            if self.once:
                self.boom = None
            raise RuntimeError("unexpected")
        return super().__call__(argv, timeout)


class WorkerErrorTests(unittest.TestCase):
    setUp = _Base.setUp
    run_job = _Base.run_job
    installs = _Base.installs

    def machine(self, **kw):
        self.system = Flaky(OLD, {str(self.new): NEW, str(self.old): OLD}, **kw)

    def test_error_while_restarting_the_new_version_is_rolled_back_and_verified(self):
        self.machine(boom=lambda a: a[0] == "systemctl" and "restart" in a, when_version=NEW)
        result = self.run_job()
        self.assertEqual((result["ok"], result["rolled_back"], result["changed_anything"]), (False, True, True))
        self.assertTrue(result["stopped"].startswith("unexpected_"))
        self.assertFalse(result["needs_owner_intervention"])
        self.assertEqual(self.system.version, OLD)
        self.assertEqual(self.installs(), [str(self.new), str(self.old)])

    def test_error_during_the_health_check_is_rolled_back(self):
        self.machine(boom=lambda a: a[0] == "systemctl" and "is-active" in a, when_version=NEW)
        result = self.run_job()
        self.assertEqual((result["ok"], result["rolled_back"]), (False, True))
        self.assertEqual(self.system.version, OLD)

    def test_error_inside_dpkg_itself_still_rolls_back(self):
        self.machine(boom=lambda a: a[0] == "dpkg" and a[-1] == str(self.new), once=True)
        result = self.run_job()
        self.assertEqual((result["ok"], result["rolled_back"]), (False, True))
        self.assertEqual(self.system.version, OLD)
        self.assertIn(str(self.old), self.installs())

    def test_error_before_anything_changed_touches_nothing(self):
        self.machine(boom=lambda a: a[0] == "dpkg-query")
        result = self.run_job()
        self.assertEqual((result["ok"], result["changed_anything"], result["rolled_back"]), (False, False, False))
        self.assertEqual(self.installs(), [])

    def test_rollback_is_not_claimed_when_dpkg_fails_even_if_the_old_version_looks_right(self):
        class OddRollback(FakeSystem):
            def __call__(inner, argv, timeout=120):
                if argv[0] == "dpkg" and "-i" in argv and argv[-1] == str(self.old):
                    return 1, "dpkg: error"                       # reinstall fails; the recorded version stays old
                if argv[0] == "dpkg" and "-i" in argv and argv[-1] == str(self.new):
                    return 1, "dpkg: error"
                return super().__call__(argv, timeout)
        self.system = OddRollback(OLD, {str(self.new): NEW, str(self.old): OLD})
        result = self.run_job()
        self.assertEqual((result["ok"], result["rolled_back"], result["needs_owner_intervention"]), (False, False, True))

    def test_rollback_is_not_claimed_when_health_fails_after_a_good_reinstall(self):
        self.machine()
        self.system.restart_fails = True                          # nothing can be restarted, old or new
        result = self.run_job(health_wait=5)
        self.assertEqual((result["ok"], result["rolled_back"], result["needs_owner_intervention"]), (False, False, True))

    def test_an_error_inside_the_rollback_asks_for_the_owner_and_never_claims_success(self):
        self.machine(boom=lambda a: a[0] == "dpkg" and a[-1] == str(self.old))
        self.system.restart_fails = True                          # forces a rollback, whose reinstall then errors
        result = self.run_job(health_wait=5)
        self.assertEqual((result["ok"], result["rolled_back"], result["needs_owner_intervention"]), (False, False, True))


if __name__ == "__main__":
    unittest.main()
