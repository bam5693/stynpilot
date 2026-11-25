"""Dev18 review BLOCKER: root builds the self-test scratch tree; an owner-side process must never be able to make root create, truncate
or re-permission a file outside it by swapping in a symbolic link."""
import os
import pwd
import stat
import tempfile
import unittest
from pathlib import Path

from stynpilot.broker import selftest


@unittest.skipUnless(os.geteuid() == 0, "needs root (the real self-test runs as root)")
class ScratchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        os.chmod(self.tmp, 0o755)
        self.outside = self.tmp / "outside.txt"
        self.outside.write_text("precious")
        os.chmod(self.outside, 0o640)
        self.owner = pwd.getpwnam("nobody")

    def snapshot(self):
        st = os.lstat(self.outside)
        return self.outside.read_text(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid

    def test_a_planted_link_is_never_followed_by_the_file_helper(self):
        before = self.snapshot()
        d = self.tmp / "d"
        d.mkdir(mode=0o700)
        (d / "root-only.bin").symlink_to(self.outside)
        fd = os.open(str(d), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(OSError):
                selftest._make_file(fd, "root-only.bin", b"root", 0o600)
            with self.assertRaises(OSError):
                selftest._make_dir(fd, "root-only.bin", 0o777)
        finally:
            os.close(fd)
        self.assertEqual(self.snapshot(), before)

    def test_nothing_is_reachable_by_the_owner_until_the_tree_is_complete_and_late_swaps_change_nothing_outside(self):
        before = self.snapshot()
        seen = []
        test = self

        class FakeRunner:
            def _acl_scratch(self, folder):
                ws = test.tmp / "selftest"
                st = os.lstat(ws)
                seen.append((folder, st.st_uid, stat.S_IMODE(st.st_mode)))
                for name in (".env", "root-only.bin", ".ssh/id_ed25519", ".stynpilot-trash/old.txt", "decoy/decoy.txt"):
                    test.assertTrue(os.path.isfile(ws / name) and not os.path.islink(ws / name))
                    test.assertEqual(os.lstat(ws / name).st_uid, 0)
                # The owner gets access from here on: act like a hostile owner and swap every entry for a link to the outside file.
                if folder.endswith("/selftest"):
                    for name in ("root-only.bin", ".env", "decoy"):
                        p = ws / name
                        if p.is_dir() and not p.is_symlink():
                            for child in p.iterdir():
                                child.unlink()
                            p.rmdir()
                        else:
                            p.unlink()
                        p.symlink_to(test.outside)

        ws, decoy, canaries, root_only = selftest._prepare_scratch(self.tmp / "selftest", self.owner, FakeRunner())
        self.assertEqual([s[1:] for s in seen], [(0, 0o700), (0, 0o700)])       # root-owned and private at every ACL step
        self.assertEqual(seen[0][0], decoy)
        self.assertEqual(os.lstat(ws).st_uid, self.owner.pw_uid)                 # handed over last
        self.assertEqual(self.snapshot(), before)                                # the outside file was never touched
        self.assertTrue(root_only.endswith("/root-only.bin") and len(canaries) == 3)

    def test_a_scratch_folder_that_already_exists_is_refused(self):
        (self.tmp / "selftest").mkdir()
        with self.assertRaises(FileExistsError):
            selftest._prepare_scratch(self.tmp / "selftest", self.owner, None)


if __name__ == "__main__":
    unittest.main()
