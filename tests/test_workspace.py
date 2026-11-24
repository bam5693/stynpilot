"""Workspace file operations (the owner's service, never root): real files, real links, real races."""
import os
import stat
import tempfile
import threading
import unittest

from stynpilot.workspace import MAX_FILE, Workspace, WorkspaceError


class WS(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.realpath(tmp.name)
        self.root = os.path.join(base, "proj")
        self.outside = os.path.join(base, "outside")
        os.makedirs(self.root)
        os.makedirs(self.outside)
        with open(os.path.join(self.outside, "secret.txt"), "w") as f:
            f.write("do not touch")
        self.ws = Workspace(self.root)

    def refused(self, code, fn, *a, **kw):
        with self.assertRaises(WorkspaceError) as caught:
            fn(*a, **kw)
        self.assertEqual(caught.exception.code, code, (fn.__name__, a))

    def secret_unchanged(self):
        with open(os.path.join(self.outside, "secret.txt")) as f:
            self.assertEqual(f.read(), "do not touch")

    # -- the everyday work -----------------------------------------------------------------------------
    def test_create_read_edit_move_and_trash(self):
        self.assertTrue(self.ws.write("src/app.py", "print('hi')\n")["created"])
        self.assertEqual(self.ws.read("src/app.py")["text"], "print('hi')\n")
        self.assertEqual(self.ws.edit("src/app.py", "hi", "hello")["replacements"], 1)
        self.assertIn("hello", self.ws.read("src/app.py")["text"])
        self.ws.move("src/app.py", "src/lib/app2.py")
        self.assertEqual([e["name"] for e in self.ws.list("src")["entries"]], ["lib"])
        moved = self.ws.trash("src/lib/app2.py")
        self.assertTrue(moved["kept_in"].startswith(".stynpilot-trash/"))
        self.assertEqual(self.ws.list("src/lib")["entries"], [])
        self.assertEqual(os.listdir(os.path.join(self.root, ".stynpilot-trash"))[0].endswith("src_lib_app2.py"), True)

    def test_overwrite_and_edit_rules(self):
        self.ws.write("a.txt", "one two one")
        self.refused("file_exists_set_overwrite", self.ws.write, "a.txt", "x")
        self.assertFalse(self.ws.write("a.txt", "new", overwrite=True)["created"])
        self.ws.write("b.txt", "one two one")
        self.refused("old_text_not_unique", self.ws.edit, "b.txt", "one", "1")
        self.assertEqual(self.ws.edit("b.txt", "one", "1", replace_all=True)["replacements"], 2)
        self.refused("old_text_not_found", self.ws.edit, "b.txt", "zzz", "1")
        self.refused("edit_invalid", self.ws.edit, "b.txt", "", "1")
        self.ws.write("c.txt", "x")
        self.refused("destination_exists_set_overwrite", self.ws.move, "c.txt", "b.txt")
        self.ws.move("c.txt", "b.txt", overwrite=True)
        self.assertEqual(self.ws.read("b.txt")["text"], "x")

    def test_writes_are_atomic_leave_no_temp_files_and_keep_the_executable_bit(self):
        self.ws.write("run.sh", "#!/bin/sh\n")
        os.chmod(os.path.join(self.root, "run.sh"), 0o755)
        self.ws.edit("run.sh", "sh", "bash")
        self.assertTrue(os.stat(os.path.join(self.root, "run.sh")).st_mode & 0o111)
        self.assertEqual(sorted(os.listdir(self.root)), ["run.sh"])
        self.refused("content_too_large", self.ws.write, "big.txt", "x" * (MAX_FILE + 1))
        self.refused("binary_content_refused", self.ws.write, "bin.dat", "a\x00b")
        self.refused("content_must_be_text", self.ws.write, "n.txt", 5)
        self.assertEqual(sorted(os.listdir(self.root)), ["run.sh"])

    def test_reads_are_redacted_paged_and_labelled_untrusted(self):
        self.ws.write("notes.txt", "token=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8" + "\n" + "y" * 100)
        got = self.ws.read("notes.txt", 0, 50)
        self.assertNotIn("ghp_", got["text"])
        self.assertTrue(got["redactions"])
        self.assertIn("untrusted", got["note"])
        self.assertEqual(self.ws.read("notes.txt", got["next_offset"], 10)["offset"], got["next_offset"])
        with open(os.path.join(self.root, "blob.bin"), "wb") as f:
            f.write(b"\x00\x01")
        self.refused("binary_file", self.ws.read, "blob.bin")
        with open(os.path.join(self.root, "latin.txt"), "wb") as f:
            f.write(b"\xff\xfe\xfa")
        self.refused("not_utf8_text", self.ws.read, "latin.txt")

    # -- what must never work ---------------------------------------------------------------------------
    def test_path_tricks_are_refused(self):
        for bad in ("../outside/secret.txt", "/etc/passwd", "a/../../x", "a//b", "./a", "a/./b", "a\\b", "a\x00b", "x" * 500, ""):
            with self.assertRaises(WorkspaceError, msg=repr(bad)):
                self.ws.write(bad, "x")
            with self.assertRaises(WorkspaceError, msg=repr(bad)):
                self.ws.read(bad)
        self.assertEqual(os.listdir(self.outside), ["secret.txt"])
        self.secret_unchanged()

    def test_credential_names_git_internals_and_our_own_names_are_refused(self):
        for name in (".env", "config/.env.local", "id_rsa", "keys/server.pem", ".npmrc", "x/credentials.json", ".git/config",
                     ".git/hooks/pre-commit", ".stynpilot-trash/x", ".stynpilot-tmp-abc", "a/.git/b"):
            self.assertRaises(WorkspaceError, self.ws.write, name, "x")
            self.assertRaises(WorkspaceError, self.ws.read, name)
            self.assertRaises(WorkspaceError, self.ws.trash, name)
        os.mkdir(os.path.join(self.root, ".git"))
        with open(os.path.join(self.root, ".env"), "w") as f:
            f.write("SECRET=1")
        listing = self.ws.list("")
        self.assertEqual(listing["entries"], [])
        self.assertEqual(listing["protected_names_hidden"], 1)

    def test_links_never_lead_outside(self):
        os.symlink(os.path.join(self.outside, "secret.txt"), os.path.join(self.root, "link.txt"))
        os.symlink(self.outside, os.path.join(self.root, "linkdir"))
        self.refused("not_a_plain_file", self.ws.read, "link.txt")
        self.refused("not_a_plain_file", self.ws.write, "link.txt", "pwn", overwrite=True)
        self.refused("not_a_plain_file", self.ws.edit, "link.txt", "do", "x")
        self.refused("not_a_plain_file", self.ws.trash, "link.txt")
        self.refused("not_a_plain_file", self.ws.move, "link.txt", "moved.txt")
        for fn, args in ((self.ws.read, ("linkdir/secret.txt",)), (self.ws.write, ("linkdir/new.txt", "x")),
                         (self.ws.list, ("linkdir",)), (self.ws.move, ("a.txt", "linkdir/a.txt"))):
            with self.assertRaises(WorkspaceError):
                fn(*args)
        self.assertEqual(os.listdir(self.outside), ["secret.txt"])
        self.secret_unchanged()

    def test_hard_linked_files_are_refused(self):
        os.link(os.path.join(self.outside, "secret.txt"), os.path.join(self.root, "hard.txt"))
        self.refused("not_a_plain_file", self.ws.read, "hard.txt")
        self.refused("not_a_plain_file", self.ws.write, "hard.txt", "pwn", overwrite=True)
        self.refused("not_a_plain_file", self.ws.edit, "hard.txt", "do", "x")
        self.refused("not_a_plain_file", self.ws.trash, "hard.txt")
        self.secret_unchanged()

    def test_a_folder_swapped_for_a_link_during_the_work_cannot_redirect_a_write(self):
        os.mkdir(os.path.join(self.root, "d"))
        stop = threading.Event()

        def swap():
            flip = True
            while not stop.is_set():
                path, aside = os.path.join(self.root, "d"), os.path.join(self.root, "d.aside")
                try:
                    if flip:
                        os.rename(path, aside)
                        os.symlink(self.outside, path)
                    else:
                        os.unlink(path)
                        os.rename(aside, path)
                    flip = not flip
                except OSError:
                    pass
        thread = threading.Thread(target=swap, daemon=True)
        thread.start()
        try:
            for i in range(400):
                try:
                    self.ws.write("d/f%d.txt" % i, "x")
                except WorkspaceError:
                    pass
        finally:
            stop.set()
            thread.join()
        self.assertEqual(os.listdir(self.outside), ["secret.txt"])

    def test_moving_a_folder_into_itself_or_over_a_folder_is_refused(self):
        os.makedirs(os.path.join(self.root, "a", "b"))
        os.makedirs(os.path.join(self.root, "z"))
        self.refused("path_invalid", self.ws.move, "a", "a/b/c")
        self.refused("destination_cannot_be_replaced", self.ws.move, "a", "z", overwrite=True)
        self.ws.write("f.txt", "x")
        self.refused("destination_cannot_be_replaced", self.ws.move, "f.txt", "z", overwrite=True)

    def test_a_root_that_is_not_canonical_is_refused(self):
        link = os.path.join(os.path.dirname(self.root), "rootlink")
        os.symlink(self.root, link)
        self.assertRaises(WorkspaceError, Workspace, link)
        self.assertRaises(WorkspaceError, Workspace, "relative/path")


if __name__ == "__main__":
    unittest.main()
