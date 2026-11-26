import hashlib
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from stynpilot import dev_lab_source, dev_lab_worker
from stynpilot.dev_lab_policy import LabError

COMMIT = "a" * 40


class SourceArtifactTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.archive = self.root / "artifact.tar"
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)

    def pack(self, name="tests/test_example.py", kind=tarfile.REGTYPE, commit=COMMIT):
        with tarfile.open(self.archive, "w", pax_headers={"comment": commit}) as output:
            record = tarfile.TarInfo(name)
            record.type = kind
            record.mode = 0o777
            record.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
            content = b"test artifact"
            if kind == tarfile.REGTYPE:
                record.size = len(content)
            output.addfile(record, io.BytesIO(content) if record.size else None)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_stages_expected_bytes_without_inheriting_write_or_setid_permissions(self):
        path = dev_lab_source.stage(self.archive, self.scratch, COMMIT, self.pack())
        artifact = path / "tests/test_example.py"
        self.assertEqual(artifact.read_bytes(), b"test artifact")
        self.assertEqual(artifact.stat().st_mode & 0o7777, 0o555)

    def test_refuses_digest_before_creating_source_tree(self):
        self.pack()
        with self.assertRaisesRegex(LabError, "lab_source_digest_mismatch"):
            dev_lab_source.stage(self.archive, self.scratch, COMMIT, "b" * 64)
        self.assertFalse((self.scratch / "src").exists())

    def test_refuses_mismatched_commit_even_with_matching_digest(self):
        digest = self.pack(commit="b" * 40)
        with self.assertRaisesRegex(LabError, "lab_source_commit_mismatch"):
            dev_lab_source.stage(self.archive, self.scratch, COMMIT, digest)

    def test_refuses_absolute_traversing_and_link_entries(self):
        for index, (name, kind) in enumerate((("/absolute", tarfile.REGTYPE),
                                              ("tests/../../escape", tarfile.REGTYPE),
                                              ("link", tarfile.SYMTYPE),
                                              (".git/config", tarfile.REGTYPE))):
            with self.subTest(name=name):
                scratch = self.scratch / str(index)
                scratch.mkdir(mode=0o700)
                digest = self.pack(name, kind)
                with self.assertRaisesRegex(LabError, "lab_source_member_invalid"):
                    dev_lab_source.stage(self.archive, scratch, COMMIT, digest)

    def test_refuses_symlink_bundle_before_reading(self):
        self.pack()
        linked = self.root / "linked.tar"
        linked.symlink_to(self.archive)
        with self.assertRaises(OSError):
            dev_lab_source.stage(linked, self.scratch, COMMIT, "a" * 64)


class WorkerProcessTests(unittest.TestCase):
    def test_preserves_failure_and_output(self):
        state, code, data = dev_lab_worker._execute(
            [sys.executable, "-I", "-c", "print('fixture'); raise SystemExit(7)"], lambda: False)
        self.assertEqual((state, code, data), ("failed", 7, b"fixture\n"))

    def test_discards_overflow(self):
        with patch.object(dev_lab_worker, "OUTPUT_LIMIT", 256):
            result = dev_lab_worker._execute(
                [sys.executable, "-I", "-c", "import os; os.write(1, b'x' * 300)"], lambda: False)
        self.assertEqual(result, ("output_limit", None, b""))

    def test_deadline_applies_after_output_is_closed(self):
        with patch.object(dev_lab_worker, "TIMEOUT", 0.25):
            result = dev_lab_worker._execute(
                [sys.executable, "-I", "-c", "import os,time; os.close(1); os.close(2); time.sleep(30)"],
                lambda: False)
        self.assertEqual(result, ("timeout", None, b""))

    def test_unimplemented_scenario_stays_closed(self):
        with self.assertRaisesRegex(LabError, "lab_scenario_not_implemented"):
            dev_lab_worker.run("unused", "unused", COMMIT, "b" * 64, "guest_restore")
