"""Dev21: the in-process .deb writer/reader. The reader is a security boundary: it decides whether a rollback copy is the package
we expect, and must refuse every unsafe archive without unpacking anything onto the disk."""
import io
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from stynpilot import debfile
from stynpilot.debfile import DebError, ar, build_deb_bytes, read_deb, read_deb_file, tar_xz

CONTROL = [("./", 0o755, None), ("./control", 0o644, b"Package: x\nVersion: 1\nArchitecture: all\nMaintainer: a <a@b>\nDescription: t\n")]
DATA = [("./", 0o755, None), ("./usr/", 0o755, None), ("./usr/bin/", 0o755, None), ("./usr/bin/tool", 0o755, b"#!/bin/sh\n"),
        ("./usr/share/", 0o755, None), ("./usr/share/odd", 0o644, b"odd length!")]


def raw_tar(members, fmt=tarfile.GNU_FORMAT):
    """A tar with arbitrary (possibly hostile) headers."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=fmt) as t:
        for info, data in members:
            t.addfile(info, io.BytesIO(data) if data is not None else None)
    return out.getvalue()


def info(name, kind=tarfile.REGTYPE, mode=0o644, size=0, uid=0, gid=0, link=""):
    i = tarfile.TarInfo(name)
    i.type, i.mode, i.size, i.uid, i.gid, i.linkname = kind, mode, size, uid, gid, link
    return i


def deb_with_data(members, *, control=None, compress=True, fmt=tarfile.GNU_FORMAT, raw=None):
    data = raw if raw is not None else raw_tar(members, fmt)
    return ar([("debian-binary", b"2.0\n"), ("control.tar.xz", tar_xz(control or CONTROL, 0)),
               ("data.tar.xz" if compress else "data.tar", lzma.compress(data, format=lzma.FORMAT_XZ) if compress else data)], 0)


class Roundtrip(unittest.TestCase):
    def test_what_is_written_reads_back_exactly_and_deterministically(self):
        one, two = build_deb_bytes(CONTROL, DATA, 1763769600), build_deb_bytes(CONTROL, DATA, 1763769600)
        self.assertEqual(one, two)
        got = read_deb(one)
        self.assertEqual(got["files"]["usr/bin/tool"], (0o755, b"#!/bin/sh\n"))
        self.assertEqual(got["files"]["usr/share/odd"][1], b"odd length!")
        self.assertEqual(set(got["dirs"]), {"", "usr", "usr/bin", "usr/share"})
        self.assertEqual(debfile.control_fields(got["control"]["control"][1].decode())["Package"], "x")

    def test_real_dpkg_deb_reads_the_writers_output(self):
        if not shutil.which("dpkg-deb"):
            self.skipTest("dpkg-deb not installed")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "x.deb").write_bytes(build_deb_bytes(CONTROL, DATA, 0))
            listing = subprocess.run(["dpkg-deb", "-c", d + "/x.deb"], capture_output=True, text=True, check=True).stdout
            self.assertIn("-rwxr-xr-x root/root", listing)
            self.assertEqual(subprocess.run(["dpkg-deb", "-f", d + "/x.deb", "Package"], capture_output=True, text=True).stdout.strip(), "x")

    def test_a_file_is_read_without_following_links_and_must_be_regular(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "x.deb").write_bytes(build_deb_bytes(CONTROL, DATA, 0))
            os.symlink(d + "/x.deb", d + "/link.deb")
            self.assertIn("usr/bin/tool", read_deb_file(d + "/x.deb")["files"])
            with self.assertRaises(OSError):
                read_deb_file(d + "/link.deb")
            os.mkfifo(d + "/fifo.deb")
            with self.assertRaises(DebError):
                read_deb_file(d + "/fifo.deb")


class Refusals(unittest.TestCase):
    def refused(self, blob, code):
        with self.assertRaises(DebError) as e:
            read_deb(blob)
        self.assertEqual(e.exception.code, code)

    def test_unsafe_paths(self):
        for name in ("../etc/passwd", "./../x", "/etc/passwd", "./usr/../../x", "./usr//x", "./usr/./x", "usr\\x", "./" + "a" * 1100):
            self.refused(deb_with_data([(info("./", tarfile.DIRTYPE, 0o755), None), (info(name, size=1), b"x")]), "unsafe_path")

    def test_duplicates_links_and_special_files(self):
        root = (info("./", tarfile.DIRTYPE, 0o755), None)
        self.refused(deb_with_data([root, (info("./a", size=1), b"x"), (info("./a", size=1), b"y")]), "duplicate_entry")
        self.refused(deb_with_data([root, (info("./a/", tarfile.DIRTYPE, 0o755), None), (info("./a", tarfile.DIRTYPE, 0o755), None)]),
                     "duplicate_entry")
        self.refused(deb_with_data([root, (info("./l", tarfile.SYMTYPE, 0o777, link="/etc/shadow"), None)]), "link_in_package")
        self.refused(deb_with_data([root, (info("./h", tarfile.LNKTYPE, link="./x"), None)]), "link_in_package")
        for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.CONTTYPE):
            self.refused(deb_with_data([root, (info("./s", kind), None)]), "special_file_in_package")

    def test_dangerous_permissions_and_owners(self):
        root = (info("./", tarfile.DIRTYPE, 0o755), None)
        for mode in (0o4755, 0o2755, 0o1755, 0o666, 0o646, 0o664):
            self.refused(deb_with_data([root, (info("./f", mode=mode, size=1), b"x")]), "dangerous_permissions")
        self.refused(deb_with_data([root, (info("./d/", tarfile.DIRTYPE, 0o777), None)]), "dangerous_permissions")
        self.refused(deb_with_data([root, (info("./f", size=1, uid=1000), b"x")]), "entry_not_owned_by_root")
        self.refused(deb_with_data([root, (info("./f", size=1, gid=1000), b"x")]), "entry_not_owned_by_root")

    def test_files_must_sit_in_listed_folders(self):
        self.refused(deb_with_data([(info("./", tarfile.DIRTYPE, 0o755), None), (info("./usr/f", size=1), b"x")]),
                     "entry_without_parent_folder")

    def test_size_and_count_limits_hold_while_decompressing(self):
        bomb = deb_with_data([(info("./", tarfile.DIRTYPE, 0o755), None), (info("./zeros", size=4 << 20), b"\0" * (4 << 20))])
        self.assertLess(len(bomb), 64 * 1024)                                         # tiny on disk...
        real = debfile.MAX_MEMBER_UNPACKED
        debfile.MAX_MEMBER_UNPACKED = 1 << 20                                         # ...much bigger unpacked
        self.addCleanup(setattr, debfile, "MAX_MEMBER_UNPACKED", real)
        self.refused(bomb, "member_too_large_or_trailing_data")
        debfile.MAX_MEMBER_UNPACKED = real
        real_entries = debfile.MAX_ENTRIES
        debfile.MAX_ENTRIES = 3
        self.addCleanup(setattr, debfile, "MAX_ENTRIES", real_entries)
        self.refused(build_deb_bytes(CONTROL, DATA, 0), "too_many_entries")
        debfile.MAX_ENTRIES = real_entries
        self.refused(b"!<arch>\n" + b"x" * 10, "damaged_deb_archive")
        real_deb = debfile.MAX_DEB
        debfile.MAX_DEB = 100
        self.addCleanup(setattr, debfile, "MAX_DEB", real_deb)
        self.refused(build_deb_bytes(CONTROL, DATA, 0), "deb_too_large")

    def test_archive_structure(self):
        good = build_deb_bytes(CONTROL, DATA, 0)
        self.refused(b"not an archive", "not_a_deb_archive")
        self.refused(good[:-5], "damaged_deb_archive")
        members = debfile._members(good)
        self.refused(ar(members + [("extra", b"x")], 0), "unexpected_deb_member")
        self.refused(ar([("debian-binary", b"3.0\n")] + members[1:], 0), "unexpected_deb_member")
        self.refused(ar([members[0], members[2], members[1]], 0), "unexpected_deb_member")
        self.refused(ar(members[:2] + [("data.tar.gz", b"\x1f\x8b")], 0), "unexpected_deb_member")
        self.refused(ar(members[:2] + [("data.tar.xz", members[2][1] + b"trailing")], 0), "member_too_large_or_trailing_data")
        self.refused(ar(members[:2] + [("data.tar.xz", b"not xz")], 0), "damaged_compression")
        self.refused(ar(members[:2] + [("data.tar.xz", members[2][1][:-20])], 0), "damaged_compression")       # truncated
        bad_control = tar_xz([("./", 0o755, None), ("./sub/", 0o755, None)], 0)
        self.refused(ar([members[0], ("control.tar.xz", bad_control), members[2]], 0), "unexpected_control_folder")



class BoundedReading(unittest.TestCase):
    """Dev21 review BLOCKER: nothing may expand beyond the limits while reading, sparse or not."""
    root = (info("./", tarfile.DIRTYPE, 0o755), None)

    def refused(self, blob, code):
        with self.assertRaises(DebError) as e:
            read_deb(blob)
        self.assertEqual(e.exception.code, code)

    def limit(self, name, value):
        real = getattr(debfile, name)
        setattr(debfile, name, value)
        self.addCleanup(setattr, debfile, name, real)

    def test_sparse_entries_and_unknown_pax_metadata_are_refused(self):
        sparse = info("./s", size=10)
        sparse.pax_headers = {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "./s",
                              "GNU.sparse.realsize": str(1 << 40)}
        self.refused(deb_with_data([self.root, (sparse, b"0\n" + b"\0" * 8)], fmt=tarfile.PAX_FORMAT), "unsupported_tar_metadata")
        odd = info("./o", size=1)
        odd.pax_headers = {"SCHILY.xattr.security.capability": "x"}
        self.refused(deb_with_data([self.root, (odd, b"x")], fmt=tarfile.PAX_FORMAT), "unsupported_tar_metadata")
        self.refused(deb_with_data([self.root, (info("./g", tarfile.GNUTYPE_SPARSE), None)]), "special_file_in_package")
        plain = info("./p", size=1)                                  # plain PAX keys from long values are fine
        plain.pax_headers = {"mtime": "1.5"}
        self.assertIn("p", read_deb(deb_with_data([self.root, (plain, b"x")], fmt=tarfile.PAX_FORMAT))["files"])

    def test_file_and_total_sizes_are_checked_before_reading(self):
        two = [self.root, (info("./a", size=600), b"a" * 600), (info("./b", size=600), b"b" * 600)]
        self.limit("MAX_FILE", 500)
        self.refused(deb_with_data(two), "file_too_large")
        self.limit("MAX_FILE", 1000)
        self.limit("MAX_CONTENT", 1000)                               # each file fits, the two together do not
        self.refused(deb_with_data(two), "file_too_large")

    def test_the_xz_decoder_memory_is_limited(self):
        self.limit("LZMA_MEMLIMIT", 4096)
        self.refused(build_deb_bytes(CONTROL, DATA, 0), "damaged_compression")

    def test_the_tar_must_end_with_zero_blocks_and_nothing_else(self):
        good = raw_tar([self.root, (info("./f", size=1), b"x")])
        body = good.rstrip(b"\0")
        body += b"\0" * (-len(body) % 512)
        self.refused(deb_with_data(None, raw=body), "damaged_tar_end")                          # end marker missing
        self.refused(deb_with_data(None, raw=good + b"junk" + b"\0" * 508), "damaged_tar_end")  # data after the end
        self.assertIn("f", read_deb(deb_with_data(None, raw=good))["files"])

    def test_ar_padding_must_be_a_newline(self):
        blob = ar([("debian-binary", b"2.0\n"), ("odd", b"abc")], 0)
        self.assertEqual(blob[-1:], b"\n")
        self.assertEqual(len(debfile._members(blob)), 2)
        with self.assertRaises(DebError) as e:
            debfile._members(blob[:-1] + b"X")
        self.assertEqual(e.exception.code, "damaged_deb_archive")

if __name__ == "__main__":
    unittest.main()
