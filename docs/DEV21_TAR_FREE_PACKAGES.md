# Dev21: packages written and checked in-process (restores the sandbox test coverage)

Cause (live probe on the Ryzen, 2026-11-25): in the sandbox systemd answers openat2 with ENOSYS (RestrictSUIDSGID=yes cannot inspect
openat2's mode). Ubuntu 26.04's GNU tar 1.35 does not fall back for names inside folders, so `dpkg-deb --build` and `dpkg-deb -x`
fail there; `dpkg-deb -f`, `--ctrl-tarfile` and `-c` work. RestrictSUIDSGID stays on.

- `stynpilot/debfile.py`: the reproducible writer (moved from tools/build_deb.py; release packages are byte-identical to Dev20's
  writer) and a strict in-memory reader: exactly debian-binary + control.tar[.xz] + data.tar[.xz]; size limits checked while
  decompressing (64 MiB package, 256 MiB per member, 20000 entries, 1024-char names); refuses absolute, '..' and non-normalized
  paths, duplicates, symlinks, hard links, devices, fifos and other special files, setuid/setgid/sticky and group/world-writable
  modes, non-root owners, entries without a listed parent folder, truncated or trailing data, extra or reordered members.
- Rollback copy: built with the writer, written with O_NOFOLLOW, then read back from disk and proven in memory (exactly the
  recorded file set, every md5 equal, Package and Version equal). Nothing is unpacked onto the host.
- Tests: fixtures build packages with the writer; the dpkg probe checks only the dpkg-deb reads the code uses; package tests find the
  pinned wheels in the release work area; new security tests (tests/test_debfile.py) and rollback-mismatch tests.
