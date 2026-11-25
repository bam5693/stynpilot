"""Debian package (.deb) writing and reading inside this process: no tar, xz or dpkg-deb child.

Why: inside the release sandbox systemd answers openat2 with ENOSYS (RestrictSUIDSGID=yes cannot inspect openat2's mode), and
Ubuntu 26.04's GNU tar does not fall back for paths inside folders, so `dpkg-deb --build` and `dpkg-deb -x` fail there. Doing it in
Python needs no relaxation of the sandbox, gives byte-for-byte reproducible output, and means a package we must CHECK is never
unpacked onto the disk by an outside tool.

Writer: ``build_deb_bytes(control_entries, data_entries, epoch)``; entries are (name, mode, bytes-or-None-for-a-folder) and are
written exactly as given (the reader is what enforces safety, so tests can also build deliberately bad packages).

Reader: ``read_deb(blob)`` checks the archive strictly and returns its contents in memory. It refuses: anything but the three
expected members in order, compression other than xz or none, oversize members or contents (checked WHILE decompressing),
too many entries, absolute or '..' or non-normalized paths, duplicates, links, devices, fifos and every other special file,
setuid/setgid/sticky or group/world-writable modes, and entries not owned by root.
"""
from __future__ import annotations

import io
import lzma
import posixpath
import tarfile

MAX_DEB = 64 * 1024 * 1024               # the whole package as stored
MAX_MEMBER_UNPACKED = 256 * 1024 * 1024  # one tar after decompression
MAX_ENTRIES = 20000
MAX_NAME = 1024
MAX_FILE = 128 * 1024 * 1024             # one file's content
MAX_CONTENT = 192 * 1024 * 1024          # all files' content in one tar, counted from the headers BEFORE anything is read
LZMA_MEMLIMIT = 128 * 1024 * 1024        # the xz decoder's own working memory
# The only PAX keys a plain archive may carry (our writer emits none; dpkg-deb may emit path/linkpath/size/mtime for long values).
_PAX_OK = {"path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"}


class DebError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# -- writing -----------------------------------------------------------------------------------------------
def tar_xz(entries, epoch):
    """A deterministic GNU tar, xz-compressed. Every entry root-owned with the fixed epoch, in the order given."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.mtime, info.mode = epoch, mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            if data is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)


def ar(members, epoch):
    out = [b"!<arch>\n"]
    for name, data in members:
        out.append(("%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, epoch, 0, 0, "100644", len(data))).encode("ascii"))
        out.append(data)
        if len(data) % 2:
            out.append(b"\n")
    return b"".join(out)


def build_deb_bytes(control_entries, data_entries, epoch):
    return ar([("debian-binary", b"2.0\n"), ("control.tar.xz", tar_xz(control_entries, epoch)),
               ("data.tar.xz", tar_xz(data_entries, epoch))], epoch)


def tree_entries(root, *, skip=None, mode_of=None):
    """(name, mode, data) for every folder and regular file under ``root``, parents first, in a fixed order; links and special
    files are refused. ``mode_of(path)`` picks the mode (default: the file's own permission bits)."""
    from pathlib import Path
    root = Path(root)
    found = [("./", 0o755, None)]
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).parts):
        rel = path.relative_to(root)
        if skip and rel.parts[0] == skip:
            continue
        if path.is_symlink():
            raise DebError("link_in_package_tree")
        if path.is_dir():
            found.append(("./%s/" % rel.as_posix(), mode_of(path) if mode_of else 0o755, None))
        elif path.is_file():
            found.append(("./" + rel.as_posix(), mode_of(path) if mode_of else path.stat().st_mode & 0o7777, path.read_bytes()))
        else:
            raise DebError("special_file_in_package_tree")
    return found


def write_tree(pkg, target, epoch, *, mode_of=None):
    """Build ``pkg`` (with its DEBIAN/ control folder) into ``target``."""
    from pathlib import Path
    pkg = Path(pkg)
    blob = build_deb_bytes(tree_entries(pkg / "DEBIAN", mode_of=mode_of), tree_entries(pkg, skip="DEBIAN", mode_of=mode_of), epoch)
    Path(target).write_bytes(blob)
    return blob


# -- reading -----------------------------------------------------------------------------------------------
def _members(blob):
    if not blob.startswith(b"!<arch>\n"):
        raise DebError("not_a_deb_archive")
    at, found = 8, []
    while at < len(blob):
        head = blob[at:at + 60]
        if len(head) != 60 or head[58:60] != b"`\n":
            raise DebError("damaged_deb_archive")
        name = head[:16].decode("ascii", "replace").rstrip(" ").rstrip("/")
        try:
            size = int(head[48:58].decode("ascii").strip())
        except ValueError:
            raise DebError("damaged_deb_archive") from None
        start = at + 60
        if size < 0 or start + size > len(blob):
            raise DebError("damaged_deb_archive")
        found.append((name, blob[start:start + size]))
        if size % 2:
            if blob[start + size:start + size + 1] != b"\n":           # ar pads odd members with exactly one newline
                raise DebError("damaged_deb_archive")
        at = start + size + (size % 2)
        if len(found) > 3:
            raise DebError("unexpected_deb_member")
    return found


def _unpack(name, data):
    if name.endswith(".tar.xz"):
        if not data.startswith(b"\xfd7zXZ\x00"):
            raise DebError("damaged_compression")
        engine = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=LZMA_MEMLIMIT)
        try:
            out = engine.decompress(data, max_length=MAX_MEMBER_UNPACKED + 1)
        except lzma.LZMAError:
            raise DebError("damaged_compression") from None
        if not engine.eof and len(out) <= MAX_MEMBER_UNPACKED:
            raise DebError("damaged_compression")                  # truncated stream
        if len(out) > MAX_MEMBER_UNPACKED or engine.unused_data:
            raise DebError("member_too_large_or_trailing_data")
        return out
    if name.endswith(".tar"):
        if len(data) > MAX_MEMBER_UNPACKED:
            raise DebError("member_too_large_or_trailing_data")
        return data
    raise DebError("unsupported_compression")


def _safe_name(raw):
    if not raw or len(raw) > MAX_NAME or "\x00" in raw or "\\" in raw:
        raise DebError("unsafe_path")
    name = raw[2:] if raw.startswith("./") else raw
    if raw in ("./", "."):
        return ""
    name = name.rstrip("/")
    if not name or name.startswith("/") or posixpath.normpath(name) != name or any(p in ("", ".", "..") for p in name.split("/")):
        raise DebError("unsafe_path")
    return name


def _read_tar(raw):
    """{name: (mode, bytes)} for files and {name: mode} for folders, every rule above enforced."""
    files, dirs, seen = {}, {}, set()
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError:
        raise DebError("damaged_tar") from None
    with archive:
        count, total = 0, 0
        while True:
            try:
                info = archive.next()
            except tarfile.TarError:
                raise DebError("damaged_tar") from None
            if info is None:
                break
            count += 1
            if count > MAX_ENTRIES:
                raise DebError("too_many_entries")
            name = _safe_name(info.name)
            if name in seen:
                raise DebError("duplicate_entry")
            seen.add(name)
            if info.issym() or info.islnk():
                raise DebError("link_in_package")
            if not info.isdir() and not (info.isreg() and info.type in (tarfile.REGTYPE, tarfile.AREGTYPE)):
                raise DebError("special_file_in_package")
            if info.uid != 0 or info.gid != 0:
                raise DebError("entry_not_owned_by_root")
            if info.mode & 0o7022:
                raise DebError("dangerous_permissions")
            # Sparse files (old GNU sparse or PAX GNU.sparse.*) can look like plain files yet expand when read: refuse them, and any
            # PAX metadata beyond the plain keys.
            if info.sparse is not None or set(info.pax_headers) - _PAX_OK:
                raise DebError("unsupported_tar_metadata")
            if info.isdir():
                if info.size:
                    raise DebError("unsupported_tar_metadata")
                dirs[name] = info.mode & 0o777
            else:
                if info.size < 0 or info.size > MAX_FILE or total + info.size > MAX_CONTENT:
                    raise DebError("file_too_large")
                total += info.size
                handle = archive.extractfile(info)
                data = handle.read(info.size + 1) if handle else b""
                if len(data) != info.size:
                    raise DebError("damaged_tar")
                files[name] = (info.mode & 0o777, data)
        # A complete archive ends with zero blocks and nothing else (tarfile alone accepts a missing end or trailing bytes).
        rest = raw[archive.offset:]
        if len(rest) < 1024 or rest.count(0) != len(rest):
            raise DebError("damaged_tar_end")
    for name in list(files) + list(dirs):              # every parent folder must be listed (no implied folders)
        parent = posixpath.dirname(name)
        if parent and parent not in dirs:
            raise DebError("entry_without_parent_folder")
    return files, dirs


def read_deb(blob):
    """Strictly checked contents: {"control": {name: (mode, bytes)}, "files": {...}, "dirs": {name: mode}}."""
    if type(blob) is not bytes or len(blob) > MAX_DEB:
        raise DebError("deb_too_large")
    members = _members(blob)
    names = [n for n, _ in members]
    if len(members) != 3 or names[0] != "debian-binary" or members[0][1] != b"2.0\n" \
            or names[1] not in ("control.tar.xz", "control.tar") or names[2] not in ("data.tar.xz", "data.tar"):
        raise DebError("unexpected_deb_member")
    control, control_dirs = _read_tar(_unpack(names[1], members[1][1]))
    if control_dirs.keys() - {""}:
        raise DebError("unexpected_control_folder")
    files, dirs = _read_tar(_unpack(names[2], members[2][1]))
    return {"control": control, "files": files, "dirs": dirs}


def read_deb_file(path):
    """read_deb of a file opened without following links, size-capped while reading."""
    import os
    import stat
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise DebError("not_a_regular_file")
        chunks, total = [], 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            total += len(block)
            if total > MAX_DEB:
                raise DebError("deb_too_large")
            chunks.append(block)
    finally:
        os.close(fd)
    return read_deb(b"".join(chunks))


def control_fields(text):
    """Simple 'Key: value' fields of a control file (continuation lines are kept with their key)."""
    fields, key = {}, None
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line.strip()
        elif ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            fields[key] = value.strip()
    return fields
