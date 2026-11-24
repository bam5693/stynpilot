"""Safe file operations inside ONE authorized project folder, run by the owner's own service (never root, never the sandbox).

Every path is a list of plain names below the folder, walked with directory file descriptors and O_NOFOLLOW, so a link
planted inside the project (even one swapped in while a command is running) can never lead an operation outside it.
Refused everywhere: absolute paths, ``..``, credential-named files (safefs.NAME_DENY), the ``.git`` internals, StyNpilot's
own bookkeeping names, links, hard-linked files (their other name may live outside) and anything that is not a plain
text file. Writes are atomic (temp file + rename) and keep the group-class permission bits the sandbox account's ACL
relies on, so the sandbox can still work on what an assistant wrote. Deleting moves to ``.stynpilot-trash`` (reversible).
Content read back is redacted before it is returned, and labelled untrusted.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import time

from . import redact, safefs

MAX_FILE = 1024 * 1024
MAX_LIST = 500
MAX_PART, MAX_PATH = 120, 400
RESERVED = (".git", ".stynpilot-trash")
TEMP_PREFIX = ".stynpilot-tmp-"
_FLAGS_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class WorkspaceError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def parts_of(rel, *, allow_reserved=()):
    """The list of plain names for a relative path, or WorkspaceError."""
    if type(rel) is not str or len(rel) > MAX_PATH or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in rel):
        raise WorkspaceError("path_invalid")
    if rel in ("", "."):
        return []
    if rel.startswith("/"):
        raise WorkspaceError("path_must_be_relative")
    parts = rel.rstrip("/").split("/")
    for part in parts:
        if part in ("", ".", "..") or len(part) > MAX_PART:
            raise WorkspaceError("path_invalid")
        if part.startswith(TEMP_PREFIX) or (part in RESERVED and part not in allow_reserved):
            raise WorkspaceError("path_is_reserved")
        try:
            safefs.Policy.name_ok(part)
        except safefs.FileDenied:
            raise WorkspaceError("protected_file_name") from None
    return parts


class Workspace:
    def __init__(self, root):
        if type(root) is not str or not os.path.isabs(root) or os.path.realpath(root) != root:
            raise WorkspaceError("workspace_path_invalid")
        self.root = root

    # -- walking --------------------------------------------------------------------------------------
    def _root_fd(self):
        try:
            return os.open(self.root, _FLAGS_DIR)
        except OSError:
            raise WorkspaceError("workspace_unavailable") from None

    def _dir(self, parts, *, create=False):
        """An fd for the folder holding ``parts`` (every step opened with O_NOFOLLOW from the previous fd)."""
        fd = self._root_fd()
        try:
            for part in parts:
                try:
                    nxt = os.open(part, _FLAGS_DIR, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise WorkspaceError("not_found") from None
                    try:
                        os.mkdir(part, 0o777, dir_fd=fd)
                        nxt = os.open(part, _FLAGS_DIR, dir_fd=fd)
                    except OSError:
                        raise WorkspaceError("could_not_create_folder") from None
                except OSError:
                    raise WorkspaceError("not_a_plain_folder") from None        # a link, a file or no permission
                os.close(fd)
                fd = nxt
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _file_bytes(self, parent, name):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            raise WorkspaceError("not_found") from None
        except OSError:
            raise WorkspaceError("not_a_plain_file") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise WorkspaceError("not_a_plain_file")
            if info.st_size > MAX_FILE:
                raise WorkspaceError("file_too_large")
            data = os.read(fd, MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise WorkspaceError("file_too_large")
            return data, info
        except PermissionError:
            raise WorkspaceError("file_not_accessible") from None
        finally:
            os.close(fd)

    @staticmethod
    def _text(data):
        if b"\x00" in data:
            raise WorkspaceError("binary_file")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise WorkspaceError("not_utf8_text") from None

    # -- reading --------------------------------------------------------------------------------------
    def list(self, rel=""):
        parts = parts_of(rel)
        fd = self._dir(parts)
        try:
            entries, hidden = [], 0
            for name in sorted(os.listdir(fd)):
                if name in RESERVED or name.startswith(TEMP_PREFIX):
                    continue
                try:
                    safefs.Policy.name_ok(name)
                except safefs.FileDenied:
                    hidden += 1
                    continue
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    continue
                kind = ("dir" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode)
                        else "link" if stat.S_ISLNK(info.st_mode) else "other")
                entries.append({"name": name, "kind": kind, "size": info.st_size if kind == "file" else None})
                if len(entries) >= MAX_LIST:
                    return {"entries": entries, "truncated": True, "protected_names_hidden": hidden}
            return {"entries": entries, "truncated": False, "protected_names_hidden": hidden}
        finally:
            os.close(fd)

    def read(self, rel, offset=0, limit=32768):
        parts = parts_of(rel)
        if not parts or type(offset) is not int or type(limit) is not int or offset < 0 or not 0 < limit <= 65536:
            raise WorkspaceError("path_or_window_invalid")
        parent = self._dir(parts[:-1])
        try:
            data, _ = self._file_bytes(parent, parts[-1])
        finally:
            os.close(parent)
        clean, found = redact.redact(self._text(data))                 # the WHOLE text is cleaned before any slicing
        window = clean[offset:offset + limit]
        return {"text": window, "offset": offset, "next_offset": offset + len(window), "total": len(clean),
                "sha256": hashlib.sha256(data).hexdigest(), "redactions": found, "note": safefs.UNTRUSTED}

    # -- writing --------------------------------------------------------------------------------------
    def _put(self, parent, name, data, *, executable=False):
        temp = TEMP_PREFIX + secrets.token_hex(8)
        try:
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o777 if executable else 0o666, dir_fd=parent)    # mode as requested: the folder's default ACL decides the rest
        except OSError:
            raise WorkspaceError("could_not_write") from None
        try:
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                raise WorkspaceError("could_not_write") from None
            try:
                os.rename(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
            except OSError:
                raise WorkspaceError("could_not_write") from None
        except BaseException:
            try:
                os.unlink(temp, dir_fd=parent)
            except OSError:
                pass
            raise

    def _existing(self, parent, name):
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise WorkspaceError("not_a_plain_file") from None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise WorkspaceError("not_a_plain_file")
        return info

    @staticmethod
    def _content(content):
        if type(content) is not str:
            raise WorkspaceError("content_must_be_text")
        data = content.encode("utf-8")
        if b"\x00" in data:
            raise WorkspaceError("binary_content_refused")
        if len(data) > MAX_FILE:
            raise WorkspaceError("content_too_large")
        return data

    def write(self, rel, content, *, overwrite=False):
        parts = parts_of(rel)
        if not parts:
            raise WorkspaceError("path_invalid")
        data = self._content(content)
        parent = self._dir(parts[:-1], create=True)
        try:
            old = self._existing(parent, parts[-1])
            if old is not None and not overwrite:
                raise WorkspaceError("file_exists_set_overwrite")
            self._put(parent, parts[-1], data, executable=bool(old and old.st_mode & 0o111))
        finally:
            os.close(parent)
        return {"path": "/".join(parts), "bytes": len(data), "created": old is None}

    def edit(self, rel, old, new, *, replace_all=False):
        parts = parts_of(rel)
        if not parts or type(old) is not str or type(new) is not str or not old:
            raise WorkspaceError("edit_invalid")
        parent = self._dir(parts[:-1])
        try:
            data, info = self._file_bytes(parent, parts[-1])
            text = self._text(data)
            count = text.count(old)
            if count == 0:
                raise WorkspaceError("old_text_not_found")
            if count > 1 and not replace_all:
                raise WorkspaceError("old_text_not_unique")
            updated = self._content(text.replace(old, new) if replace_all else text.replace(old, new, 1))
            self._put(parent, parts[-1], updated, executable=bool(info.st_mode & 0o111))
        finally:
            os.close(parent)
        return {"path": "/".join(parts), "replacements": count if replace_all else 1, "bytes": len(updated)}

    def move(self, src, dst, *, overwrite=False):
        a, b = parts_of(src), parts_of(dst)
        if not a or not b or a == b or b[:len(a)] == a:
            raise WorkspaceError("path_invalid")
        pa = self._dir(a[:-1])
        try:
            pb = self._dir(b[:-1], create=True)
            try:
                try:
                    info = os.stat(a[-1], dir_fd=pa, follow_symlinks=False)
                except FileNotFoundError:
                    raise WorkspaceError("not_found") from None
                if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or \
                        (stat.S_ISREG(info.st_mode) and info.st_nlink > 1):
                    raise WorkspaceError("not_a_plain_file")
                try:
                    target = os.stat(b[-1], dir_fd=pb, follow_symlinks=False)
                except FileNotFoundError:
                    target = None
                except OSError:
                    raise WorkspaceError("not_a_plain_file") from None
                if target is not None:
                    if not overwrite:
                        raise WorkspaceError("destination_exists_set_overwrite")
                    if not stat.S_ISREG(target.st_mode) or target.st_nlink > 1 or stat.S_ISDIR(info.st_mode):
                        raise WorkspaceError("destination_cannot_be_replaced")
                try:
                    os.rename(a[-1], b[-1], src_dir_fd=pa, dst_dir_fd=pb)
                except OSError:
                    raise WorkspaceError("could_not_move") from None
            finally:
                os.close(pb)
        finally:
            os.close(pa)
        return {"from": "/".join(a), "to": "/".join(b)}

    def trash(self, rel):
        """Delete = move into ``.stynpilot-trash`` with a time stamp, so nothing is ever lost for good."""
        parts = parts_of(rel)
        if not parts:
            raise WorkspaceError("path_invalid")
        parent = self._dir(parts[:-1])
        try:
            try:
                info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                raise WorkspaceError("not_found") from None
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or \
                    (stat.S_ISREG(info.st_mode) and info.st_nlink > 1):
                raise WorkspaceError("not_a_plain_file")
            root = self._root_fd()
            try:
                try:
                    os.mkdir(".stynpilot-trash", 0o777, dir_fd=root)
                except FileExistsError:
                    pass
                bin_fd = os.open(".stynpilot-trash", _FLAGS_DIR, dir_fd=root)
            except OSError:
                os.close(root)
                raise WorkspaceError("could_not_use_the_trash") from None
            os.close(root)
            try:
                name = "%d-%s-%s" % (int(time.time()), secrets.token_hex(3), "_".join(parts)[:80])
                os.rename(parts[-1], name, src_dir_fd=parent, dst_dir_fd=bin_fd)
            except OSError:
                raise WorkspaceError("could_not_move") from None
            finally:
                os.close(bin_fd)
        finally:
            os.close(parent)
        return {"trashed": "/".join(parts), "kept_in": ".stynpilot-trash/" + name}
