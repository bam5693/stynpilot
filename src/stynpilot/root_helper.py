"""The ONLY program polkit lets run as root for StyNpilot: a fixed list of three jobs, nothing else.

  root-setup   --from FILE    copy the owner's proposed installer config to /etc/stynpilot (never replaces one)
  root-backup  --out FILE     back up the installer's ledgers and package snapshots to a file the caller owns
  root-restore --archive FILE restore them into the EMPTY installer state folder (the installer must be stopped)

It acts for exactly the person polkit authenticated (PKEXEC_UID) and never starts, stops or enables anything.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

from . import backup
from .service import ConfigError
from .setup_wizard import root_setup

INSTALLER_STATE = Path("/var/lib/stynpilot-installer")


def _caller(environ=os.environ, geteuid=os.geteuid):
    if geteuid() != 0:
        raise ConfigError("must_run_through_polkit_as_root")
    try:
        uid = int(environ["PKEXEC_UID"])
    except (KeyError, ValueError):
        raise ConfigError("not_started_by_polkit") from None
    if uid < 1000:
        raise ConfigError("caller_must_be_a_normal_user")
    return uid


def _folder_ok(path, uid):
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise ConfigError("folder_must_be_private_and_owned_by_the_caller")


def root_backup(out, *, state=INSTALLER_STATE, **kw):
    uid = _caller(**kw)
    out = Path(out)
    _folder_ok(out.parent, uid)
    return backup.make_backup(state, out, kind="root", chown_to=uid)


def root_restore(archive, *, state=INSTALLER_STATE, **kw):
    uid = _caller(**kw)
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise ConfigError("archive_must_be_a_private_file_owned_by_the_caller")
    finally:
        os.close(fd)
    return backup.restore_backup(archive, state, kind="root")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="stynpilot-root-helper")
    sub = parser.add_subparsers(dest="job", required=True)
    sub.add_parser("root-setup").add_argument("--from", dest="source", required=True)
    sub.add_parser("root-backup").add_argument("--out", required=True)
    sub.add_parser("root-restore").add_argument("--archive", required=True)
    args = parser.parse_args(argv)
    try:
        if args.job == "root-setup":
            print("wrote", root_setup(args.source))
        elif args.job == "root-backup":
            manifest = root_backup(args.out)
            print("backup written to", args.out, "(%d files)" % len(manifest["files"]))
        else:
            root_restore(args.archive)
            print("installer records restored; start the installer only after checking them")
    except Exception as error:
        print("stynpilot-root-helper: %s: %s" % (type(error).__name__, getattr(error, "code", None) or error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":                                   # pragma: no cover
    raise SystemExit(main())
