"""The ``stynpilot`` command: one entry point for the menu launchers, systemd units and the owner."""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__

DEFAULT_OWNER_CONFIG = "~/.config/stynpilot/owner.json"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="stynpilot")
    sub = parser.add_subparsers(dest="command", required=True)
    svc = sub.add_parser("service")
    svc.add_argument("role", choices=("owner", "installer", "provision", "passkeys"))
    svc.add_argument("--config", required=True)
    svc.add_argument("--action", choices=("list", "activate", "confirm-restored"), default="list")
    svc.add_argument("--kid", default="")
    sub.add_parser("setup")
    sub.add_parser("auth-check", help="read-only: why might a password step fail from this login?")
    sub.add_parser("setup-system", help="finish setup's one password step in this terminal (works over SSH)")
    rbak = sub.add_parser("root-backup", help="back up the installer's rollback records (asks for your password)")
    rbak.add_argument("--out", required=True)
    rres = sub.add_parser("root-restore", help="restore the installer's rollback records (asks for your password)")
    rres.add_argument("--archive", required=True)
    for name, text in (("start", "start StyNpilot (asks for your password once)"), ("stop", "stop StyNpilot")):
        one = sub.add_parser(name, help=text)
        one.add_argument("--config", default=DEFAULT_OWNER_CONFIG)
        one.add_argument("--show", action="store_true", help="show the result in a window afterwards")
    doc = sub.add_parser("doctor")
    doc.add_argument("--config", default=DEFAULT_OWNER_CONFIG)
    doc.add_argument("--html", action="store_true", help="show the report in a window (browser) instead of the terminal")
    bak = sub.add_parser("backup")
    bak.add_argument("--config", default=DEFAULT_OWNER_CONFIG)
    bak.add_argument("--out")
    res = sub.add_parser("restore")
    res.add_argument("--config", default=DEFAULT_OWNER_CONFIG)
    res.add_argument("--archive", required=True)
    sub.add_parser("version")
    args = parser.parse_args(argv)
    from .service import ConfigError, OwnerConfig
    try:
        if args.command == "version":
            print(__version__)
        elif args.command == "service":
            from . import service
            return service.main([args.role, "--config", args.config, "--action", args.action, "--kid", args.kid])
        elif args.command == "setup":
            from . import setup_wizard
            setup_wizard.serve()
        elif args.command == "auth-check":
            from . import doctor
            print(doctor.render(doctor.check_authorization()))
            return 0
        elif args.command == "setup-system":
            from . import setup_wizard
            return setup_wizard.finish_system(Path.home(), os.getuid())
        elif args.command in ("root-backup", "root-restore"):
            import subprocess
            from .setup_wizard import ROOT_HELPER
            job = ["root-backup", "--out", args.out] if args.command == "root-backup" else ["root-restore", "--archive", args.archive]
            return subprocess.run(["pkexec", ROOT_HELPER] + job).returncode
        elif args.command in ("start", "stop"):
            from . import lifecycle
            return lifecycle.run(args.command, Path(args.config).expanduser(), show=args.show)
        elif args.command == "doctor":
            from . import doctor
            from .broker.service import BrokerClient
            from .service_status import listeners
            path = Path(args.config).expanduser()
            config = OwnerConfig.from_file(path) if path.exists() else None
            checks = doctor.run_checks(owner_config=config, listeners=listeners if config else None,
                                       client=BrokerClient(config.broker_socket) if config else None)
            if config is None:
                checks.insert(2, ("owner config", doctor.WARN, "not set up yet: open StyNpilot Setup from the menu"))
            if args.html:
                doctor.show_html(checks)
            else:
                print(doctor.render(checks))
            return doctor.exit_code(checks)
        elif args.command in ("backup", "restore"):
            from . import backup
            config = OwnerConfig.from_file(Path(args.config).expanduser())
            if args.command == "backup":
                out = args.out or str(config.state_dir.parent / ("stynpilot-backup-%s.tar" % time.strftime("%Y%m%d-%H%M%S")))
                manifest = backup.make_backup(config.state_dir, out)
                print("owner-state backup written to", out, "(%d files, integrity hashes recorded). This covers YOUR request "
                      "queue and revoked connectors only; use root-backup for software-rollback records." % len(manifest["files"]))
            else:
                backup.restore_backup(args.archive, config.state_dir)
                print("state restored from", args.archive)
    except Exception as error:
        code = getattr(error, "code", None) or str(error) or type(error).__name__
        print("stynpilot:", type(error).__name__ + ":", code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":                                   # pragma: no cover
    raise SystemExit(main())
