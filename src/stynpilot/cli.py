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
    svc.add_argument("role", choices=("owner", "installer", "provision"))
    svc.add_argument("--config", required=True)
    sub.add_parser("setup")
    root = sub.add_parser("root-setup")
    root.add_argument("--from", dest="source", required=True)
    doc = sub.add_parser("doctor")
    doc.add_argument("--config", default=DEFAULT_OWNER_CONFIG)
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
            return service.main([args.role, "--config", args.config])
        elif args.command == "setup":
            from . import setup_wizard
            setup_wizard.serve()
        elif args.command == "root-setup":
            from . import setup_wizard
            print("wrote", setup_wizard.root_setup(args.source))
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
            print(doctor.render(checks))
            return doctor.exit_code(checks)
        elif args.command in ("backup", "restore"):
            from . import backup
            config = OwnerConfig.from_file(Path(args.config).expanduser())
            if args.command == "backup":
                out = args.out or str(config.state_dir.parent / ("stynpilot-backup-%s.tar" % time.strftime("%Y%m%d-%H%M%S")))
                manifest = backup.make_backup(config.state_dir, out)
                print("backup written to", out, "(%d files, hashes recorded)" % len(manifest["files"]))
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
