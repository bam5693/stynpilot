"""Start and stop StyNpilot without a terminal: one password prompt for the root installer (a fixed polkit action),
then the owner's own user service. Both are plain systemd units; nothing here has extra rights.

  start: pkexec root-start  ->  systemctl --user enable --now stynpilot-owner  ->  stay running after logout (linger,
         best effort)  ->  wait until both are really up and say so, or say what is wrong.
  stop : the reverse. Requests, backups and settings are left exactly as they are.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from .setup_wizard import ROOT_HELPER

OWNER_UNIT = "stynpilot-owner.service"
INSTALLER_UNIT = "stynpilot-installer.service"
SOCKET = "/run/stynpilot/installer.sock"


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def _active(unit, user):
    return _run((["systemctl", "--user"] if user else ["systemctl"]) + ["is-active", unit]).stdout.strip() == "active"


def _listening(port):
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def wait_until(check, seconds, clock=time.monotonic, sleep=time.sleep):
    end = clock() + seconds
    while clock() < end:
        if check():
            return True
        sleep(1)
    return bool(check())


def run(command, config_path, *, show=False, run=_run, active=_active, wait=wait_until, listening=_listening, out=sys.stdout):
    from .service import ConfigError, OwnerConfig
    if command == "start":
        config = OwnerConfig.from_file(config_path)               # fail early if setup was never finished
        first = run(["pkexec", ROOT_HELPER, "root-start"], timeout=300)
        if first.returncode != 0:
            print("The installer was NOT started (password prompt cancelled or refused):",
                  (first.stderr or first.stdout).strip()[:300], file=out)
            return 1
        second = run(["systemctl", "--user", "enable", "--now", OWNER_UNIT])
        if second.returncode != 0:
            print("The owner service did not start:", (second.stderr or second.stdout).strip()[:300], file=out)
            return 1
        run(["loginctl", "enable-linger", str(os.getuid())])        # keep it running when nobody is logged in
        up = wait(lambda: active(INSTALLER_UNIT, False) and active(OWNER_UNIT, True) and os.path.exists(SOCKET)
                  and listening(config.approval_port) and listening(config.mcp_port), 90)   # "running" means answering
        print("StyNpilot is running." if up else "StyNpilot did not come up in time: open Doctor to see why "
              "(journalctl -u %s)." % INSTALLER_UNIT, file=out)
        code = 0 if up else 1
    else:
        run(["systemctl", "--user", "disable", "--now", OWNER_UNIT])
        stopped = run(["pkexec", ROOT_HELPER, "root-stop"], timeout=300)
        if stopped.returncode != 0:
            print("The installer was NOT stopped:", (stopped.stderr or stopped.stdout).strip()[:300], file=out)
            return 1
        print("StyNpilot is stopped. Your settings, requests and backups are untouched.", file=out)
        code = 0
    if show:
        from . import doctor
        from .broker.service import BrokerClient
        from .service_status import listeners
        cfg = OwnerConfig.from_file(config_path)
        doctor.show_html(doctor.run_checks(owner_config=cfg, listeners=listeners, client=BrokerClient(cfg.broker_socket)))
    return code
