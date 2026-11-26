"""Fixed systemd operations for the independent root recovery worker."""
import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, root_restore
from .broker import selftest
from .upgrade_worker import ENV, socket_answers

# The service manager runs this fixed readiness probe as the enrolled owner.
_OWNER_PROBE = ("import os,subprocess,sys;from pathlib import Path;sys.path.insert(0,'/usr/lib/stynpilot/lib');sys.path.append('/usr/lib/stynpilot/vendor');"
                "from stynpilot.service import OwnerConfig;from stynpilot.upgrade_worker import endpoint_answers;"
                "os.environ['XDG_RUNTIME_DIR']='/run/user/%d'%os.getuid();"
                "subprocess.run(['/usr/bin/systemctl','--user','is-active','--quiet','stynpilot-owner.service'],check=True,timeout=10);"
                "c=OwnerConfig.from_file(Path.home()/'.config/stynpilot/owner.json');"
                "sys.exit(0 if endpoint_answers({'port':c.mcp_port,'host':c.mcp_public_host}) else 1)")

UNIT = "stynpilot-installer.service"
PACKAGED_STATE = Path("/var/lib/stynpilot-installer")
_PROBE = ("import sys,json;sys.path.insert(0,'/usr/lib/stynpilot/lib');sys.path.append('/usr/lib/stynpilot/vendor');"
          "from stynpilot.broker.service import BrokerClient;"
          "client=BrokerClient(sys.argv[1]);"
          "print(json.dumps(client._ask({'op':'restore_check','probe':sys.stdin.read(65)},120)['result']))")


def complete_checks(result):
    expected = set(selftest.REQUIRED + selftest.OPTIONAL + selftest.STRICT_REQUIRED)
    return (result.get("ok") is True and result.get("ran") is True and result.get("version") == __version__
            and result.get("failed") == [] and result.get("unverified") == [] and set(result.get("passed", [])) == expected)


class Services:
    def __init__(self, config):
        self.owner = pwd.getpwuid(config.owner_uid)
        self.socket = str(config.socket_path)

    def systemctl(self, *args):
        return subprocess.run(["/usr/bin/systemctl", *args], timeout=90, check=False, env=ENV,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL).returncode == 0

    def stop(self):
        if not self.systemctl("stop", UNIT):
            raise root_restore.ERROR("installer_stop_failed")

    def start(self):
        if not self.systemctl("start", UNIT):
            raise root_restore.ERROR("installer_start_failed")

    def start_safe(self):
        self.start()

    def services_ready(self):
        return (self.systemctl("is-active", "--quiet", UNIT)
                and socket_answers(self.socket, self.owner.pw_uid, self.owner.pw_gid))

    def healthy(self, probe_token):
        limit = time.monotonic() + 90
        while not self.services_ready():
            if time.monotonic() >= limit:
                return False
            time.sleep(2)
        probe = subprocess.run([sys.executable, "-I", "-c", _PROBE, self.socket], env=ENV, cwd="/",
                               user=self.owner.pw_uid, group=self.owner.pw_gid, extra_groups=[],
                               input=probe_token.encode(), capture_output=True, timeout=150)
        if probe.returncode or not complete_checks(json.loads(probe.stdout)) or not self.services_ready():
            return False
        owner = subprocess.run(["/usr/bin/systemd-run", "--uid=" + str(self.owner.pw_uid),
                                "--gid=" + str(self.owner.pw_gid), "--quiet", "--wait", "--collect",
                                "--property=NoNewPrivileges=yes", "--property=TimeoutStartSec=30s", "--service-type=oneshot",
                                "/usr/bin/python3", "-I", "-c", _OWNER_PROBE], timeout=40, env=ENV,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return owner.returncode == 0


def run(path, config):
    from .service import root_vault
    if os.geteuid() != 0 or config.state_dir != PACKAGED_STATE or Path(path) != Path("/etc/stynpilot/installer.json"):
        raise root_restore.ERROR("packaged_root_restore_configuration_required")
    root_restore.worker(root_vault(path, config), Services(config))
    return 0


def serve_safe(config):
    from .broker.service import BrokerService

    class RecoveryStatus(BrokerService):
        def handle(self, message):
            return root_restore.safe_reply(config.state_dir, message if isinstance(message, dict) else {})
    RecoveryStatus(socket_path=config.socket_path, executor=None, allowed_uid=config.owner_uid).serve_forever()
    return 0


def watcher_ready(config, path):
    return (config.state_dir == PACKAGED_STATE and Path(path) == Path("/etc/stynpilot/installer.json")
            and Services(config).systemctl("is-active", "--quiet", "stynpilot-restore.path"))
