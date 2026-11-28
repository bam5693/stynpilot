"""Persistent systemd startup guard for binaries that lack private authorization."""

import os
from pathlib import Path
import stat

from .. import vault
from . import apt

MINIMUM = "0.1.0~dev34"
UNIT = "stynpilot-installer.service"
DROP_IN = Path("/etc/systemd/system") / (UNIT + ".d") / "60-stynpilot-private-floor.conf"
_CHECK = (
    "import subprocess,sys; "
    "v=subprocess.check_output(['/usr/bin/dpkg-query','-W','-f='+chr(36)+'{Version}','stynpilot'],"
    "timeout=10,text=True).strip(); "
    f"sys.exit(subprocess.run(['/usr/bin/dpkg','--compare-versions',v,'ge','{MINIMUM}'],timeout=10).returncode)"
)
BODY = ("[Service]\nExecStartPre=/usr/bin/python3 -I -B -c \"" + _CHECK + "\"\n").encode("ascii")


class FloorError(Exception):
    code = "private_access_version_floor_unverified"


def _trusted_folder(folder):
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise FloorError()


def ready(*, run=apt.real_run):
    try:
        for parent in reversed(DROP_IN.parents):
            _trusted_folder(parent)
        if vault._read_private(DROP_IN, 4096, uid=0) != BODY:
            return False
        query = ["/usr/bin/systemctl", "show", "--property=DropInPaths", "--value", UNIT]
        code, result = run(query, 10)
        return code == 0 and str(DROP_IN) in result.split()
    except (FloorError, OSError, vault.VaultError):
        return False


def install(*, run=apt.real_run):
    """Arm the persistent fence before granting any private access."""
    folder = DROP_IN.parent
    try:
        for parent in reversed(folder.parents):
            _trusted_folder(parent)
        folder.mkdir(mode=0o755, exist_ok=True)
        _trusted_folder(folder)
        try:
            body = vault._read_private(DROP_IN, 4096, uid=0)
        except FileNotFoundError:
            vault._write_atomic(folder, DROP_IN.name, BODY)
        else:
            if body != BODY:
                raise FloorError()
        if ready(run=run):
            return
        if run(["/usr/bin/systemctl", "daemon-reload"], 20)[0] or not ready(run=run):
            raise FloorError()
    except (OSError, vault.VaultError) as error:
        raise FloorError() from error
