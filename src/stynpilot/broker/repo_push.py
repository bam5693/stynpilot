"""Root admission and isolated native Git transport for an approved work ref."""
from __future__ import annotations

from pathlib import Path
import re
import secrets
import subprocess

from .. import repo_git, vault

_ENTRY = ("import sys;sys.pycache_prefix='/usr/lib/stynpilot/.source-only';"
          "sys.path.insert(0,'/usr/lib/stynpilot/lib');"
          "from stynpilot.repo_push import main;raise SystemExit(main())")
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class Transport:
    def __init__(self, state, run=subprocess.run):
        self.credential = Path(state) / "repository-github-token"
        self.run = run

    def ready(self):
        try:
            data = vault._read_private(self.credential, 256)
            return re.fullmatch(rb"[A-Za-z0-9_]{20,255}\n?", data) is not None
        except (OSError, vault.VaultError):
            return False

    def publish(self, bundle, branch, commit, expected):
        repo_git.validate_push(branch, commit, expected)
        if not self.ready():
            raise repo_git.WorkspaceError("git_push_credential_unavailable")
        unit = "stynpilot-repo-push-" + secrets.token_hex(12)
        properties = (
            "DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes",
            "NoNewPrivileges=yes", "ProtectControlGroups=yes", "ProtectKernelTunables=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "UMask=0077", "KillMode=control-group",
            "TimeoutStartSec=10s", "TimeoutStopSec=5s", "RuntimeMaxSec=130s", "MemoryMax=1G", "MemorySwapMax=0", "TasksMax=32",
            "CPUQuota=200%", "LimitFSIZE=64M", "TemporaryFileSystem=/tmp:rw,nosuid,nodev,size=128M",
            "InaccessiblePaths=-/var/lib/stynpilot-installer -/run/stynpilot",
            "LoadCredential=github:" + str(self.credential),
        )
        command = ["/usr/bin/systemd-run", "--pipe", "--wait", "--quiet", "--collect", "--service-type=exec", "--unit=" + unit]
        command.extend("--property=" + prop for prop in properties)
        command.extend(["--", "/usr/bin/python3", "-IB", "-c", _ENTRY, branch, commit, expected])
        try:
            result = self.run(command, input=bundle, env=_ENV, timeout=140,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except (OSError, subprocess.SubprocessError):
            raise repo_git.WorkspaceError("git_push_outcome_unverified") from None
        if result.returncode:
            raise repo_git.WorkspaceError("git_push_refused_or_unverified")
