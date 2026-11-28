"""Run the fixed private capture worker and collect only its completed frame."""

import hashlib
import json
import os
import stat
import subprocess

from .. import archive_store, managed_activity, repo_archive, repo_intake
from .lab import LabError, SystemdLab

_ENTRY = ("import sys;sys.pycache_prefix='/usr/lib/stynpilot/.source-only';"
          "sys.path.insert(0,'/usr/lib/stynpilot/lib');"
          "from stynpilot.repo_intake import installed;raise SystemExit(installed())")
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
SECONDS = 205


def capture_unit(job):
    if type(job) is not str or not managed_activity.ID.fullmatch(job):
        raise repo_archive.ArchiveError("archive_intake_request_invalid")
    return "stynpilot-archive-capture-" + job + ".service"


class Transport:
    def __init__(self, *, run=subprocess.run, fence=None):
        self.run = run
        self.fence = fence or SystemdLab(unit_name=capture_unit)

    def capture(self, *, job, source, refs, head, credential, stream):
        if type(source) is not tuple or len(source) != 2 or source[0] != "gitlab":
            raise repo_archive.ArchiveError("archive_intake_provider_unsupported")
        unit = capture_unit(job)
        data = json.dumps({"origin": source[1], "refs": refs, "head": head, "credential": credential},
                          separators=(",", ":")).encode()
        repo_intake._worker_request(data)
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or info.st_nlink != 0):
            raise repo_archive.ArchiveError("archive_intake_output_invalid")
        stream.seek(0)
        stream.truncate()
        props = (
            "DynamicUser=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectControlGroups=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "UMask=0077",
            "KillMode=control-group", "ExitType=cgroup", "Slice=system.slice",
            "BindsTo=stynpilot-installer.service", "After=stynpilot-installer.service",
            "TimeoutStartSec=10s", "TimeoutStopSec=5s", f"RuntimeMaxSec={SECONDS}",
            "MemoryMax=2G", "MemorySwapMax=0", "TasksMax=32", "CPUQuota=200%",
            "LimitCORE=0", "CoredumpFilter=0x0", "LimitFSIZE=520M",
            "TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,size=1536M,mode=1777",
            "InaccessiblePaths=-/var/lib/stynpilot-installer -/run/stynpilot",
        )
        command = ["/usr/bin/systemd-run", "--pipe", "--wait", "--quiet", "--collect",
                   "--service-type=exec", "--unit=" + unit]
        command.extend("--property=" + prop for prop in props)
        command += ["--", "/usr/bin/python3", "-IB", "-c", _ENTRY]
        try:
            done = self.run(command, input=data, stdout=stream, stderr=subprocess.DEVNULL, check=False,
                            timeout=SECONDS + 16, env=_ENV)
        except (OSError, subprocess.SubprocessError):
            raise repo_archive.ArchiveError("archive_intake_outcome_unverified") from None
        finally:
            try:
                self.fence.stop(job)
            except (LabError, OSError, subprocess.SubprocessError):
                raise repo_archive.ArchiveError("archive_intake_quiescence_unverified") from None
        if done.returncode:
            raise repo_archive.ArchiveError("archive_intake_refused")
        return self._verify_frame(stream, source, refs, head)

    @staticmethod
    def _verify_frame(stream, source, refs, head):
        stream.seek(0)
        header = stream.read(4)
        length = int.from_bytes(header, "big")
        if len(header) != 4 or not 0 < length <= repo_archive.MAX_MANIFEST:
            raise repo_archive.ArchiveError("archive_manifest_limit")
        raw = stream.read(length)
        receipt = archive_store._receipt_data(raw)
        if (len(raw) != length or receipt["source"] != repo_archive.source_origin(*source)
                or receipt["refs"] != refs or receipt["default_head"] != head):
            raise repo_archive.ArchiveError("archive_binding_invalid")
        digest, size = repo_archive._hash_bundle_stream(stream, limit=receipt["bundle_size"])
        if (digest, size) != (receipt["bundle_sha256"], receipt["bundle_size"]):
            raise repo_archive.ArchiveError("archive_bundle_digest_mismatch")
        stream.seek(0)
        return {"manifest_sha256": hashlib.sha256(raw).hexdigest(), "bundle_sha256": digest, "bundle_size": size}
