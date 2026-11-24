"""StyNpilot upgrades itself: the root installer's part (it runs as root; the AI side can only ASK).

What the installer does for an owner-approved upgrade, stopping at the first failure BEFORE anything is changed:

 1. The plan is a signed release manifest (release.py): exact shape, trusted Ed25519 key, newer than what is
    installed, download address built from the pinned repository. The summary the owner reads comes from here.
 2. The owner's Auth0-signed proof is verified (the same proof as installs); the pre-change backup of the installer's
    own records is made; then the package is downloaded to a root-only folder and checked: size, SHA-256 against the
    signed manifest, the package's own name/version/architecture, the SAME dependency line as the installed package
    (an upgrade that needs new dependencies is refused here), no install scripts of any kind, only StyNpilot's own
    file locations, nothing owned by anyone but root, no setuid files, no links.
 3. A full copy of the CURRENT version is saved (the previous release if we kept it, otherwise the installed files
    re-packed and re-checked byte for byte against dpkg's own checksums). This is the rollback.
 4. Only then is the owner's challenge consumed and a separate worker started (its own systemd unit, so it survives
    the restart of this installer). The worker installs, restarts, checks health and rolls back by itself on failure.

Everything the installer will not do: install anything but the ``stynpilot`` package, trust a download address or
key that arrived with the request, run install scripts, or continue when the saved rollback cannot be proven good.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import release
from ..release import ReleaseError

PAYLOAD_FIELDS = {"kind", "software", "owner", "device", "manifest", "signature", "expires_at"}
SOFTWARE = "stynpilot-self"
PACKAGE = "stynpilot"
KEEP = 3                                                      # previous packages kept for rollback
JOB_GRACE = 90                                                # seconds before "no unit, no result" means vanished
_ALLOWED_PREFIXES = ("usr/lib/stynpilot/", "usr/libexec/stynpilot/", "usr/share/stynpilot/", "usr/share/doc/stynpilot/",
                     "usr/lib/systemd/system/stynpilot-", "usr/lib/systemd/user/stynpilot-",
                     "usr/share/applications/stynpilot-", "usr/share/polkit-1/actions/org.stynpilot.policy",
                     "usr/bin/stynpilot")
_DIRS = {"", "usr", "usr/lib", "usr/libexec", "usr/bin", "usr/share", "usr/lib/systemd", "usr/lib/systemd/system",
         "usr/lib/systemd/user", "usr/share/applications", "usr/share/polkit-1", "usr/share/polkit-1/actions",
         "usr/share/doc"}
_CONTROL_OK = {"control", "md5sums"}
_EXPIRY = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class UpgradeRefused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _field(text, name):
    for line in text.splitlines():
        if line.startswith(name + ":"):
            return line.split(":", 1)[1].strip()
    return ""


class Upgrader:
    def __init__(self, executor, *, keys=None, fetch=None, launch=None, options=None):
        self.ex = executor
        self._keys, self.fetch, self.launch = keys, fetch or release.https_get, launch or self._systemd_launch
        o = options or {}
        self.root = Path(o.get("root", "/"))                  # where installed files live (tests use a fake root)
        self.dpkg_extra = list(o.get("dpkg_extra", []))       # e.g. ["--root=/x"] in a disposable test machine
        self.query_extra = list(o.get("query_extra", []))
        self.config_files = o.get("config_files")             # None = default places
        self.owner_user = o.get("owner_user")
        self.doctor = o.get("doctor", True)
        self.restart = o.get("restart", True)
        self.health_wait = o.get("health_wait", 90)
        self.settle_seconds = o.get("settle_seconds", 8)
        self.socket_path = o.get("socket_path", "/run/stynpilot/installer.sock")
        self.worker_source = Path(o.get("worker_source", Path(__file__).resolve().parent.parent / "upgrade_worker.py"))
        self.python = o.get("python", "/usr/bin/python3")
        self.jobs = executor.dir / "upgrades"
        self.jobs.mkdir(exist_ok=True, mode=0o700)
        (executor.dir / "kept").mkdir(exist_ok=True, mode=0o700)
        (executor.dir / "upgrade-backups").mkdir(exist_ok=True, mode=0o700)

    # -- small helpers ----------------------------------------------------------------------------------
    @property
    def keys(self):
        if self._keys is None:
            self._keys = release.load_trusted_keys()
        return self._keys

    def _run(self, argv, timeout=120):
        return self.ex.run(argv, timeout)

    def installed_version(self):
        code, out = self._run(["dpkg-query", *self.query_extra, "-W", "-f", "${Version}", PACKAGE], 30)
        version = out.strip()
        if code != 0 or not version:
            raise UpgradeRefused("stynpilot_not_installed_as_a_package")
        return version

    def _installed_field(self, name):
        code, out = self._run(["dpkg-query", *self.query_extra, "-W", "-f", "${%s}" % name, PACKAGE], 30)
        return out.strip() if code == 0 else ""

    def version_gt(self, a, b):
        return self._run(["dpkg", *self.dpkg_extra, "--compare-versions", a, "gt", b], 30)[0] == 0

    def version_ge(self, a, b):
        return self._run(["dpkg", *self.dpkg_extra, "--compare-versions", a, "ge", b], 30)[0] == 0

    def job_dir(self, rid):
        return self.jobs / rid[:32]

    # -- 1. the plan ------------------------------------------------------------------------------------
    def check(self, payload):
        """Validate an upgrade payload completely. Returns (content, key_id, installed_version) or raises."""
        if type(payload) is not dict or set(payload) != PAYLOAD_FIELDS or payload["software"] != SOFTWARE:
            raise UpgradeRefused("plan_invalid_or_expired")
        if payload["owner"] != self.ex.owner or payload["device"] != self.ex.device:
            raise UpgradeRefused("plan_invalid_or_expired")
        expiry = payload["expires_at"]
        if type(expiry) is not str or not _EXPIRY.fullmatch(expiry):
            raise UpgradeRefused("plan_invalid_or_expired")
        when = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if not 0 < (when - now).total_seconds() <= 86400:
            raise UpgradeRefused("plan_invalid_or_expired")
        try:
            key = release.verify(payload["manifest"], payload["signature"], self.keys)
        except ReleaseError as bad:
            raise UpgradeRefused(bad.code) from None
        manifest = payload["manifest"]
        installed = self.installed_version()
        if not self.version_gt(manifest["version"], installed):
            raise UpgradeRefused("not_newer_than_installed")
        if manifest["from_min"] and not self.version_ge(installed, manifest["from_min"]):
            raise UpgradeRefused("installed_version_too_old_for_this_release")
        return payload, key, installed

    def summary(self, payload):
        content, key, installed = self.check(payload)
        return release.summary_lines(content["manifest"], key, installed)

    # -- 2. the package ---------------------------------------------------------------------------------
    def download(self, manifest, dest):
        data = self.fetch(release.download_url(manifest), manifest["size"] + 1)
        if len(data) != manifest["size"] or hashlib.sha256(data).hexdigest() != manifest["sha256"]:
            raise UpgradeRefused("download_does_not_match_signed_manifest")
        fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def inspect(self, deb, manifest, installed):
        """The package must be exactly a plain StyNpilot file set. Raises UpgradeRefused."""
        code, info = self._run(["dpkg-deb", "-f", str(deb)], 60)
        if code != 0:
            raise UpgradeRefused("package_unreadable")
        if (_field(info, "Package") != PACKAGE or _field(info, "Version") != manifest["version"]
                or _field(info, "Architecture") != "all"):
            raise UpgradeRefused("package_identity_differs_from_manifest")
        if _field(info, "Depends") != self._installed_field("Depends"):
            raise UpgradeRefused("package_changes_dependencies_not_allowed_here")
        with tempfile.TemporaryDirectory(dir=self.jobs) as tmp:
            code, _ = self._run(["dpkg-deb", "-e", str(deb), tmp + "/c"], 60)
            if code != 0:
                raise UpgradeRefused("package_unreadable")
            if set(os.listdir(tmp + "/c")) - _CONTROL_OK:
                raise UpgradeRefused("package_has_install_scripts_or_extra_control_files")
        code, listing = self._run(["dpkg-deb", "-c", str(deb)], 60)
        if code != 0:
            raise UpgradeRefused("package_unreadable")
        for line in listing.splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                raise UpgradeRefused("package_listing_unreadable")
            perms, owner, path = parts[0], parts[1], parts[5]
            if owner != "root/root" or perms[0] not in "-d" or "s" in perms or "t" in perms[1:] or " -> " in path:
                raise UpgradeRefused("package_contains_a_disallowed_file_type_or_owner")
            rel = path.removeprefix("./").rstrip("/")
            if ".." in rel.split("/"):
                raise UpgradeRefused("package_path_not_allowed")
            if perms[0] == "d":
                if rel not in _DIRS and not (rel + "/").startswith(_ALLOWED_PREFIXES[:4]):
                    raise UpgradeRefused("package_path_not_allowed")
            elif not (rel.startswith(_ALLOWED_PREFIXES)):
                raise UpgradeRefused("package_path_not_allowed")
        return True

    # -- 3. the rollback copy ---------------------------------------------------------------------------
    def previous_package(self, installed, dest):
        """A complete, proven copy of the installed version at ``dest``. Prefer the exact package we kept."""
        kept = self.ex.dir / "kept" / ("stynpilot_%s_all.deb" % installed.replace(":", "_"))
        if kept.is_file() and not kept.is_symlink():
            shutil.copyfile(kept, dest)
            return "kept_original"
        self.repack(installed, dest)
        return "repacked_from_installed_files"

    def repack(self, installed, dest):
        info_dir = self.root / "var/lib/dpkg/info"
        sums = info_dir / (PACKAGE + ".md5sums")
        try:
            entries = [line.split(None, 1) for line in sums.read_text().splitlines() if line.strip()]
        except OSError:
            raise UpgradeRefused("installed_file_list_unreadable") from None
        fields = {n: self._installed_field(n) for n in ("Package", "Version", "Architecture", "Depends", "Section",
                                                         "Priority", "Maintainer")}
        if fields["Version"] != installed:
            raise UpgradeRefused("installed_version_changed")
        with tempfile.TemporaryDirectory(dir=self.jobs) as tmp:
            stage = Path(tmp) / "pkg"
            for digest, rel in entries:
                rel = rel.strip()
                src = self.root / rel
                if ".." in rel.split("/") or rel.startswith("/") or src.is_symlink() or not src.is_file():
                    raise UpgradeRefused("installed_files_do_not_match_package_records")
                data = src.read_bytes()
                if hashlib.md5(data).hexdigest() != digest:
                    raise UpgradeRefused("installed_files_modified_so_no_trustworthy_rollback_copy")
                out = stage / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
                out.chmod(src.stat().st_mode & 0o7777)
            for path in [stage, *stage.rglob("*")]:
                if path.is_dir():
                    path.chmod(0o755)
            control = stage / "DEBIAN"
            control.mkdir(mode=0o755)
            lines = ["Package: %s" % PACKAGE, "Version: %s" % installed, "Architecture: all"]
            lines += ["%s: %s" % (k, fields[k]) for k in ("Section", "Priority", "Maintainer", "Depends") if fields[k]]
            lines += ["Description: StyNpilot (rollback copy re-packed from the installed files before an upgrade)"]
            (control / "control").write_text("\n".join(lines) + "\n")
            (control / "md5sums").write_text("".join("%s  %s\n" % (d, r.strip()) for d, r in entries))
            for name in ("control", "md5sums"):
                (control / name).chmod(0o644)
            code, out = self._run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(stage), str(dest)], 300)
            if code != 0:
                raise UpgradeRefused("rollback_copy_could_not_be_built")
            check = Path(tmp) / "check"
            if self._run(["dpkg-deb", "-x", str(dest), str(check)], 120)[0] != 0:
                raise UpgradeRefused("rollback_copy_could_not_be_verified")
            for digest, rel in entries:
                if hashlib.md5((check / rel.strip()).read_bytes()).hexdigest() != digest:
                    raise UpgradeRefused("rollback_copy_differs_from_installed_files")

    # -- 4. the job -------------------------------------------------------------------------------------
    def _owner_user(self):
        if self.owner_user:
            return self.owner_user
        return pwd.getpwuid(self.ex.owner_uid).pw_name

    def _default_config_files(self):
        files = sorted(str(p) for p in Path("/etc/stynpilot").glob("*") if p.is_file())
        try:
            home = Path(pwd.getpwuid(self.ex.owner_uid).pw_dir)
            for rel in (".config/stynpilot/owner.json",):
                if (home / rel).is_file():
                    files.append(str(home / rel))
        except (KeyError, TypeError):
            pass
        return files

    def _is_active(self, scope, unit):
        argv = ["systemctl"] + (["--user", "--machine=%s@.host" % self._owner_user()] if scope == "user" else [])
        return self._run(argv + ["is-active", unit], 30)[1].strip() == "active"

    def prepare(self, rid, content, installed):
        """Download, inspect, save the rollback copy, write job.json. Nothing on the machine changes. Returns job dir."""
        manifest = content["manifest"]
        free = shutil.disk_usage(self.ex.dir).free
        if free < 6 * manifest["size"] + 300 * 1024 * 1024:
            raise UpgradeRefused("not_enough_free_disk_space")
        job = self.job_dir(rid)
        if job.exists():
            raise UpgradeRefused("already_decided_or_used")
        job.mkdir(mode=0o700)
        try:
            new_deb, old_deb = job / "new.deb", job / "previous.deb"
            self.download(manifest, new_deb)
            self.inspect(new_deb, manifest, installed)
            how = self.previous_package(installed, old_deb)
            if self._run(["dpkg-deb", "-f", str(old_deb), "Version"], 30)[1].strip() != installed:
                raise UpgradeRefused("rollback_copy_is_not_the_installed_version")
            config_files = self.config_files if self.config_files is not None else self._default_config_files()
            hashes = {f: hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in config_files}
            user = self._owner_user()
            restart_installer = self.restart and self._is_active("system", "stynpilot-installer.service")
            restart_owner = self.restart and self._is_active("user", "stynpilot-owner.service")
            doctor = None
            if self.doctor and self.restart:
                uid = pwd.getpwnam(user).pw_uid
                doctor = ["runuser", "-u", user, "--", "env", "HOME=" + pwd.getpwnam(user).pw_dir,
                          "XDG_RUNTIME_DIR=/run/user/%d" % uid, "/usr/bin/stynpilot", "doctor"]
            baseline = self._run(doctor, 120)[0] if doctor else 0
            data = {"request_id": rid, "from_version": installed, "to_version": manifest["version"],
                    "new_deb": str(new_deb), "new_sha256": hashlib.sha256(new_deb.read_bytes()).hexdigest(),
                    "old_deb": str(old_deb), "old_sha256": hashlib.sha256(old_deb.read_bytes()).hexdigest(),
                    "previous_copy": how, "installer_unit": "stynpilot-installer.service",
                    "owner_unit": "stynpilot-owner.service", "owner_user": user, "socket_path": self.socket_path,
                    "restart_installer": bool(restart_installer), "restart_owner": bool(restart_owner),
                    "config_hashes": hashes, "doctor_command": doctor, "baseline_doctor_code": baseline,
                    "dpkg_extra": self.dpkg_extra, "query_extra": self.query_extra,
                    "health_wait": self.health_wait, "settle_seconds": self.settle_seconds,
                    "started_at": int(time.time())}
            worker = job / "upgrade_worker.py"
            shutil.copyfile(self.worker_source, worker)
            worker.chmod(0o700)
            (job / "job.json").write_text(json.dumps(data, sort_keys=True))
            (job / "README.txt").write_text(
                "If StyNpilot is broken after an interrupted upgrade, run as root:\n"
                "  dpkg -i --force-downgrade --force-confold %s\nthen: systemctl restart stynpilot-installer.service\n"
                % old_deb)
            for p in (job / "job.json", job / "README.txt"):
                p.chmod(0o600)
            return job
        except BaseException:
            shutil.rmtree(job, ignore_errors=True)
            raise

    def _systemd_launch(self, rid, job):
        unit = "stynpilot-upgrade-" + rid[:12]
        code, out = self._run(["systemd-run", "--unit", unit, "--collect", "--quiet",
                               "--description=StyNpilot upgrade worker", "--property=RuntimeMaxSec=1800",
                               self.python, "-I", str(job / "upgrade_worker.py"), str(job)], 60)
        if code != 0:
            raise UpgradeRefused("could_not_start_the_upgrade_worker")
        return unit

    def start(self, rid, job):
        unit = self.launch(rid, job)
        (job / "unit").write_text(str(unit))
        return unit

    # -- 5. outcome -------------------------------------------------------------------------------------
    def is_job(self, rid):
        return self.job_dir(rid).is_dir()

    def reconcile(self, rid):
        """Settle a 'running' upgrade from its job folder. True once the run has a final state."""
        job = self.job_dir(rid)
        result_file = job / "result.json"
        if not job.is_dir():
            return False
        if result_file.is_file() and not result_file.is_symlink():
            try:
                result = json.loads(result_file.read_text())
                if type(result) is not dict or "ok" not in result:
                    raise ValueError
            except (OSError, ValueError):
                result = {"ok": False, "stopped": "upgrade_result_unreadable", "changed_anything": None,
                          "needs_owner_intervention": True}
            self._finish(rid, result)
            return True
        try:
            started = json.loads((job / "job.json").read_text()).get("started_at", 0)
        except (OSError, ValueError):
            started = 0
        unit = "stynpilot-upgrade-" + rid[:12]
        alive = self._run(["systemctl", "is-active", unit], 30)[1].strip() in ("active", "activating")
        if alive or time.time() - started < JOB_GRACE:
            return False
        self._finish(rid, {"ok": False, "stopped": "upgrade_worker_vanished_without_a_result", "changed_anything": None,
                           "needs_owner_intervention": True})
        return True

    def _finish(self, rid, result):
        state = ("needs_owner_intervention" if result.get("needs_owner_intervention")
                 else "done" if result.get("ok") else "failed")
        if state == "needs_owner_intervention":
            self.ex._attention(rid, None, str(result.get("stopped", "upgrade_needs_attention"))[:60],
                               "see the upgrade job folder; its README names the manual rollback command")
        if state == "done":
            self._keep(rid)
        self.ex.runs.finish(rid, state, result)

    def _keep(self, rid):
        """After a good upgrade the exact package that ran becomes the next rollback source."""
        job = self.job_dir(rid)
        try:
            data = json.loads((job / "job.json").read_text())
            new = job / "new.deb"
            target = self.ex.dir / "kept" / ("stynpilot_%s_all.deb" % data["to_version"].replace(":", "_"))
            shutil.copyfile(new, target)
            target.chmod(0o600)
            kept = sorted((self.ex.dir / "kept").glob("stynpilot_*_all.deb"), key=lambda p: p.stat().st_mtime)
            for old in kept[:-KEEP]:
                old.unlink()
        except (OSError, ValueError, KeyError):
            pass
