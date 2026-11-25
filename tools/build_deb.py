#!/usr/bin/env python3
"""Build dist/stynpilot_<version>_all.deb from this repo. Offline except for fetching the pinned wheel(s) in
packaging/vendor.lock, which are verified against their SHA-256 before use. Reproducible: fixed file times
(SOURCE_DATE_EPOCH) and sorted contents. The package has NO maintainer scripts: installing it starts, enables
and changes nothing; removing it deletes only its own files (state and config are left for the owner)."""
import hashlib
import io
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from stynpilot import __version__          # noqa: E402

DEPENDS = ["python3 (>= 3.11)", "python3-cryptography", "python3-jwt", "python3-starlette", "python3-uvicorn",
           "python3-httpx", "python3-pydantic", "python3-pydantic-settings", "python3-sse-starlette",
           "python3-httpx-sse", "python3-jsonschema", "python3-multipart", "python3-anyio",
           "python3-typing-extensions", "python3-typing-inspection", "polkitd | policykit-1", "ca-certificates"]


def deb_version():
    return __version__.replace(".dev", "~dev")


def read_lock():
    for line in (ROOT / "packaging/vendor.lock").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            spec, digest = line.split()
            name, version = spec.split("==")
            yield name, version, digest


def fetch_wheel(name, version, digest, cache):
    cache.mkdir(parents=True, exist_ok=True)
    found = list(cache.glob("%s-%s-*.whl" % (name, version)))
    if not found:
        subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:", "-d", str(cache),
                        "%s==%s" % (name, version)], check=True, capture_output=True)
        found = list(cache.glob("%s-%s-*.whl" % (name, version)))
    wheel = found[0]
    if not wheel.name.endswith("-py3-none-any.whl"):
        raise SystemExit("vendored wheels must be pure Python: " + wheel.name)
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != digest:
        raise SystemExit("hash mismatch for " + wheel.name)
    return wheel


def stage(dest, cache):
    lib = dest / "usr/lib/stynpilot/lib"
    shutil.copytree(ROOT / "src/stynpilot", lib / "stynpilot", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    vendor = dest / "usr/lib/stynpilot/vendor"
    vendor.mkdir(parents=True)
    for name, version, digest in read_lock():
        with zipfile.ZipFile(fetch_wheel(name, version, digest, cache)) as z:
            for member in z.namelist():
                if member.startswith("/") or ".." in Path(member).parts:
                    raise SystemExit("unsafe path in wheel")
            z.extractall(vendor)
    files = {"usr/bin/stynpilot": ("packaging/stynpilot-launcher", 0o755),
             "usr/libexec/stynpilot/root-helper": ("packaging/stynpilot-root-helper", 0o755),
             "usr/lib/systemd/system/stynpilot-installer.service": ("deploy/systemd/stynpilot-installer.service", 0o644),
             "usr/lib/systemd/user/stynpilot-owner.service": ("deploy/systemd/stynpilot-owner.service", 0o644),
             "usr/share/stynpilot/owner.example.json": ("deploy/owner.example.json", 0o644),
             "usr/share/stynpilot/installer.example.json": ("deploy/installer.example.json", 0o644),
             "usr/share/stynpilot/release-keys.json": ("packaging/release-keys.json", 0o644),
             "usr/share/polkit-1/actions/org.stynpilot.policy": ("packaging/org.stynpilot.policy", 0o644),
             "usr/share/applications/stynpilot-setup.desktop": ("packaging/stynpilot-setup.desktop", 0o644),
             "usr/share/applications/stynpilot-doctor.desktop": ("packaging/stynpilot-doctor.desktop", 0o644),
             "usr/share/applications/stynpilot-start.desktop": ("packaging/stynpilot-start.desktop", 0o644),
             "usr/share/applications/stynpilot-stop.desktop": ("packaging/stynpilot-stop.desktop", 0o644),
             "usr/share/doc/stynpilot/README.md": ("README.md", 0o644),
             "usr/share/doc/stynpilot/copyright": ("packaging/copyright", 0o644)}
    for target, (source, mode) in files.items():
        out = dest / target
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, out)
        out.chmod(mode)


def build(out_dir=None, cache=None):
    # The result must not depend on the builder's umask (a private 0077 umask used to leave DEBIAN unreadable by dpkg-deb
    # and could change file modes): fix it for the whole build, and set every mode explicitly below.
    os.umask(0o022)
    out_dir = Path(out_dir or ROOT / "dist")
    out_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1763769600"))
    with tempfile.TemporaryDirectory() as tmp:
        pkg = Path(tmp) / "pkg"
        stage(pkg, Path(cache or ROOT / ".build-cache"))
        for path in [pkg, *pkg.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
            elif not path.is_symlink() and not path.stat().st_mode & 0o111:
                path.chmod(0o644)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        size = sum(p.stat().st_size for p in pkg.rglob("*") if p.is_file()) // 1024
        control = pkg / "DEBIAN"
        control.mkdir()
        control.chmod(0o755)
        (control / "control").write_text(
            "Package: stynpilot\nVersion: %s\nSection: admin\nPriority: optional\nArchitecture: all\n"
            "Depends: %s\nInstalled-Size: %d\nMaintainer: StyNpilot owner <owner@invalid>\n"
            "Description: Owner-approved AI control of this computer\n"
            " Lets ChatGPT and Claude ask; only the owner can approve. Installing this package starts and\n"
            " changes nothing: run StyNpilot Setup from the menu.\n" % (deb_version(), ", ".join(DEPENDS), size))
        sums = []
        for path in sorted(p for p in pkg.rglob("*") if p.is_file() and "DEBIAN" not in p.parts):
            sums.append("%s  %s" % (hashlib.md5(path.read_bytes()).hexdigest(), path.relative_to(pkg)))
        (control / "md5sums").write_text("\n".join(sums) + "\n")
        for path in (control / "control", control / "md5sums"):
            path.chmod(0o644)
        for path in (control, control / "control", control / "md5sums"):
            os.utime(path, (epoch, epoch))
        target = out_dir / ("stynpilot_%s_all.deb" % deb_version())
        write_deb(pkg, target, epoch)
    return target


def _entries(root, skip_debian):
    """(name, mode, data-or-None) for every directory and regular file under root, parents first, in a fixed order. Anything
    else (a symlink, a device, a fifo) is refused: this package has none, and a surprise there is a build error."""
    found = [("./", 0o755, None)]
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).parts):
        rel = path.relative_to(root)
        if skip_debian and rel.parts[0] == "DEBIAN":
            continue
        if path.is_symlink():
            raise SystemExit("symlinks are not allowed in the package: " + str(rel))
        if path.is_dir():
            found.append(("./%s/" % rel.as_posix(), 0o755, None))
        elif path.is_file():
            found.append(("./" + rel.as_posix(), 0o755 if path.stat().st_mode & 0o111 else 0o644, path.read_bytes()))
        else:
            raise SystemExit("unsupported file type in the package: " + str(rel))
    return found


def _tar_xz(entries, epoch):
    """A deterministic GNU tar, xz-compressed, written entirely in this process: no tar/xz/dpkg-deb child, so the build needs no
    syscalls beyond Python's own. Every entry is root-owned with the fixed epoch."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.mtime, info.mode = epoch, mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            if data is None:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)


def _ar(members, epoch):
    out = [b"!<arch>\n"]
    for name, data in members:
        out.append(("%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, epoch, 0, 0, "100644", len(data))).encode("ascii"))
        out.append(data)
        if len(data) % 2:
            out.append(b"\n")
    return b"".join(out)


def write_deb(pkg, target, epoch):
    """Write the .deb (an ar archive: debian-binary, control.tar.xz, data.tar.xz) byte-for-byte deterministically."""
    control = _tar_xz(_entries(pkg / "DEBIAN", False), epoch)
    data = _tar_xz(_entries(pkg, True), epoch)
    Path(target).write_bytes(_ar([("debian-binary", b"2.0\n"), ("control.tar.xz", control), ("data.tar.xz", data)], epoch))


if __name__ == "__main__":
    print(build())
