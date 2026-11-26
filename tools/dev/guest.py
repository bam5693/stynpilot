#!/usr/bin/env python3
"""Boot a trusted Ubuntu image with a fresh copy-on-write disk and no network."""
import argparse
import fcntl
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time

GIB = 1 << 30
DEFAULT = Path.home() / ".local/share/stynpilot-dev"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--seed", type=Path, required=True, help="NoCloud ISO with synthetic guest configuration")
    parser.add_argument("--payload", type=Path, help="Optional read-only artifact ISO")
    parser.add_argument("--power-cycle-marker", help="Kill the emulator at this serial marker and reboot its overlay once")
    parser.add_argument("--marker", required=True, help="Expected serial output on successful shutdown")
    parser.add_argument("--timeout", type=int, default=900, metavar="60..3600")
    args = parser.parse_args()
    if not 60 <= args.timeout <= 3600:
        parser.error("timeout must be 60 to 3600 seconds")
    if os.geteuid() == 0:
        parser.error("run the guest as a normal user")
    directory = args.directory.resolve()
    cache, work = directory / "cache", directory / "work"
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    image_dir = cache / "ubuntu-resolute"
    prepared = cache / "qemu/usr"
    image = image_dir / "ubuntu-26.04-server-cloudimg-amd64.img"
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LD_LIBRARY_PATH": str(prepared / "lib/x86_64-linux-gnu")}
    with (work / "guest.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error("another guest is running in this development directory")
        available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                             if line.startswith("MemAvailable:"))) * 1024
        if available < 6 * GIB or shutil.disk_usage(work).free < 22 * GIB:
            parser.error("guest requires 6 GiB available RAM and 22 GiB free disk")
        with open("/dev/kvm", "r+b", buffering=0) as kvm:
            if fcntl.ioctl(kvm, 0xAE00, 0) != 12:
                parser.error("KVM is unavailable")
        subprocess.run(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg",
                        "SHA256SUMS.gpg", "SHA256SUMS"], cwd=image_dir, check=True)
        # Verify against the signed manifest, not a checksum supplied by the caller.
        lines = (image_dir / "SHA256SUMS").read_text().splitlines()
        match = [line for line in lines if line.endswith(" *" + image.name)]
        if len(match) != 1:
            parser.error("signed manifest does not uniquely identify the base image")
        subprocess.run(["sha256sum", "--strict", "--check"], input=match[0] + "\n", cwd=image_dir, text=True, check=True)
        result = Path(tempfile.mkdtemp(prefix="result-", dir=work))
        print(result, flush=True)
        with tempfile.TemporaryDirectory(prefix="disk-", dir=work) as disk:
            overlay = Path(disk) / "overlay.qcow2"
            subprocess.run([prepared / "bin/qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
                            "-b", image, overlay], env=env, check=True)
            subprocess.run([prepared / "bin/qemu-img", "resize", "-q", overlay, "16G"], env=env, check=True)
            command = [prepared / "bin/qemu-system-x86_64", "-L", prepared / "share/qemu", "-enable-kvm",
                       "-cpu", "host", "-smbios", "type=1,product=STYNPILOT-DISPOSABLE", "-smp", "2", "-m", "3072", "-machine", "q35",
                       "-bios", prepared / "share/ovmf/OVMF.fd", "-nic", "none", "-display", "none", "-vga", "none",
                       "-serial", f"file:{result / 'serial.log'}", "-monitor", "none", "-no-reboot",
                       "-drive", f"file={overlay},if=virtio,format=qcow2"]
            for iso in (args.seed, args.payload):
                if iso:
                    path = iso.resolve(strict=True)
                    if "," in str(path) or not path.is_file():
                        parser.error("ISO must be a regular file with a comma-free path")
                    command += ["-drive", f"file={path},media=cdrom,format=raw,readonly=on"]
            with (result / "qemu.log").open("w") as log:
                try:
                    if args.power_cycle_marker:
                        serial_path = result / "serial.log"
                        with subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log) as first:
                            try:
                                deadline = time.monotonic() + args.timeout
                                cursor = 0
                                interrupted = False
                                while first.poll() is None and time.monotonic() < deadline:
                                    if serial_path.exists():
                                        with serial_path.open(errors="replace") as serial:
                                            serial.seek(cursor)
                                            while line := serial.readline():
                                                if not line.endswith("\n"):
                                                    break
                                                cursor = serial.tell()
                                                if args.power_cycle_marker in line:
                                                    first.kill()
                                                    interrupted = True
                                                    first.wait()
                                                    break
                                    time.sleep(0.2)
                                if not interrupted or first.returncode != -9:
                                    return 1
                            finally:
                                if first.poll() is None:
                                    first.kill()
                        serial_path.rename(result / "before-power-cut.log")
                    process = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                                             stdout=log, stderr=log, timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    return 124
        if process.returncode:
            return process.returncode
        with (result / "serial.log").open(errors="replace") as serial:
            return 0 if any(args.marker in line for line in serial) else 1


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_FSIZE, (18 * GIB, 18 * GIB))
    raise SystemExit(main())
