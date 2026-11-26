#!/usr/bin/env python3
"""Boot a trusted Ubuntu image with a fresh copy-on-write disk and no network."""
import argparse
import fcntl
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

GIB = 1 << 30
DEFAULT = Path.home() / ".local/share/stynpilot-dev"
LOG_LIMIT = 8 << 20


def boot(command, env, serial_path, log, marker, deadline, *, cut_power=False):
    marker_line = marker.encode("ascii")
    if time.monotonic() >= deadline:
        return 124
    with (serial_path.open("wb") as serial,
          selectors.DefaultSelector() as selector,
          subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process):
        selector.register(process.stdout, selectors.EVENT_READ, serial)
        selector.register(process.stderr, selectors.EVENT_READ, log)
        saw_marker = False
        line = b""
        overlong_line = False
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 124
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fd)
                        continue
                    output = key.data
                    room = LOG_LIMIT - output.tell()
                    output.write(chunk[:room])
                    if len(chunk) > room:
                        return 125
                    if output is log:
                        continue
                    parts = chunk.split(b"\n")
                    for part in parts[:-1]:
                        if not overlong_line and line + part in (marker_line, marker_line + b"\r"):
                            saw_marker = True
                            if cut_power:
                                if process.poll() is not None:
                                    return 1
                                process.kill()
                                return 0 if process.wait() == -signal.SIGKILL else 1
                        line = b""
                        overlong_line = False
                    if not overlong_line:
                        line += parts[-1]
                        if len(line) > len(marker_line) + 1:
                            line = b""
                            overlong_line = True
            exit_code = process.wait(timeout=max(0, deadline - time.monotonic()))
            return exit_code or (0 if saw_marker and not cut_power else 1)
        except subprocess.TimeoutExpired:
            return 124
        finally:
            if process.poll() is None:
                process.kill()


def _terminate(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT)
    parser.add_argument("--seed", type=Path, required=True, help="NoCloud ISO with synthetic guest configuration")
    parser.add_argument("--payload", type=Path, help="Optional read-only artifact ISO")
    parser.add_argument("--power-cycle-marker", help="Kill the emulator at this serial marker and reboot its overlay once")
    parser.add_argument("--marker", required=True, help="Expected serial output on successful shutdown")
    parser.add_argument("--timeout", type=int, default=900, metavar="60..3600")
    args = parser.parse_args()
    for marker in (args.marker, args.power_cycle_marker):
        if marker is not None and (not marker.isascii() or not marker.isidentifier() or len(marker) > 128):
            parser.error("markers must be ASCII identifiers of up to 128 characters")
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
                       "-serial", "stdio", "-monitor", "none", "-no-reboot",
                       "-drive", f"file={overlay},if=virtio,format=qcow2"]
            for iso in (args.seed, args.payload):
                if iso:
                    path = iso.resolve(strict=True)
                    if "," in str(path) or not path.is_file():
                        parser.error("ISO must be a regular file with a comma-free path")
                    command += ["-drive", f"file={path},media=cdrom,format=raw,readonly=on"]
            deadline = time.monotonic() + args.timeout
            with (result / "qemu.log").open("wb") as log:
                if args.power_cycle_marker:
                    status = boot(command, env, result / "before-power-cut.log", log,
                                  args.power_cycle_marker, deadline, cut_power=True)
                    if status:
                        return status
                return boot(command, env, result / "serial.log", log, args.marker, deadline)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _terminate)
    resource.setrlimit(resource.RLIMIT_FSIZE, (18 * GIB, 18 * GIB))
    raise SystemExit(main())
