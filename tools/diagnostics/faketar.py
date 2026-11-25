#!/usr/bin/python3.12
# Mimics Ubuntu 26.04 GNU tar 1.35 inside the release sandbox (live probe 2026-11-25: openat2 -> ENOSYS without fallback):
# names inside a folder fail ('Cannot stat' when creating from a list, 'Cannot mkdir/open' when extracting); top-level names,
# plain listing and plain directory creation work. Everything else is passed to the real tar.
import io, subprocess, sys, tarfile
args = sys.argv[1:]
flags = "".join(a for a in args[:1] if not a.startswith("--")) + "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
nested = lambda names: any("/" in n[2:].rstrip("/") if n.startswith("./") else "/" in n.rstrip("/") for n in names if n not in (".", "./"))
data = None
if "x" in flags:
    src = args[args.index("-f") + 1] if "-f" in args else "-"
    data = sys.stdin.buffer.read() if src == "-" else open(src, "rb").read()
    names = tarfile.open(fileobj=io.BytesIO(data), mode="r:*").getnames()
    if nested(names):
        sys.stderr.write("tar: %s: Cannot open: Function not implemented\n" % [n for n in names if "/" in n.strip("./")][0]); sys.exit(2)
elif "-T" in args or any(a.startswith("--files-from") for a in args):
    data = sys.stdin.buffer.read()
    names = [n.decode() for n in data.replace(b"\n", b"\0").split(b"\0") if n]
    if nested(names):
        sys.stderr.write("tar: %s: Cannot stat: Function not implemented\n" % [n for n in names if "/" in n.strip("./")][0]); sys.exit(2)
sys.exit(subprocess.run(["/usr/bin/tar"] + args, input=data).returncode)
