#!/bin/sh
set -eu
umask 077
test "$(id -u)" -ne 0
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
dev_dir=${STYNPILOT_DEV_DIR:-"$HOME/.local/share/stynpilot-dev"}
ref=${1:-HEAD}
mkdir -p "$dev_dir/work" "$dev_dir/cache/seccomp-deb"
work=$(mktemp -d "$dev_dir/work/suites.XXXXXXXX")
mkdir "$work/src" "$work/cache" "$work/vendor" "$work/seccomp"
oid=$(git -C "$repo" rev-parse --verify "$ref^{commit}")
echo "$oid" > "$work/source-commit"
git -C "$repo" archive "$oid" -o "$work/source.tar"
tar xf "$work/source.tar" -C "$work/src"
unlink "$work/source.tar"
python3 -B - "$work" "$dev_dir/cache/wheels" <<'PY'
import hashlib
from pathlib import Path
import shutil
import sys
import zipfile
work, cache = map(Path, sys.argv[1:])
for line in (work / "src/packaging/vendor.lock").read_text().splitlines():
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    spec, digest = line.split()
    name, version = spec.split("==")
    wheels = list(cache.glob(f"{name}-{version}-*.whl"))
    if len(wheels) != 1 or hashlib.sha256(wheels[0].read_bytes()).hexdigest() != digest:
        raise SystemExit(f"missing or invalid pinned wheel: {spec}")
    shutil.copy2(wheels[0], work / "cache")
    with zipfile.ZipFile(wheels[0]) as wheel:
        wheel.extractall(work / "vendor")
PY
(
    cd "$dev_dir/cache/seccomp-deb"
    version=$(apt-cache policy python3-seccomp | awk '$1 == "Candidate:" {print $2; exit}')
    test -n "$version"
    apt-get download "python3-seccomp=$version" >&2
    set -- ./*.deb
    test "$#" -eq 1
    dpkg-deb -x "$1" "$work/seccomp"
)
echo "$work"
