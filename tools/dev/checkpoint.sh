#!/bin/sh
# Record candidate identity, test environment and reproducible package evidence.
set -eu
umask 077
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
dev_dir=${STYNPILOT_DEV_DIR:-"$HOME/.local/share/stynpilot-dev"}
wheel_cache="$dev_dir/cache/wheels"
mkdir -p "$dev_dir/work"
result=$(mktemp -d "$dev_dir/work/checkpoint.XXXXXXXX")
echo "$result"
{
    git -C "$repo" rev-parse HEAD
    git -C "$repo" status --short --branch
    python3 --version
    git --version
    docker compose version 2>/dev/null || true
} > "$result/context.log"
git -C "$repo" diff --check
(
    cd "$repo"
    python3 -B - "$result" "$wheel_cache" <<'PY'
import hashlib
from pathlib import Path
import sys
sys.path.insert(0, "tools")
from build_deb import build, read_lock
output, cache = map(Path, sys.argv[1:])
for name, version, digest in read_lock():
    matches = list(cache.glob(f"{name}-{version}-*.whl"))
    if len(matches) != 1 or hashlib.sha256(matches[0].read_bytes()).hexdigest() != digest:
        raise SystemExit(f"missing or invalid pinned wheel in cache: {name} {version}")
first = build(output / "first", cache)
second = build(output / "second", cache)
digest = hashlib.sha256(first.read_bytes()).hexdigest()
if hashlib.sha256(second.read_bytes()).hexdigest() != digest:
    raise SystemExit("package is not reproducible")
print(digest, first.stat().st_size, first.name)
PY
) > "$result/package.log"
cat "$result/context.log" "$result/package.log"
