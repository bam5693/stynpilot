#!/bin/sh
# Build a release .deb from a PINNED commit of the public repository and print its SHA-256 for comparison with the
# published value. The build is reproducible: the same commit gives the same bytes on any machine (pinned, hash-checked
# wheels; fixed timestamps). Nothing is installed; nothing outside the output folder is touched.
#   get_release.sh COMMIT EXPECTED_SHA256 [OUTDIR]        (COMMIT = full 40-character hash)
set -eu
COMMIT="${1:?full commit hash}"; EXPECT="${2:?expected sha256}"; OUT="${3:-$HOME/stynpilot-releases}"
REPO="${STYNPILOT_REPO:-https://github.com/bam5693/stynpilot.git}"
case "$COMMIT" in *[!0-9a-f]*|"") echo "FAIL: commit must be lowercase hex" >&2; exit 1;; esac
[ "${#COMMIT}" = 40 ] || { echo "FAIL: use the full 40-character commit hash" >&2; exit 1; }
case "$EXPECT" in *[!0-9a-f]*|"") echo "FAIL: expected hash must be lowercase hex" >&2; exit 1;; esac
[ "${#EXPECT}" = 64 ] || { echo "FAIL: expected sha256 must be 64 hex characters" >&2; exit 1; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
git init -q "$W/src"; git -C "$W/src" fetch -q --depth 1 "$REPO" "$COMMIT"; git -C "$W/src" checkout -q FETCH_HEAD
[ "$(git -C "$W/src" rev-parse HEAD)" = "$COMMIT" ] || { echo "FAIL: fetched commit differs from the pinned one" >&2; exit 1; }
(cd "$W/src" && python3 tools/build_deb.py >/dev/null)
DEB=$(ls "$W"/src/dist/stynpilot_*_all.deb); GOT=$(sha256sum "$DEB" | cut -d' ' -f1)
echo "built $(basename "$DEB") from $COMMIT"; echo "sha256 $GOT"
[ "$GOT" = "$EXPECT" ] || { echo "FAIL: checksum differs from the published value ($EXPECT); do not use this file" >&2; exit 1; }
mkdir -p "$OUT"; chmod 700 "$OUT"; NAME="$(basename "$DEB")"; [ -e "$OUT/$NAME" ] && { echo "FAIL: $OUT/$NAME already exists" >&2; exit 1; }
install -m 600 "$DEB" "$OUT/$NAME"; echo "saved $OUT/$NAME"; echo "RESULT: PASS checksum matches"
