#!/bin/sh
# Pre-upgrade protection of everything StyNpilot keeps OUTSIDE what `stynpilot backup` / `root-backup` cover:
#   owner side (no root): owner settings file (owner.json: AI-endpoint/Auth0 connection settings), the existing device
#                         pairing database, and EVERY file in the owner state folder (approval/request history,
#                         revocations, provisioned marker);
#   root side (sudo):     /etc/stynpilot/installer.json and setup-receipt.json -> a root-only folder under /var/backups.
# Read-only on the live files (SQLite files are copied with SQLite's own online-backup call, opened read-only).
# Everything lands in NEW folders created 0700 (files 0600); nothing existing is overwritten. Every copy is verified
# (SHA-256 list, SQLite integrity check, source unchanged). File contents are never printed.
#
#   preflight_backup.sh [OWNER_DEST]           make the backups and verify them
#   preflight_backup.sh --verify OWNER_DEST    re-verify an earlier backup (owner side and its root-side twin)
# The root-side folder name is stored in OWNER_DEST/ROOT_DEST.
set -eu
umask 077
OWNERCFG="${STYNPILOT_OWNER_CONFIG:-$HOME/.config/stynpilot/owner.json}"
ROOTCFG_DIR="${STYNPILOT_ROOT_CONFIG_DIR:-/etc/stynpilot}"
ROOT_BACKUPS="${STYNPILOT_ROOT_BACKUPS:-/var/backups}"
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo"; fi
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf '== %s\n' "$*"; }

verify() {
  D="$1"; [ -d "$D/owner" ] || fail "$D is not a preflight backup"
  R=$(cat "$D/ROOT_DEST"); [ -n "$R" ] || fail "root destination unknown"
  (cd "$D/owner" && sha256sum -c --quiet SHA256SUMS) || fail "owner-side checksum mismatch"
  find "$D" -type d ! -perm 700 | grep -q . && fail "a backup folder is not 0700"
  find "$D" -type f ! -perm 600 | grep -q . && fail "a backup file is not 0600"
  for f in $(cd "$D/owner" && find . -name '*.sqlite3' | sort); do
    python3 -I -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute("pragma integrity_check").fetchone()[0]; sys.exit(0 if r=="ok" else 1)' "$D/owner/$f" || fail "SQLite integrity check failed: $f"
  done
  $SUDO sh -c "cd '$R' && sha256sum -c --quiet SHA256SUMS" || fail "root-side checksum mismatch"
  $SUDO sh -c "[ \"\$(stat -c %a '$R')\" = 700 ] && [ \"\$(stat -c %U '$R')\" = root ]" || fail "root-side folder is not root-only 0700"
  $SUDO sh -c "find '$R' -type f ! -perm 600 | grep -q ." && fail "a root-side file is not 0600" || true
  say "verified: $D and $R"
}

if [ "${1:-}" = "--verify" ]; then verify "${2:?owner backup folder required}"; echo "RESULT: PASS (verify)"; exit 0; fi

TS=$(date +%Y%m%d-%H%M%S)
DEST="${1:-$HOME/stynpilot-pre-m1-$TS}"
ROOTDEST="$ROOT_BACKUPS/stynpilot-pre-m1-$TS"
[ ! -e "$DEST" ] || fail "$DEST already exists; refusing to overwrite"
[ -f "$OWNERCFG" ] || fail "owner settings file not found: $OWNERCFG"
$SUDO sh -c "[ ! -e '$ROOTDEST' ]" || fail "$ROOTDEST already exists"

# Where the pairing database and state live comes from the owner's own settings file.
eval "$(python3 -I - "$OWNERCFG" <<'PY'
import json, shlex, sys
c = json.load(open(sys.argv[1]))
print("PAIRING=%s" % shlex.quote(str(c["pairing_db"])))
print("STATE=%s" % shlex.quote(str(c["state_dir"])))
PY
)"
[ -f "$PAIRING" ] || fail "pairing database not found at the configured path"
[ -d "$STATE" ] || fail "owner state folder not found at the configured path"

say "1. owner side -> $DEST (0700)"
install -d -m 700 "$DEST" "$DEST/owner" "$DEST/owner/state"
before=$( (sha256sum "$OWNERCFG"; find "$STATE" -type f -not -name '*.sqlite3*' -exec sha256sum {} +) | sort | sha256sum)
cp -p "$OWNERCFG" "$DEST/owner/owner.json"
copy_sqlite() {
  python3 -I - "$1" "$2" <<'PY'
import sqlite3, sys, urllib.parse
src = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(sys.argv[1]), uri=True)
dst = sqlite3.connect(sys.argv[2]); src.backup(dst)
ok = dst.execute("pragma integrity_check").fetchone()[0] == "ok"
dst.close(); src.close(); sys.exit(0 if ok else 1)
PY
}
copy_sqlite "$PAIRING" "$DEST/owner/pairing.sqlite3" || fail "could not copy the pairing database"
find "$STATE" -maxdepth 1 -type f | sort | while read -r f; do
  n=$(basename "$f")
  case "$n" in
    *.sqlite3) copy_sqlite "$f" "$DEST/owner/state/$n" || fail "could not copy $n" ;;
    *-wal|*-shm|*-journal) ;;                                   # SQLite's own side files; covered by the online backup
    *) cp -p "$f" "$DEST/owner/state/$n" ;;
  esac
done
chmod 600 "$DEST"/owner/owner.json "$DEST"/owner/*.sqlite3 "$DEST"/owner/state/* 2>/dev/null || true
{ echo "date_utc $(date -u +%FT%TZ)"; echo "package $(dpkg-query -W -f '${Version}' stynpilot 2>/dev/null || echo none)"
  echo "installer_service $(systemctl is-active stynpilot-installer 2>/dev/null || true)"
  echo "owner_service $(systemctl --user is-active stynpilot-owner 2>/dev/null || true)"; } > "$DEST/owner/INFO.txt"
chmod 600 "$DEST/owner/INFO.txt"
(cd "$DEST/owner" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS && chmod 600 SHA256SUMS)
after=$( (sha256sum "$OWNERCFG"; find "$STATE" -type f -not -name '*.sqlite3*' -exec sha256sum {} +) | sort | sha256sum)
[ "$before" = "$after" ] || fail "a live file changed while backing up"

say "2. root side -> $ROOTDEST (root-only 0700)"
$SUDO sh -c "umask 077; install -d -m 700 '$ROOTDEST'
  for n in installer.json setup-receipt.json; do
    if [ -e '$ROOTCFG_DIR'/\$n ]; then cp -p '$ROOTCFG_DIR'/\$n '$ROOTDEST'/\$n; chmod 600 '$ROOTDEST'/\$n; fi
  done
  [ -f '$ROOTDEST'/installer.json ] || { echo 'installer.json missing' >&2; exit 1; }
  cd '$ROOTDEST' && sha256sum installer.json \$(ls setup-receipt.json 2>/dev/null) > SHA256SUMS && chmod 600 SHA256SUMS
  cmp '$ROOTCFG_DIR'/installer.json '$ROOTDEST'/installer.json" || fail "root-side copy failed"
printf '%s\n' "$ROOTDEST" > "$DEST/ROOT_DEST"; chmod 600 "$DEST/ROOT_DEST"

say "3. verify"
verify "$DEST"
printf '\nOwner-side backup: %s\nRoot-side backup:  %s\nRESULT: PASS\n' "$DEST" "$ROOTDEST"
