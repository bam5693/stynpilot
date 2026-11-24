#!/bin/sh
# Pre-upgrade protection of what StyNpilot keeps OUTSIDE `stynpilot backup` / `root-backup`:
#   owner side (no root): owner settings file owner.json (AI-endpoint/Auth0 connection settings on this machine), the
#                         existing device pairing database, and the owner state folder (approval/request history,
#                         revocations, provisioned marker);
#   root side (sudo):     /etc/stynpilot/installer.json and setup-receipt.json -> a root-only folder under /var/backups.
#
# Safety rules (reviewed; regression-tested in tools/preflight_tools_check.sh):
# * No path or value is ever placed inside privileged shell source. Root work is a FIXED script that receives its one
#   variable (the backup folder) as a positional argument, and re-validates it itself against a strict pattern.
# * The root folder is ALWAYS /var/backups/stynpilot-pre-m1-YYYYMMDD-HHMMSS (no environment override). The root-side
#   name stored in the owner folder is untrusted text: it is only used if it matches that pattern, and root then also
#   requires the folder to be a real (non-symlink) directory owned by root with mode 700 holding only expected files.
# * Root-side sources must be regular, non-symlink files owned by root; the folder is created with mkdir (fails if it exists).
# * The owner state folder must have the audited FLAT layout (exactly the four files StyNpilot creates, plus SQLite's own
#   -journal/-wal/-shm side files). Anything else (subfolder, symlink, unknown file, missing file) -> refuse, change nothing.
# * Read-only on live files. SQLite files are copied with SQLite's online-backup call from a read-only connection and
#   integrity-checked; for them "unchanged" cannot be hashed, so that claim covers only owner.json and the JSON state
#   files (checked before/after). New folders only (0700, files 0600). Contents are never printed.
#
#   preflight_backup.sh [OWNER_DEST]           make the backups and verify them
#   preflight_backup.sh --verify OWNER_DEST    re-verify an earlier backup (owner side and its root-side twin)
set -eu
umask 077
OWNERCFG="${STYNPILOT_OWNER_CONFIG:-$HOME/.config/stynpilot/owner.json}"
if [ "$(id -u)" = 0 ]; then SUDO=""; else SUDO="sudo"; fi
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
say() { printf '== %s\n' "$*"; }
ROOT_PATTERN_OK() {   # strict, fixed shape; no other characters can pass
  case "$1" in
    /var/backups/stynpilot-pre-m1-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) return 0 ;;
    *) return 1 ;;
  esac
}

# ---- FIXED privileged scripts: the folder arrives as $1 and is validated again here --------------------------------
ROOT_MAKE='set -eu; umask 077
R="$1"; C=/etc/stynpilot
case "$R" in /var/backups/stynpilot-pre-m1-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) echo "bad folder" >&2; exit 1;; esac
[ -d /var/backups ] && [ ! -L /var/backups ] || { echo "bad /var/backups" >&2; exit 1; }
[ -d "$C" ] && [ ! -L "$C" ] && [ "$(stat -c %u "$C")" = 0 ] || { echo "bad settings folder" >&2; exit 1; }
for n in installer.json setup-receipt.json; do
  if [ -e "$C/$n" ] || [ -L "$C/$n" ]; then
    [ -f "$C/$n" ] && [ ! -L "$C/$n" ] && [ "$(stat -c %u "$C/$n")" = 0 ] || { echo "unexpected $n" >&2; exit 1; }
  fi
done
[ -f "$C/installer.json" ] || { echo "installer.json missing" >&2; exit 1; }
mkdir -m 700 -- "$R"
for n in installer.json setup-receipt.json; do
  if [ -f "$C/$n" ]; then cp -- "$C/$n" "$R/$n"; chmod 600 -- "$R/$n"; fi
done
cd -- "$R"
if [ -f setup-receipt.json ]; then sha256sum installer.json setup-receipt.json > SHA256SUMS; else sha256sum installer.json > SHA256SUMS; fi
chmod 600 SHA256SUMS
cmp -- "$C/installer.json" installer.json'
ROOT_VERIFY='set -eu
R="$1"
case "$R" in /var/backups/stynpilot-pre-m1-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) echo "bad folder" >&2; exit 1;; esac
[ -d "$R" ] && [ ! -L "$R" ] || { echo "not a real folder" >&2; exit 1; }
[ "$(stat -c "%u %a" -- "$R")" = "0 700" ] || { echo "folder is not root-only 0700" >&2; exit 1; }
cd -- "$R"
[ -z "$(find . -mindepth 1 \( ! -type f -o ! -perm 600 -o ! -user root \) -print)" ] || { echo "unexpected entries or permissions" >&2; exit 1; }
[ -z "$(find . -mindepth 1 -type f ! -name SHA256SUMS ! -name installer.json ! -name setup-receipt.json -print)" ] || { echo "unexpected files" >&2; exit 1; }
[ -z "$(grep -Ev "^[0-9a-f]{64}  (installer|setup-receipt)\.json$" SHA256SUMS)" ] || { echo "unexpected checksum list" >&2; exit 1; }
sha256sum -c --quiet SHA256SUMS'

verify() {
  D="$1"; [ -d "$D/owner" ] && [ ! -L "$D" ] || fail "not a preflight backup folder"
  [ -f "$D/ROOT_DEST" ] && [ ! -L "$D/ROOT_DEST" ] || fail "root-side reference missing"
  R=$(head -c 200 "$D/ROOT_DEST")
  ROOT_PATTERN_OK "$R" || fail "root-side folder name is not the expected form; refusing to use it"
  (cd "$D/owner" && sha256sum -c --quiet SHA256SUMS) || fail "owner-side checksum mismatch"
  [ -z "$(find "$D" \( -type d ! -perm 700 -o -type f ! -perm 600 -o -type l \) -print)" ] || fail "owner-side folder has unexpected permissions or links"
  for f in pairing.sqlite3 state/requests.sqlite3 state/token-revocations.sqlite3; do
    [ -f "$D/owner/$f" ] || fail "missing $f"
    python3 -I -c 'import sqlite3,sys; c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro", uri=True); r=c.execute("pragma integrity_check").fetchone()[0]; sys.exit(0 if r=="ok" else 1)' "$(cd "$D/owner" && pwd -P)/$f" || fail "SQLite integrity check failed: $f"
  done
  $SUDO sh -c "$ROOT_VERIFY" sh "$R" || fail "root-side verification failed"
  say "verified: $D and $R"
}

if [ "${1:-}" = "--verify" ]; then verify "${2:?owner backup folder required}"; echo "RESULT: PASS (verify)"; exit 0; fi

TS=$(date +%Y%m%d-%H%M%S)
DEST="${1:-$HOME/stynpilot-pre-m1-$TS}"
ROOTDEST="/var/backups/stynpilot-pre-m1-$TS"
ROOT_PATTERN_OK "$ROOTDEST" || fail "internal: root folder name not in the expected form"
[ ! -e "$DEST" ] && [ ! -L "$DEST" ] || fail "$DEST already exists; refusing to overwrite"
[ -f "$OWNERCFG" ] && [ ! -L "$OWNERCFG" ] || fail "owner settings file not found (or is a link): $OWNERCFG"

# Locations come from the owner's own settings file; validated (absolute, no control characters) before use.
{ IFS= read -r PAIRING; IFS= read -r STATE; } <<EOP || fail "owner settings file is not valid"
$(python3 -I - "$OWNERCFG" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
for key in ("pairing_db", "state_dir"):
    v = c[key]
    if not isinstance(v, str) or not v.startswith("/") or any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        sys.exit("bad " + key)
    print(v)
PY
)
EOP
[ -f "$PAIRING" ] && [ ! -L "$PAIRING" ] || fail "pairing database not found at the configured path (or is a link)"
[ -d "$STATE" ] && [ ! -L "$STATE" ] || fail "owner state folder not found at the configured path (or is a link)"

# Audited FLAT state layout: exactly the four files StyNpilot creates (+ SQLite side files). Anything else: refuse.
for n in requests.sqlite3 revoked-clients.json token-revocations.sqlite3 provisioned.json; do
  [ -f "$STATE/$n" ] && [ ! -L "$STATE/$n" ] || fail "expected state file missing or not a plain file: $n"
done
odd=$(find "$STATE" -mindepth 1 \( ! -type f -o -type l \) -print -o -type f ! \( -name requests.sqlite3 -o -name requests.sqlite3-journal -o -name requests.sqlite3-wal -o -name requests.sqlite3-shm -o -name token-revocations.sqlite3 -o -name token-revocations.sqlite3-journal -o -name token-revocations.sqlite3-wal -o -name token-revocations.sqlite3-shm -o -name revoked-clients.json -o -name provisioned.json \) -print | head -3)
[ -z "$odd" ] || fail "owner state folder has an unexpected layout (subfolder, link or unknown file); not backing up. Ask for review."

say "1. owner side -> $DEST (0700)"
install -d -m 700 "$DEST" "$DEST/owner" "$DEST/owner/state"
sums() { (sha256sum "$OWNERCFG" "$STATE/revoked-clients.json" "$STATE/provisioned.json") | sha256sum; }
before=$(sums)
cp -p -- "$OWNERCFG" "$DEST/owner/owner.json"
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
for n in requests.sqlite3 token-revocations.sqlite3; do copy_sqlite "$STATE/$n" "$DEST/owner/state/$n" || fail "could not copy $n"; done
for n in revoked-clients.json provisioned.json; do cp -p -- "$STATE/$n" "$DEST/owner/state/$n"; done
chmod 600 -- "$DEST"/owner/owner.json "$DEST"/owner/pairing.sqlite3 "$DEST"/owner/state/*
{ echo "date_utc $(date -u +%FT%TZ)"; echo "package $(dpkg-query -W -f '${Version}' stynpilot 2>/dev/null || echo none)"
  echo "installer_service $(systemctl is-active stynpilot-installer 2>/dev/null || true)"
  echo "owner_service $(systemctl --user is-active stynpilot-owner 2>/dev/null || true)"; } > "$DEST/owner/INFO.txt"
chmod 600 "$DEST/owner/INFO.txt"
(cd "$DEST/owner" && find . -type f ! -name SHA256SUMS | sort | xargs -d '\n' sha256sum > SHA256SUMS && chmod 600 SHA256SUMS)
[ "$before" = "$(sums)" ] || fail "a live settings or JSON file changed while backing up"

say "2. root side -> $ROOTDEST (root-only 0700)"
$SUDO sh -c "$ROOT_MAKE" sh "$ROOTDEST" || fail "root-side backup failed (nothing was overwritten)"
printf '%s\n' "$ROOTDEST" > "$DEST/ROOT_DEST"; chmod 600 "$DEST/ROOT_DEST"

say "3. verify"
verify "$DEST"
printf '\nOwner-side backup: %s\nRoot-side backup:  %s\nRESULT: PASS\n' "$DEST" "$ROOTDEST"
