#!/bin/sh
# Makes ONE private backup file of the current StyNpilot "Preview26" install. It copies; it never stops, changes or
# deletes anything. Run:   sudo ./backup.sh [folder]        (default folder: your home folder)
# The archive holds secrets (settings, pairing database): keep it private; it is created 0600 owned by you.
set -eu
PKG="${PREVIEW_PKG:-stynpilot-preview}"
[ "$(id -u)" = 0 ] || { echo "run with sudo (it must read root-only settings)"; exit 2; }
OWNER="${SUDO_USER:-}"; [ -n "$OWNER" ] && [ "$OWNER" != root ] || { echo "run it with sudo from your own account"; exit 2; }
OUID="$(id -u "$OWNER")"; OHOME="$(getent passwd "$OWNER" | cut -d: -f6)"
DEST="${1:-$OHOME}"
[ -d "$DEST" ] && [ ! -L "$DEST" ] || { echo "destination must be an existing folder"; exit 2; }
[ "$(stat -c %u "$DEST")" = "$OUID" ] && [ "$(( 0$(stat -c %a "$DEST") & 022 ))" = 0 ] || { echo "destination folder must be yours and not writable by others"; exit 2; }
dpkg-query -W "$PKG" >/dev/null 2>&1 || { echo "$PKG is not installed: nothing to back up"; exit 3; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/preview26-backup-$STAMP.tar"
STAGE="$(mktemp -d /var/tmp/sp-backup.XXXXXX)"; trap 'rm -rf "$STAGE"' EXIT; chmod 700 "$STAGE"
mkdir "$STAGE/files"
LIST="$STAGE/paths"; : > "$LIST"
add() { [ -e "$1" ] && printf '%s\n' "$1" >> "$LIST" || true; }
dpkg -L "$PKG" | while read -r f; do [ -f "$f" ] && ! [ -L "$f" ] && echo "$f"; done >> "$LIST" || true
dpkg -L "$PKG" | while read -r f; do [ -L "$f" ] && echo "$f"; done >> "$LIST" || true
find /etc/stynpilot -mindepth 1 \( -type f -o -type l \) 2>/dev/null >> "$LIST" || true
for g in /var/lib/stynpilot* /etc/systemd/system/*stynpilot* /etc/polkit-1/rules.d/*stynpilot* /usr/share/polkit-1/actions/*stynpilot*; do [ -d "$g" ] && find "$g" \( -type f -o -type l \) >> "$LIST" || add "$g"; done
for d in "$OHOME/.local/state/stynpilot-owner" "$OHOME/.config/stynpilot" "$OHOME/.config/systemd/user/stynpilot-"*; do
  [ -d "$d" ] && find "$d" \( -type f -o -type l \) >> "$LIST" || add "$d"; done
find "$OHOME/.config/systemd/user" -maxdepth 3 -lname '*stynpilot*' 2>/dev/null >> "$LIST" || true
sort -u "$LIST" -o "$LIST"
# consistent copy: ordinary files as they are, SQLite files through SQLite's own online-backup call
python3 - "$LIST" "$STAGE/files" <<'PY'
import os, shutil, sqlite3, sys
paths = [l.rstrip("\n") for l in open(sys.argv[1]) if l.strip()]
root = sys.argv[2]
for p in paths:
    dst = os.path.join(root, p.lstrip("/"))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.islink(p):
        os.symlink(os.readlink(p), dst); continue
    magic = open(p, "rb").read(16) if os.path.isfile(p) else b""
    if magic.startswith(b"SQLite format 3"):
        src = sqlite3.connect("file:%s?mode=ro" % p, uri=True); out = sqlite3.connect(dst)
        src.backup(out); out.close(); src.close()
        shutil.copystat(p, dst); os.chown(dst, os.stat(p).st_uid, os.stat(p).st_gid)
    else:
        shutil.copy2(p, dst); os.chown(dst, os.stat(p).st_uid, os.stat(p).st_gid)
PY
mkdir "$STAGE/meta"
dpkg-query -W -f='${Package} ${Version}\n' "$PKG" > "$STAGE/meta/package.txt"
CACHED="$(ls /var/cache/apt/archives/${PKG}_*.deb 2>/dev/null | tail -1 || true)"
if [ -n "$CACHED" ]; then cp "$CACHED" "$STAGE/meta/package.deb"
elif command -v dpkg-repack >/dev/null 2>&1; then ( cd "$STAGE/meta" && dpkg-repack "$PKG" >/dev/null 2>&1 && mv ./"${PKG}"_*.deb package.deb ) || true; fi
[ -f "$STAGE/meta/package.deb" ] || echo "NOTE: no reinstallable copy of the package could be made (sudo apt install dpkg-repack, then back up again). File-level restore still works while the package stays installed."
{ systemctl is-enabled 'stynpilot*' 2>&1; systemctl list-units 'stynpilot*' --all --no-legend --no-pager 2>&1; } > "$STAGE/meta/units-system.txt" || true
runuser -u "$OWNER" -- env XDG_RUNTIME_DIR="/run/user/$OUID" systemctl --user list-units 'stynpilot*' --all --no-legend --no-pager > "$STAGE/meta/units-user.txt" 2>&1 || true
systemctl list-units 'stynpilot*' --state=active --no-legend --plain | awk '{print $1}' | grep -v '^stynpilot-installer' > "$STAGE/meta/active-system.txt" || true
runuser -u "$OWNER" -- env XDG_RUNTIME_DIR="/run/user/$OUID" systemctl --user list-units 'stynpilot*' --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' | grep -v '^stynpilot-owner' > "$STAGE/meta/active-user.txt" || true
( cd "$STAGE/files" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum 2>/dev/null ) > "$STAGE/meta/sha256.txt"
( cd "$STAGE/files" && find . -mindepth 1 -printf '%m %u %g %y %p\n' | sort -k5 ) > "$STAGE/meta/modes.txt"
printf 'format 1\ncreated %s\npackage %s\nowner %s\n' "$STAMP" "$(cat "$STAGE/meta/package.txt")" "$OWNER" > "$STAGE/meta/INFO"
umask 077
tar --numeric-owner --xattrs -C "$STAGE" -cf "$OUT.part" files meta
mv "$OUT.part" "$OUT"; chown "$OUID:$(id -g "$OWNER")" "$OUT"; chmod 600 "$OUT"
( cd "$DEST" && sha256sum "$(basename "$OUT")" > "$OUT.sha256" ); chown "$OUID" "$OUT.sha256"; chmod 600 "$OUT.sha256"
echo "backup written: $OUT"; echo "files: $(wc -l < "$STAGE/meta/sha256.txt")   package: $(cat "$STAGE/meta/package.txt")"
echo "checksum file: $OUT.sha256   (keep BOTH somewhere off this computer too)"
