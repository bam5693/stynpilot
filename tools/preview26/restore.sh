#!/bin/sh
# Puts the files from a backup.sh archive back exactly as they were. DRY RUN unless you add --really.
#   sudo ./restore.sh ARCHIVE            shows what would change
#   sudo ./restore.sh ARCHIVE --really   stops Preview26's services, restores, starts what was running before
# It only touches paths listed in the backup, never follows links out of them, and never removes the NEW StyNpilot.
set -eu
PKG="${PREVIEW_PKG:-stynpilot-preview}"
ARCH="${1:-}"; MODE="${2:-}"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }
[ -n "$ARCH" ] && [ -f "$ARCH" ] && [ ! -L "$ARCH" ] || { echo "give the backup archive file"; exit 2; }
OWNER="${SUDO_USER:-}"; [ -n "$OWNER" ] && [ "$OWNER" != root ] || { echo "run it with sudo from your own account"; exit 2; }
OUID="$(id -u "$OWNER")"
[ "$(stat -c %u "$ARCH")" = "$OUID" ] && [ "$(( 0$(stat -c %a "$ARCH") & 077 ))" = 0 ] || { echo "the archive must be yours and private (mode 600)"; exit 2; }
if [ -f "$ARCH.sha256" ]; then ( cd "$(dirname "$ARCH")" && sha256sum -c "$(basename "$ARCH").sha256" >/dev/null ) || { echo "CHECKSUM MISMATCH: archive was changed or damaged"; exit 4; }; else echo "WARNING: no .sha256 file next to the archive; integrity not checked"; fi
STAGE="$(mktemp -d /var/tmp/sp-restore.XXXXXX)"; trap 'rm -rf "$STAGE"' EXIT; chmod 700 "$STAGE"
# member names must be plain relative paths under files/ or meta/ (no .. , no absolute, no device nodes)
tar -tf "$ARCH" | awk '$0 !~ /^(files|meta)(\/|$)/ || $0 ~ /(^|\/)\.\.(\/|$)/ {bad=1} END{exit bad}' || { echo "archive has unexpected paths: refusing"; exit 4; }
tar --numeric-owner --xattrs -C "$STAGE" -xf "$ARCH" --no-same-permissions --warning=no-timestamp 2>/dev/null || tar --numeric-owner -C "$STAGE" -xf "$ARCH"
[ -d "$STAGE/files" ] && [ -f "$STAGE/meta/sha256.txt" ] || { echo "not a Preview26 backup"; exit 4; }
( cd "$STAGE/files" && sha256sum -c ../meta/sha256.txt >/dev/null ) || { echo "files inside the archive do not match its own list: refusing"; exit 4; }
# only paths the backup tool could have produced
( cd "$STAGE/files" && find . -mindepth 1 \( -type f -o -type l \) | sed 's#^\.##' ) > "$STAGE/targets"
while read -r t; do
  # exact paths the package itself owns (recorded at backup time) are always allowed
  if [ -f "$STAGE/meta/package-files.txt" ] && grep -qxF -- "$t" "$STAGE/meta/package-files.txt"; then continue; fi
  case "$t" in /usr/share/stynpilot-*/*|/usr/lib/stynpilot-*/*|/usr/share/stynpilot-preview/*|/usr/lib/systemd/*stynpilot*|/usr/lib/stynpilot-preview/*|/usr/lib/systemd/*/stynpilot*|/usr/share/doc/stynpilot-preview/*|/usr/bin/stynpilot-*|/usr/share/polkit-1/actions/*stynpilot*|/etc/stynpilot/*|/var/lib/stynpilot*|/etc/systemd/system/*stynpilot*|/etc/polkit-1/rules.d/*stynpilot*|/home/*/.local/state/stynpilot-owner/*|/home/*/.config/stynpilot/*|/home/*/.config/systemd/user/*stynpilot*|/usr/share/applications/*stynpilot*|/usr/libexec/stynpilot*|/usr/sbin/stynpilot*) ;;
    *) echo "outside the allowed StyNpilot locations: $t"; exit 4 ;; esac
done < "$STAGE/targets"
echo "backup: $(cat "$STAGE/meta/INFO" | tr '\n' ' ')"
echo "files in backup: $(wc -l < "$STAGE/targets")"
CHANGED=0; MISSING=0
while read -r t; do
  if [ ! -e "$t" ] && [ ! -L "$t" ]; then MISSING=$((MISSING+1)); echo "  missing now : $t"
  elif [ -f "$STAGE/files$t" ] && ! cmp -s "$STAGE/files$t" "$t"; then CHANGED=$((CHANGED+1)); echo "  differs now : $t"; fi
done < "$STAGE/targets"
echo "summary: $MISSING missing, $CHANGED different, rest identical"
[ "$MODE" = "--really" ] || { echo "DRY RUN: nothing was changed. Add --really to restore."; exit 0; }
BEFORE_SYS="$(cat "$STAGE/meta/active-system.txt" 2>/dev/null || true)"          # what was running when the backup was made
BEFORE_USER="$(cat "$STAGE/meta/active-user.txt" 2>/dev/null || true)"
for u in $BEFORE_USER; do runuser -u "$OWNER" -- env XDG_RUNTIME_DIR="/run/user/$OUID" systemctl --user stop "$u" || true; done
for u in $BEFORE_SYS; do systemctl stop "$u" || true; done
if ! dpkg-query -W -f='${db:Status-Status}' "$PKG" 2>/dev/null | grep -qx installed; then
  [ -f "$STAGE/meta/package.deb" ] || { echo "the package is not installed and the backup has no copy of it: reinstall it first, then run this again"; exit 5; }
  dpkg -i "$STAGE/meta/package.deb" >/dev/null
  echo "reinstalled $PKG from the copy inside the backup"
fi
( cd "$STAGE/files" && find . \( -type f -o -type l \) -print0 | tar --null -T - --no-recursion --numeric-owner --xattrs -cf - ) | tar --numeric-owner --xattrs -C / -xf - --overwrite
# a restored SQLite file must stand alone: remove stale write-ahead/journal companions, then check it opens cleanly
python3 - "$STAGE/targets" <<'PY'
import os, sqlite3, sys
bad = []
for t in (l.rstrip("\n") for l in open(sys.argv[1])):
    if os.path.isfile(t) and not os.path.islink(t) and open(t, "rb").read(16).startswith(b"SQLite format 3"):
        for s in ("-wal", "-shm", "-journal"):
            if os.path.lexists(t + s):
                os.unlink(t + s)
        db = sqlite3.connect("file:%s?mode=ro" % t, uri=True)
        ok = db.execute("PRAGMA integrity_check").fetchone()[0]
        db.close()
        if ok != "ok":
            bad.append(t)
if bad:
    sys.exit("restored database(s) failed their integrity check: %s" % bad)
PY
OGRP="$(id -g "$OWNER")"; OHOME="$(getent passwd "$OWNER" | cut -d: -f6)"
for d in "$OHOME/.local/state/stynpilot-owner" "$OHOME/.config/stynpilot"; do [ -d "$d" ] && chown -R "$OUID:$OGRP" "$d" || true; done
systemctl daemon-reload; runuser -u "$OWNER" -- env XDG_RUNTIME_DIR="/run/user/$OUID" systemctl --user daemon-reload || true
for u in $BEFORE_SYS; do systemctl start "$u" || echo "could not start $u"; done
for u in $BEFORE_USER; do runuser -u "$OWNER" -- env XDG_RUNTIME_DIR="/run/user/$OUID" systemctl --user start "$u" || echo "could not start $u"; done
echo "restored. Verify with:  sh inventory.sh"
