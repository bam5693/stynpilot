#!/bin/sh
# Prove that the saved baseline .deb IS what is installed: same version, and every file the package ships (programs,
# helper, systemd units, polkit policy, desktop entries, docs) exists on this machine with identical bytes and mode,
# and the installed package ships no file the baseline does not. Read-only. Any difference -> FAIL and nonzero exit.
#   verify_baseline.sh /path/to/baseline.deb
# Limits (stated plainly): it checks what the PACKAGE installed. It does not see files created later by setup or
# running (settings, state: those are protected by preflight_backup.sh), nor can it prove nothing else on the machine
# was hand-edited outside the package's files. `dpkg --verify` is also run for packaged conffiles.
set -eu
DEB="${1:?path to baseline .deb required}"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
[ -f "$DEB" ] || fail "no such file"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
echo "baseline sha256 $(sha256sum "$DEB" | cut -d' ' -f1)"
[ "$(dpkg-deb -f "$DEB" Package)" = stynpilot ] || fail "not a stynpilot package"
WANT=$(dpkg-deb -f "$DEB" Version); HAVE=$(dpkg-query -W -f '${Version}' stynpilot 2>/dev/null) || fail "stynpilot is not installed"
[ "$WANT" = "$HAVE" ] || fail "installed version $HAVE differs from the baseline $WANT"
dpkg-deb -x "$DEB" "$T/x"
(cd "$T/x" && find . \( -type f -o -type l \) | sed 's|^\.||' | sort) > "$T/packaged"
dpkg -L stynpilot | while read -r p; do [ -f "$p" ] || [ -L "$p" ] && echo "$p"; done | sort > "$T/installed"
echo "files in baseline: $(wc -l < "$T/packaged"); files installed by the package: $(wc -l < "$T/installed")"
extra=$(comm -13 "$T/packaged" "$T/installed"); [ -z "$extra" ] || fail "installed package ships files the baseline does not: $(echo "$extra" | head -3 | tr '\n' ' ')"
bad=0
while read -r p; do
  [ -e "$p" ] || [ -L "$p" ] || { echo "MISSING $p"; bad=1; continue; }
  if [ -L "$T/x$p" ]; then [ "$(readlink "$T/x$p")" = "$(readlink "$p")" ] || { echo "LINK DIFFERS $p"; bad=1; }; continue; fi
  cmp -s "$T/x$p" "$p" || { echo "BYTES DIFFER $p"; bad=1; }
  [ "$(stat -c %a "$T/x$p")" = "$(stat -c %a "$p")" ] || { echo "MODE DIFFERS $p"; bad=1; }
done < "$T/packaged"
[ "$bad" = 0 ] || fail "installed files differ from the baseline package (see above); do NOT upgrade until this is understood"
units=$(grep -c 'systemd' "$T/packaged" || true); echo "systemd/unit-related files compared: $units"
dpkg --verify stynpilot || fail "dpkg --verify reports changes"
echo "RESULT: PASS the installed stynpilot $HAVE is byte-for-byte the baseline package"
