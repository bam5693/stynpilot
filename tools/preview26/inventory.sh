#!/bin/sh
# READ-ONLY: shows what the current StyNpilot "Preview26" install consists of. Prints names, modes, sizes and
# service states only - never file contents. Safe to run any time; changes nothing.
set -u
PKG="${PREVIEW_PKG:-stynpilot-preview}"
OWNER="${SUDO_USER:-$(id -un)}"
HOME_DIR="$(getent passwd "$OWNER" | cut -d: -f6)"
echo "== package"; dpkg-query -W -f='${Package} ${Version} ${db:Status-Status}\n' "$PKG" 2>&1
echo "== package files (type mode owner size path)"
dpkg -L "$PKG" 2>/dev/null | while read -r f; do [ -e "$f" ] && stat -c '%F %a %U %s %n' "$f"; done
echo "== package files changed since install (dpkg -V; blank = unchanged)"; dpkg -V "$PKG" 2>&1 | head -40
echo "== units"; systemctl list-unit-files 'stynpilot*' --no-pager 2>&1 | head -20
systemctl list-units 'stynpilot*' --all --no-pager 2>&1 | head -20
echo "== owner user units"
for u in $(systemctl --user -M "$OWNER@" list-unit-files 'stynpilot*' --no-legend 2>/dev/null | cut -d' ' -f1); do echo "$u"; done
echo "== /etc/stynpilot (mode owner size name)"; ls -la /etc/stynpilot 2>&1 | head -30
echo "== owner state and settings (mode owner size path)"
for p in "$HOME_DIR/.local/state/stynpilot-owner" "$HOME_DIR/.config/stynpilot" "$HOME_DIR/.config/systemd/user"; do
  [ -e "$p" ] && find "$p" -maxdepth 2 -name '*stynpilot*' -o -maxdepth 2 -path "$HOME_DIR/.local/state/stynpilot-owner/*" 2>/dev/null | while read -r f; do stat -c '%a %U %s %n' "$f"; done
done
echo "== other StyNpilot files"; ls -d /var/lib/stynpilot* /etc/systemd/system/*stynpilot* /etc/polkit-1/*/*stynpilot* /usr/share/polkit-1/actions/*stynpilot* 2>/dev/null
echo "== who listens on 443/18443/18444 (no payloads)"; ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E ':(443|18443|18444)$' || echo none
echo "== apt cache copies of the package"; ls -la /var/cache/apt/archives/"${PKG}"_*.deb 2>/dev/null || echo "none (restore then uses the file copy inside the backup)"
