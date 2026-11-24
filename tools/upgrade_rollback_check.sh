#!/bin/sh
# Disposable-machine check of the UPGRADE and the ROLLBACK of the .deb itself. Run as root inside a throwaway
# Ubuntu chroot/VM (never on the live Ryzen):  upgrade_rollback_check.sh BASELINE.deb NEW.deb
# Proves: upgrading keeps every config/state/pairing file byte-for-byte, starts/enables nothing, and installing
# the baseline .deb again (downgrade) restores the old program and again leaves all state untouched.
set -eu
OLD="$1"; NEW="$2"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ver() { dpkg-query -W -f '${Version}' stynpilot; }
program_hash() { (cd /usr/lib/stynpilot && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1); }
state_hash() { find /etc/stynpilot /var/lib/stynpilot-installer /home/nobody-state -type f -o -type l 2>/dev/null | sort | xargs -r sha256sum | sha256sum | cut -d' ' -f1; }
modes() { find /etc/stynpilot /var/lib/stynpilot-installer /home/nobody-state -printf '%p %m %U\n' 2>/dev/null | sort | sha256sum | cut -d' ' -f1; }
units() { ls /etc/systemd/system/multi-user.target.wants /etc/systemd/user/default.target.wants 2>/dev/null | grep -c stynpilot || true; }
export DEBIAN_FRONTEND=noninteractive

printf '== 1. install the baseline (currently installed) package\n'
apt-get install -y --no-install-recommends --allow-downgrades "$OLD" >/dev/null 2>&1 || fail "baseline did not install"
OLDVER=$(ver); OLDPROG=$(program_hash); echo "baseline $OLDVER"

printf '== 2. create realistic owner state (settings, pairing DB, approvals, request history, installer state)\n'
mkdir -p /etc/stynpilot /var/lib/stynpilot-installer/snapshots /home/nobody-state/.config/stynpilot /home/nobody-state/.local/state/stynpilot
printf '{"owner":"x"}' > /etc/stynpilot/installer.json; chmod 600 /etc/stynpilot/installer.json
printf '{"receipt":1}' > /etc/stynpilot/setup-receipt.json
printf 'ledger' > /var/lib/stynpilot-installer/installs.sqlite3; chmod 600 /var/lib/stynpilot-installer/installs.sqlite3
printf 'snap'   > /var/lib/stynpilot-installer/snapshots/a
printf 'config' > /home/nobody-state/.config/stynpilot/owner.json
printf 'pairing' > /home/nobody-state/.local/state/stynpilot/pairing.sqlite3
printf 'requests' > /home/nobody-state/.local/state/stynpilot/requests.sqlite3
STATE=$(state_hash); MODES=$(modes); echo "state $STATE"

printf '== 3. upgrade to the new package\n'
apt-get install -y --no-install-recommends "$NEW" >/dev/null 2>&1 || fail "upgrade failed"
NEWVER=$(ver); [ "$NEWVER" != "$OLDVER" ] || fail "new package has the same version as the baseline ($NEWVER)"
dpkg --compare-versions "$NEWVER" gt "$OLDVER" || fail "new version is not newer"
[ "$(state_hash)" = "$STATE" ] || fail "upgrade changed owner state/config"
[ "$(modes)" = "$MODES" ] || fail "upgrade changed state permissions/ownership"
[ "$(units)" = "0" ] || fail "upgrade enabled a StyNpilot unit"
[ "$(program_hash)" != "$OLDPROG" ] || fail "program files did not change"
NEWPROG=$(program_hash); echo "upgraded $OLDVER -> $NEWVER"

printf '== 4. roll back: install the saved baseline package over it\n'
apt-get install -y --no-install-recommends --allow-downgrades "$OLD" >/dev/null 2>&1 || fail "rollback install failed"
[ "$(ver)" = "$OLDVER" ] || fail "rollback did not restore the baseline version"
[ "$(program_hash)" = "$OLDPROG" ] || fail "rollback did not restore the baseline program byte-for-byte"
[ "$(state_hash)" = "$STATE" ] || fail "rollback changed owner state/config"
[ "$(modes)" = "$MODES" ] || fail "rollback changed state permissions/ownership"
[ "$(units)" = "0" ] || fail "rollback enabled a StyNpilot unit"
/usr/bin/stynpilot version >/dev/null 2>&1 || fail "baseline program does not run after rollback"

printf '== 5. upgrade again (repeatable)\n'
apt-get install -y --no-install-recommends "$NEW" >/dev/null 2>&1 || fail "second upgrade failed"
[ "$(program_hash)" = "$NEWPROG" ] && [ "$(state_hash)" = "$STATE" ] || fail "second upgrade differs"
rm -rf /home/nobody-state
printf '\nRESULT: PASS upgrade %s -> %s, rollback to %s, re-upgrade; state untouched\n' "$OLDVER" "$NEWVER" "$OLDVER"
