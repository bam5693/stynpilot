#!/bin/sh
# Disposable-machine test of preflight_backup.sh and verify_baseline.sh (run as root in a throwaway Ubuntu chroot/VM, never live):
#   preflight_tools_check.sh BASELINE.deb NEW.deb [TOOLS_DIR]
BASE="$1"; NEW="$2"; TOOLS="${3:-$(dirname "$0")}"
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends --allow-downgrades "$BASE" >/dev/null 2>&1
H=/tmp/ownerhome; rm -rf $H /etc/stynpilot /var/backups/stynpilot-pre-m1-*; mkdir -p $H/.config/stynpilot $H/state /etc/stynpilot
python3 - <<PY
import sqlite3,json
for n in ("pairing","state/requests","state/token-revocations"):
    c=sqlite3.connect("$H/%s.sqlite3"%n); c.execute("create table t(x)"); c.execute("insert into t values('secret-row')"); c.commit(); c.close()
open("$H/state/revoked-clients.json","w").write("[]"); open("$H/state/provisioned.json","w").write("{}")
json.dump({"pairing_db":"$H/pairing.sqlite3","state_dir":"$H/state","issuer":"https://x"},open("$H/.config/stynpilot/owner.json","w"))
PY
echo '{"r":1}' > /etc/stynpilot/installer.json; chmod 600 /etc/stynpilot/installer.json; echo '{"ok":1}' > /etc/stynpilot/setup-receipt.json
export HOME=$H
echo "--- backup"; sh "$TOOLS/preflight_backup.sh" $H/bk1 | tail -6
echo "--- perms"; find $H/bk1 -printf '%m %p\n' | sort | head -20; ls -la /var/backups | grep pre-m1
echo "--- verify again"; sh "$TOOLS/preflight_backup.sh" --verify $H/bk1 | tail -2
echo "--- refuses overwrite"; sh "$TOOLS/preflight_backup.sh" $H/bk1 2>&1 | tail -1 || true
echo "--- tamper detection (owner side)"; echo x >> $H/bk1/owner/state/revoked-clients.json; sh "$TOOLS/preflight_backup.sh" --verify $H/bk1 2>&1 | tail -1 || true
echo "--- tamper detection (root side)"; sleep 1; sh "$TOOLS/preflight_backup.sh" $H/bk2 >/dev/null; echo x >> $(cat $H/bk2/ROOT_DEST)/installer.json; sh "$TOOLS/preflight_backup.sh" --verify $H/bk2 2>&1 | tail -1 || true
echo "--- baseline verify (installed = baseline)"; sh "$TOOLS/verify_baseline.sh" "$BASE" | tail -5
echo "--- tamper: unit file"; U=$(dpkg -L stynpilot | grep '\.service$' | head -1); cp $U /tmp/u.bak; echo "# x" >> $U; sh "$TOOLS/verify_baseline.sh" "$BASE" 2>&1 | tail -2 || true; cp /tmp/u.bak $U
echo "--- tamper: program file"; P=/usr/bin/stynpilot; cp $P /tmp/p.bak; echo "# x" >> $P; sh "$TOOLS/verify_baseline.sh" "$BASE" 2>&1 | tail -2 || true; cp -p /tmp/p.bak $P
echo "--- tamper: extra file in package tree"; sh "$TOOLS/verify_baseline.sh" "$BASE" | tail -1
echo "--- M1 installed vs baseline file"; apt-get install -y --no-install-recommends "$NEW" >/dev/null 2>&1; sh "$TOOLS/verify_baseline.sh" "$BASE" 2>&1 | tail -1 || true
sh "$TOOLS/verify_baseline.sh" "$NEW" | tail -1
