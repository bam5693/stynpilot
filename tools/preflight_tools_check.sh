#!/bin/sh
# Disposable-machine test of preflight_backup.sh and verify_baseline.sh. Run as root in a throwaway Ubuntu chroot/VM, NEVER live:
#   preflight_tools_check.sh BASELINE.deb NEW.deb [TOOLS_DIR]
# Every assertion is mandatory: first failure prints FAIL and exits nonzero; success ends with "RESULT: PASS".
set -eu
BASE="$1"; NEW="$2"; TOOLS="${3:-$(dirname "$0")}"
export DEBIAN_FRONTEND=noninteractive
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf 'ok: %s\n' "$*"; }
refused() { d="$1"; shift; if "$@" >/tmp/out.$$ 2>&1; then cat /tmp/out.$$ >&2; fail "$d: expected a refusal"; fi; }
mark() { rm -f /tmp/INJECTED*; }
no_injection() { ls /tmp/INJECTED* >/dev/null 2>&1 && fail "INJECTION: a planted command ran ($1)" || ok "no injected command ran: $1"; }
PRE="sh $TOOLS/preflight_backup.sh"; VB="sh $TOOLS/verify_baseline.sh"

apt-get install -y --no-install-recommends --allow-downgrades "$BASE" >/dev/null 2>&1
H=/tmp/ownerhome; rm -rf $H /etc/stynpilot /var/backups/stynpilot-pre-m1-*; mkdir -p $H/.config/stynpilot $H/state /etc/stynpilot
mkstate() {
rm -f $H/pairing.sqlite3
python3 - <<PY
import sqlite3, json
for n in ("pairing", "state/requests", "state/token-revocations"):
    c = sqlite3.connect("$H/%s.sqlite3" % n); c.execute("create table t(x)"); c.execute("insert into t values('secret-row')"); c.commit(); c.close()
open("$H/state/revoked-clients.json", "w").write("[]"); open("$H/state/provisioned.json", "w").write("{}")
json.dump({"pairing_db": "$H/pairing.sqlite3", "state_dir": "$H/state", "issuer": "https://x"}, open("$H/.config/stynpilot/owner.json", "w"))
PY
}
mkstate
echo '{"r":1}' > /etc/stynpilot/installer.json; chmod 600 /etc/stynpilot/installer.json; echo '{"ok":1}' > /etc/stynpilot/setup-receipt.json
export HOME=$H

echo "== A. normal backup, permissions, re-verify, tamper detection"
$PRE $H/bk1 > /tmp/o.txt 2>&1 || { cat /tmp/o.txt; fail "backup failed"; }; tail -1 /tmp/o.txt | grep -q "RESULT: PASS" || fail "no PASS"
[ -z "$(find $H/bk1 \( -type d ! -perm 700 -o -type f ! -perm 600 \))" ] || fail "owner-side permissions"
R=$(cat $H/bk1/ROOT_DEST); [ "$(stat -c '%u %a' "$R")" = "0 700" ] || fail "root-side folder perms"
for f in owner.json pairing.sqlite3 state/requests.sqlite3 state/token-revocations.sqlite3 state/revoked-clients.json state/provisioned.json; do [ -f $H/bk1/owner/$f ] || fail "missing $f"; done
[ -f "$R/installer.json" ] && [ -f "$R/setup-receipt.json" ] || fail "root-side files missing"
ok "complete and restricted"
$PRE --verify $H/bk1 | tail -1 | grep -q PASS || fail "re-verify"
refused "overwrite" $PRE $H/bk1
cp -p $H/bk1/owner/state/revoked-clients.json /tmp/rc.bak; echo x >> $H/bk1/owner/state/revoked-clients.json
refused "owner tamper" $PRE --verify $H/bk1; cp -p /tmp/rc.bak $H/bk1/owner/state/revoked-clients.json; $PRE --verify $H/bk1 >/dev/null
sleep 1; $PRE $H/bk2 >/dev/null; R2=$(cat $H/bk2/ROOT_DEST); echo x >> $R2/installer.json
refused "root tamper" $PRE --verify $H/bk2; ok "tamper detected on both sides"

echo "== B. injection attempts through the root-side reference (an owner-writable file)"
for payload in "$R'; touch /tmp/INJECTED_quote; echo '" '$(touch /tmp/INJECTED_subst)' '`touch /tmp/INJECTED_tick`' "/var/backups/x\"; touch /tmp/INJECTED_dq; \"" \
               "$R
touch /tmp/INJECTED_newline" "$R/../../tmp" "/var/backups/../etc" "/var/backups/stynpilot-pre-m1-20260101-000000;touch /tmp/INJECTED_semi" \
               "/var/backups/stynpilot-pre-m1-2026*" "-n" "" "/etc/stynpilot"; do
  mark; printf '%s' "$payload" > $H/bk1/ROOT_DEST
  refused "hostile ROOT_DEST" $PRE --verify $H/bk1; no_injection "ROOT_DEST=$(printf %s "$payload" | head -1 | cut -c1-40)"
done
printf '%s\n' "$R" > $H/bk1/ROOT_DEST
ln -sfn /root /var/backups/stynpilot-pre-m1-20260101-000001; printf '%s\n' /var/backups/stynpilot-pre-m1-20260101-000001 > $H/bk1/ROOT_DEST
refused "symlinked root folder" $PRE --verify $H/bk1; ok "symlinked root-side folder refused"; rm -f /var/backups/stynpilot-pre-m1-20260101-000001
mkdir -m 755 /var/backups/stynpilot-pre-m1-20260101-000002; cp $R/* /var/backups/stynpilot-pre-m1-20260101-000002/; printf '%s\n' /var/backups/stynpilot-pre-m1-20260101-000002 > $H/bk1/ROOT_DEST
refused "wrong mode root folder" $PRE --verify $H/bk1; ok "root-side folder with wrong mode refused"; rm -rf /var/backups/stynpilot-pre-m1-20260101-000002
printf '%s\n' "$R" > $H/bk1/ROOT_DEST; $PRE --verify $H/bk1 >/dev/null; ok "restored valid reference verifies again"
cp $R/SHA256SUMS /tmp/sums.bak; echo "0000000000000000000000000000000000000000000000000000000000000000  /etc/shadow" >> $R/SHA256SUMS
refused "foreign path in checksum list" $PRE --verify $H/bk1; cp /tmp/sums.bak $R/SHA256SUMS; ok "unexpected checksum list refused"

echo "== C. injection through environment and paths"
mark; sleep 1; STYNPILOT_ROOT_BACKUPS="/tmp/x'; touch /tmp/INJECTED_env; '" STYNPILOT_ROOT_CONFIG_DIR="/tmp/y'; touch /tmp/INJECTED_env2; '" $PRE $H/bk3 > /tmp/o.txt 2>&1 || { cat /tmp/o.txt; fail "backup with hostile env"; }
no_injection "environment variables"; case "$(cat $H/bk3/ROOT_DEST)" in /var/backups/stynpilot-pre-m1-*) ok "environment cannot redirect the root folder" ;; *) fail "root folder redirected by environment" ;; esac
mark; sleep 1; D="$H/we'ird \"d\"; touch /tmp/INJECTED_dest #"; $PRE "$D" >/dev/null 2>&1 || fail "backup into an odd-looking owner folder"; no_injection "owner destination path"
$PRE --verify "$D" >/dev/null || fail "verify odd folder"; ok "owner folder with quotes and metacharacters handled as plain text"
mark; cp $H/.config/stynpilot/owner.json /tmp/owner.bak
for bad in '"/tmp/p; touch /tmp/INJECTED_cfg"' '"relative/path"' '"/tmp/new\nline"' '5' 'null'; do
  python3 - "$bad" <<'PY'
import json, sys
c = json.load(open("/tmp/ownerhome/.config/stynpilot/owner.json")); c["pairing_db"] = json.loads(sys.argv[1]); json.dump(c, open("/tmp/ownerhome/.config/stynpilot/owner.json", "w"))
PY
  sleep 1; refused "bad pairing_db $bad" $PRE $H/bkx; [ ! -e $H/bkx ] || fail "created output despite invalid settings"
done; no_injection "settings file values"; cp /tmp/owner.bak $H/.config/stynpilot/owner.json; ok "invalid owner settings fail closed and create nothing"

echo "== D. state layout is enforced (flat, audited)"
before_root=$(ls /var/backups | grep -c pre-m1 || true)
for case in subdir symlink unknown missing; do
  rm -rf $H/state; mkdir $H/state; mkstate
  case $case in
    subdir) mkdir $H/state/extra ;; symlink) ln -s /etc/passwd $H/state/link ;; unknown) echo x > $H/state/other.dat ;; missing) rm $H/state/provisioned.json ;;
  esac
  sleep 1; refused "state layout: $case" $PRE $H/bkl; [ ! -e $H/bkl ] || fail "owner output created for layout $case"
done
[ "$(ls /var/backups | grep -c pre-m1 || true)" = "$before_root" ] || fail "a root-side folder was created for a refused layout"
rm -rf $H/state; mkdir $H/state; mkstate; touch $H/state/requests.sqlite3-journal; sleep 1; $PRE $H/bkok >/dev/null || fail "SQLite side file wrongly refused"
ok "unexpected layouts refused before anything is written; known side files tolerated"

echo "== E. root-side source checks"
mv /etc/stynpilot/installer.json /tmp/inst.bak; ln -s /etc/shadow /etc/stynpilot/installer.json
sleep 1; refused "symlinked installer.json" $PRE $H/bks; rm /etc/stynpilot/installer.json; mv /tmp/inst.bak /etc/stynpilot/installer.json
rm -f /etc/stynpilot/setup-receipt.json; sleep 1; $PRE $H/bkn >/dev/null || fail "missing optional receipt should still back up installer.json"; ok "symlinked source refused; optional receipt tolerated"
echo '{"ok":1}' > /etc/stynpilot/setup-receipt.json

echo "== F. baseline verification"
$VB "$BASE" | tail -1 | grep -q "byte-for-byte the baseline" || fail "baseline did not verify"
U=$(dpkg -L stynpilot | grep '\.service$' | head -1); cp -p $U /tmp/u.bak; echo "# x" >> $U; refused "tampered unit" $VB "$BASE"; cp -p /tmp/u.bak $U
P=/usr/bin/stynpilot; cp -p $P /tmp/p.bak; echo "# x" >> $P; refused "tampered program" $VB "$BASE"; cp -p /tmp/p.bak $P
$VB "$BASE" >/dev/null || fail "baseline no longer verifies after restoring files"
apt-get install -y --no-install-recommends "$NEW" >/dev/null 2>&1
refused "newer version vs baseline" $VB "$BASE"; $VB "$NEW" | tail -1 | grep -q byte-for-byte || fail "new package verification"
ok "baseline verification: pass, unit/program tamper refused, version change refused"
rm -rf $H /var/backups/stynpilot-pre-m1-* /etc/stynpilot; rm -f /tmp/INJECTED*
printf '\nRESULT: PASS\n'
