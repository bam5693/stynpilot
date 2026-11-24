#!/bin/sh
# Drill for tools/install_dev4.sh. Run as root in a sandbox (NEVER on the owner's computer): it installs real dev3 and
# dev4 packages into a throwaway dpkg root, fakes systemctl/doctor/the MCP endpoint, and runs the real script as an
# ordinary user through scenarios: success, failed health checks, failed restart, broken endpoint, wrong checksum,
# already installed, and a Ctrl-C mid-upgrade. Every failure after the change must end with dev3 restored byte-for-byte.
#   sh tools/install_dev4_check.sh
set -u
[ "$(id -u)" = 0 ] || { echo "run as root in a sandbox"; exit 1; }
HERE=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d /tmp/drill4.XXXXXX); chmod 755 "$T"
SHIM="$T/shim"; FAKE="$T/root"; H="$T/home"; USERNAME=nobody; PASS=0; FAILN=0
BACKUPS_BEFORE=$(ls /var/backups 2>/dev/null | grep stynpilot-pre-m1 || true)
cleanup() { [ -n "${SRVPID:-}" ] && kill "$SRVPID" 2>/dev/null; rm -f /etc/sudoers.d/zz-drill4; rm -rf /etc/stynpilot "$T"
  for d in /var/backups/stynpilot-pre-m1-*; do [ -e "$d" ] || continue; echo "$BACKUPS_BEFORE" | grep -qx "$(basename "$d")" || rm -rf "$d"; done; }
trap cleanup EXIT
ok()  { PASS=$((PASS+1)); echo "  PASS $*"; }
bad() { FAILN=$((FAILN+1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# ---- the two source commits: dev3 (pinned in the script) plus the working tree committed as the candidate ----------
git clone -q "$HERE" "$T/repo" && git -C "$T/repo" config uploadpack.allowAnySHA1InWant true
git -C "$T/repo" checkout -q -b drill
(cd "$HERE" && git ls-files -co --exclude-standard) | while read -r f; do mkdir -p "$T/repo/$(dirname "$f")"; cp -p "$HERE/$f" "$T/repo/$f"; done
git -C "$T/repo" add -A && git -C "$T/repo" -c user.email=d@d -c user.name=drill commit -q -m drill
COMMIT=$(git -C "$T/repo" rev-parse HEAD)
(umask 022; cd "$T/repo" && python3 tools/build_deb.py >/dev/null); NEWDEB=$(ls "$T"/repo/dist/stynpilot_0.1.0~dev4_all.deb)
SHA=$(sha256sum "$NEWDEB" | cut -d' ' -f1)
DEV3=859b66e901782276a97b3580a6e96f62d357f733
git -C "$T/repo" cat-file -e "$DEV3^{commit}" || { echo "dev3 commit missing from this checkout"; exit 1; }
D3DEB="$T/dev3.deb"; (umask 022; rm -rf "$T/d3" && git -C "$T/repo" worktree add -q -f "$T/d3" "$DEV3" && cd "$T/d3" && python3 tools/build_deb.py >/dev/null && cp dist/stynpilot_0.1.0~dev3_all.deb "$D3DEB")

# ---- a fake machine --------------------------------------------------------------------------------------------
mkdir -p "$SHIM" "$FAKE/var/lib/dpkg" "$H/.config/stynpilot" "$H/state" "$T/ctl" /etc/stynpilot /var/backups
: > "$FAKE/var/lib/dpkg/status"; : > "$FAKE/var/lib/dpkg/available"
echo '{"owner":"o","installer":"x"}' > /etc/stynpilot/installer.json; chmod 600 /etc/stynpilot/installer.json
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1])')
printf '{"pairing_db":"%s/pairing.sqlite3","state_dir":"%s/state","mcp_port":%s,"mcp_public_host":"mcp.example.test"}\n' "$H" "$H" "$PORT" > "$H/.config/stynpilot/owner.json"
for db in "$H/pairing.sqlite3" "$H/state/requests.sqlite3" "$H/state/token-revocations.sqlite3"; do python3 -c 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute("create table t(x)");c.commit()' "$db"; done
echo '[]' > "$H/state/revoked-clients.json"; echo '{}' > "$H/state/provisioned.json"
chown -R $USERNAME "$H"; chmod 700 "$H"
printf 'nobody ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/zz-drill4; chmod 440 /etc/sudoers.d/zz-drill4

cat > "$SHIM/sudo" <<S
#!/bin/sh
case "\$1" in -v|-n) exit 0;; esac
exec /usr/bin/sudo -n /usr/bin/env PATH="$SHIM:\$PATH" "\$@"
S
cat > "$SHIM/dpkg" <<S
#!/bin/sh
exec /usr/bin/dpkg --root=$FAKE --force-depends --no-triggers "\$@"
S
cat > "$SHIM/dpkg-query" <<S
#!/bin/sh
exec /usr/bin/dpkg-query --admindir=$FAKE/var/lib/dpkg "\$@"
S
cat > "$SHIM/systemctl" <<S
#!/bin/sh
# flags are files in $T/flags: fail_restart, down (inactive)
v=\$(/usr/bin/dpkg-query --admindir=$FAKE/var/lib/dpkg -W -f '\${Version}' stynpilot 2>/dev/null)
for a in "\$@"; do case "\$a" in
  is-active) if [ -e $T/flags/down ] && [ "\$v" = "0.1.0~dev4" ]; then echo inactive; exit 3; fi; echo active; exit 0;;
  restart) if [ -e $T/flags/fail_restart ] && [ "\$v" = "0.1.0~dev4" ]; then exit 1; fi; if [ -e $T/flags/break_endpoint ]; then if [ "\$v" = "0.1.0~dev4" ]; then touch $T/flags/endpoint_broken; else rm -f $T/flags/endpoint_broken; fi; fi; exit 0;;
esac; done; exit 0
S
cat > "$SHIM/stynpilot" <<S
#!/bin/sh
v=\$(/usr/bin/dpkg-query --admindir=$FAKE/var/lib/dpkg -W -f '\${Version}' stynpilot 2>/dev/null)
echo "doctor report (fake)"; if [ -e $T/flags/doctor_fail ] && [ "\$v" = "0.1.0~dev4" ]; then echo FAIL thing; exit 1; fi; exit \${DOCTOR_BASE:-0}
S
chmod +x "$SHIM"/*; mkdir -p "$T/flags"; chmod 755 "$T" "$SHIM"; cp "${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" "$T/ca.crt"; chmod 644 "$T/ca.crt"; chown -R nobody "$T/repo" 2>/dev/null; chmod -R a+rX "$T/shim" "$T/dev3.deb" 2>/dev/null

# a tiny MCP stand-in: 401 + WWW-Authenticate: Bearer, or 200 when the flag file says the endpoint is broken
cat > "$T/server.py" <<'PY'
import http.server, os, sys
port, flag = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if os.path.exists(flag):
            self.send_response(200); self.end_headers(); return
        self.send_response(401); self.send_header("WWW-Authenticate", 'Bearer scope="health.read"'); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$T/server.py" "$PORT" "$T/flags/endpoint_broken" & SRVPID=$!

tree() { (cd "$FAKE" && find usr/lib/stynpilot -type f -exec sha256sum {} + | sort | sha256sum); }
ver()  { /usr/bin/dpkg-query --admindir="$FAKE/var/lib/dpkg" -W -f '${Version}' stynpilot 2>/dev/null || echo none; }
reset_to_dev3() { /usr/bin/dpkg --root="$FAKE" --force-depends --no-triggers --force-downgrade -i "$D3DEB" >/dev/null 2>&1; rm -f "$T"/flags/*; rm -rf "$H/stynpilot-releases" "$H/stynpilot-upgrade-logs" "$H"/stynpilot-pre-dev4-*; }
run() {   # $@ = script args; prints the script output; extra env via ENVV
  su -s /bin/sh "$USERNAME" -c "cd $H && HOME=$H HTTPS_PROXY=${HTTPS_PROXY:-} https_proxy=${https_proxy:-} SSL_CERT_FILE=$T/ca.crt PIP_CERT=$T/ca.crt REQUESTS_CA_BUNDLE=$T/ca.crt PIP_CONFIG_FILE=/dev/null PATH=$SHIM:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin STYNPILOT_REPO=$T/repo STYNPILOT_HEALTH_WAIT=${WAIT:-6} XDG_RUNTIME_DIR=/tmp sh $HERE/tools/install_dev4.sh $*" 2>&1
}

reset_to_dev3; BASE=$(tree)
if [ "${ONLY:-}" != 6 ]; then
echo "[1] success"
OUT=$(run "$COMMIT" "$SHA"); echo "$OUT" | tail -12
check "result SUCCESS" 'echo "$OUT" | grep -q "^RESULT: SUCCESS"'
check "dev4 installed" '[ "$(ver)" = 0.1.0~dev4 ]'
check "program files changed" '[ "$(tree)" != "$BASE" ]'
check "settings untouched" 'grep -q installer /etc/stynpilot/installer.json'
check "backups verified exist" 'ls -d $H/stynpilot-pre-dev4-* >/dev/null'
check "rollback package kept" '[ -f $H/stynpilot-releases/stynpilot_0.1.0~dev3_all.deb ] && [ -f $H/stynpilot-releases/stynpilot_0.1.0~dev4_all.deb ]'
check "log written" 'ls $H/stynpilot-upgrade-logs/dev4-*.log >/dev/null'

echo "[2] already installed -> verify only"
OUT=$(run "$COMMIT" "$SHA"); check "nothing changed" 'echo "$OUT" | grep -q "^RESULT: OK. dev4 is installed"'

for scenario in doctor_fail down fail_restart break_endpoint; do
  echo "[3] health problem after install: $scenario"
  reset_to_dev3; BASE=$(tree); touch "$T/flags/$scenario"
  OUT=$(run "$COMMIT" "$SHA"); echo "$OUT" | tail -4
  rm -f "$T/flags/$scenario"
  check "$scenario: rolled back" 'echo "$OUT" | grep -q "^RESULT: ROLLED BACK"'
  check "$scenario: dev3 restored" '[ "$(ver)" = 0.1.0~dev3 ]'
  check "$scenario: program files byte-identical to before" '[ "$(tree)" = "$BASE" ]'
done
# the "down" / "fail_restart" flags only bite once dev4 is in; the flags above are cleared before the check re-runs,
# so a failed rollback check would show NEEDS HELP instead.

echo "[4] wrong checksum -> nothing changes"
reset_to_dev3; BASE=$(tree)
OUT=$(run "$COMMIT" 0000000000000000000000000000000000000000000000000000000000000000); echo "$OUT" | tail -3
check "refused before any change" 'echo "$OUT" | grep -q "STOPPED BEFORE ANY CHANGE" && [ "$(ver)" = 0.1.0~dev3 ] && [ "$(tree)" = "$BASE" ]'

echo "[5] root account is refused"
OUT=$(sh "$HERE/tools/install_dev4.sh" "$COMMIT" "$SHA" 2>&1 | head -3); check "refused" 'echo "$OUT" | grep -q "not root"'

fi
echo "[6] Ctrl-C during the health wait -> rolled back"
reset_to_dev3; BASE=$(tree); touch "$T/flags/down"; WAIT=60 run "$COMMIT" "$SHA" >"$T/int.out" 2>&1 &
RP=$!; i=0; while [ $i -lt 60 ]; do [ "$(ver)" = 0.1.0~dev4 ] && break; sleep 1; i=$((i+1)); done; sleep 3
pkill -TERM -f "^sh .*install_dev4.sh $COMMIT"; wait $RP 2>/dev/null
i=0; while [ $i -lt 150 ] && pgrep -f "install_dev4.sh $COMMIT" >/dev/null; do sleep 1; i=$((i+1)); done; rm -f "$T/flags/down"
tail -3 "$T/int.out" | cut -c1-160
check "interrupted: dev3 restored" '[ "$(ver)" = 0.1.0~dev3 ] && [ "$(tree)" = "$BASE" ]'
check "interrupted: says rolled back" 'grep -q "ROLLED BACK" "$T/int.out"'

echo; echo "drill: $PASS passed, $FAILN failed"; [ "$FAILN" = 0 ]
