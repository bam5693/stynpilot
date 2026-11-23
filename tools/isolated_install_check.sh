#!/bin/sh
# Disposable-machine acceptance check for the .deb. Run as root INSIDE a throwaway Ubuntu 26.04 chroot/VM/container
# (never on the live Ryzen).  Usage: isolated_install_check.sh /path/to/stynpilot_X_all.deb /path/to/repo/tests
# EVERY assertion is mandatory: the first one that is false prints FAIL and the script exits nonzero. The last line
# is "RESULT: PASS <deb sha256>" and exit status 0 only if all of them held.
# Self-test: SP_INJECT=<name> deliberately breaks one invariant; the script must then FAIL (see tests/test_g7.py).
set -eu
export PYTHONDONTWRITEBYTECODE=1
DEB="$1"; TESTS="$2"; U=nobody; UIDN=$(id -u $U); INJECT="${SP_INJECT:-}"
OUT=$(mktemp); trap 'rm -f "$OUT"' EXIT
say() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
inject() { [ "$INJECT" = "$1" ]; }
assert_absent() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "$2 ($1 exists)"; }
assert_present() { [ -e "$1" ] || fail "$2 ($1 missing)"; }
assert_ok() { d="$1"; shift; "$@" >"$OUT" 2>&1 || { cat "$OUT" >&2; fail "$d (exit $?)"; }; cat "$OUT"; }
assert_refused() { d="$1"; shift; if "$@" >"$OUT" 2>&1; then cat "$OUT" >&2; fail "$d: expected a refusal but it succeeded"; fi; cat "$OUT"; }
assert_said() { grep -q -- "$1" "$OUT" || { cat "$OUT" >&2; fail "$2: expected output containing '$1'"; }; }
H=/tmp/spcheck
as_user() { setpriv --reuid=$U --regid=nogroup --clear-groups env HOME="$H" "$@"; }
helper() { PKEXEC_UID=$UIDN /usr/libexec/stynpilot/root-helper "$@"; }

say "0. start from a clean machine; package hash"
HASH=$(sha256sum "$DEB" | cut -d' ' -f1); echo "deb sha256 $HASH"
rm -rf "$H" /etc/stynpilot /var/lib/stynpilot-installer /etc/systemd/system/multi-user.target.wants/stynpilot-installer.service
mkdir -p "$H"; chown $U "$H"; chmod 700 "$H"
inject enable_unit && { mkdir -p /etc/systemd/system/multi-user.target.wants; ln -s /usr/lib/systemd/system/stynpilot-installer.service /etc/systemd/system/multi-user.target.wants/stynpilot-installer.service; }
inject etc_created && mkdir -p /etc/stynpilot
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$DEB" >/dev/null 2>&1 || fail "package did not install"

say "1. installing started/enabled/created nothing"
assert_absent /etc/systemd/system/multi-user.target.wants/stynpilot-installer.service "no system unit enabled"
assert_absent /etc/systemd/user/default.target.wants/stynpilot-owner.service "no user unit enabled"
assert_absent /etc/stynpilot "no system configuration created"
assert_absent /var/lib/stynpilot-installer "no installer state created"
assert_present /usr/bin/stynpilot "program installed"
assert_present /usr/libexec/stynpilot/root-helper "root helper installed"

say "2. doctor before setup (read-only)"
assert_ok "doctor runs before setup" as_user /usr/bin/stynpilot doctor
assert_said "not set up yet" "doctor reports setup missing"
assert_absent "$H/.config/stynpilot" "doctor created nothing"

say "3. first-run setup as the owner (interrupted at every stage, then resumed)"
as_user python3 -IB - <<PY || fail "setup scenario"
import sys, time, os
sys.path[:0] = ["/usr/lib/stynpilot/lib", "/usr/lib/stynpilot/vendor", "$TESTS"]
from pathlib import Path
from legacy_pairing import make_pairing_db
from stynpilot.identity import account_id
from stynpilot import setup_wizard
from stynpilot.service import ConfigError
H = Path("$H")
owner = account_id(verified_issuer="https://tenant.example.auth/", verified_subject="auth0|fixture")
make_pairing_db(H / ".local/state/stynpilot-owner", [("dtdev_FIXTUREdevice", owner, time.time() + 3600, None, ["workspace.propose"])])
pdb = H / ".local/state/stynpilot-owner/pairing.sqlite3"
if not pdb.exists():
    pdb = next(p for p in (H / ".local/state/stynpilot-owner").iterdir() if p.suffix in (".db", ".sqlite3"))
assert setup_wizard.discover_pairing_db(H) == str(pdb), "pairing database not auto-discovered"
form = {"issuer": "tenant.example.auth", "approval_client_id": "approval-app", "approval_public_host": "pc.example.test:8444",
        "mcp_public_host": "pc.example.test", "pairing_db": str(pdb), "chatgpt_client_id": "cg", "claude_client_id": "cl"}
status = setup_wizard.resume_setup(form, H, $UIDN)
assert status["config"] == "ok" and status["proposal"] == "ok" and status["state"] == "complete", status
assert setup_wizard.resume_setup(None, H, $UIDN)["state"] == "complete"            # idempotent resume
try:
    setup_wizard.resume_setup(dict(form, approval_client_id="other"), H, $UIDN); raise SystemExit("mismatch accepted")
except ConfigError:
    pass
print("setup ok", status)
PY
assert_present "$H/.config/stynpilot/owner.json" "owner settings written"
assert_present "$H/.local/state/stynpilot/provisioned.json" "state provisioned"

say "4. the polkit root step (run directly as the helper does), for exactly the caller"
assert_ok "root step writes the installer config" helper root-setup --from "$H/.config/stynpilot/installer.proposed.json"
[ "$(stat -c %a /etc/stynpilot/installer.json)" = 600 ] || fail "installer config must be 0600"
[ "$(stat -c %U /etc/stynpilot/installer.json)" = root ] || fail "installer config must be root-owned"
inject allow_overwrite && rm -f /etc/stynpilot/installer.json
assert_refused "a second root step must be refused" helper root-setup --from "$H/.config/stynpilot/installer.proposed.json"
assert_said "FileExistsError" "second root step refusal reason"
assert_refused "root helper refuses an unknown job" helper rm-rf /

say "4b. cross-user: root wrote a 0600 file the owner cannot read; the owner's wizard still verifies completion"
inject receipt_private && chmod 600 /etc/stynpilot/setup-receipt.json
[ "$(stat -c %a /etc/stynpilot/setup-receipt.json 2>/dev/null)" ] || fail "root step must leave a receipt"
if as_user cat /etc/stynpilot/installer.json >/dev/null 2>&1; then fail "the owner must NOT be able to read the root-only settings"; fi
setup_state() { as_user python3 -IB -c "
import sys; sys.path[:0] = ['/usr/lib/stynpilot/lib', '/usr/lib/stynpilot/vendor']
from pathlib import Path
from stynpilot import setup_wizard
s = setup_wizard.setup_status(Path('$H'), $UIDN); print(s['system'], s['complete'])"; }
[ "$(setup_state)" = "done True" ] || fail "wizard must report setup complete after the root step (got: $(setup_state))"
R=/etc/stynpilot/setup-receipt.json; cp $R /tmp/receipt.good
python3 -IB -c "
import json; r = json.load(open('$R')); r['config_sha256'] = '1' * 64; json.dump(r, open('$R', 'w'))"
[ "$(setup_state)" = "mismatch False" ] || fail "tampered receipt (wrong hash) must be refused (got: $(setup_state))"
python3 -IB -c "
import json; r = json.load(open('/tmp/receipt.good')); r['owner_uid'] = $UIDN + 1; json.dump(r, open('$R', 'w'))"
[ "$(setup_state)" = "mismatch False" ] || fail "receipt for another owner must be refused (got: $(setup_state))"
cp /tmp/receipt.good $R; chmod 644 $R; chmod 666 $R
[ "$(setup_state)" = "mismatch False" ] || fail "receipt writable by others must be refused (got: $(setup_state))"
chmod 644 $R; chmod 644 /etc/stynpilot/installer.json
[ "$(setup_state)" = "mismatch False" ] || fail "settings readable by others must be refused (got: $(setup_state))"
chmod 600 /etc/stynpilot/installer.json
[ "$(setup_state)" = "done True" ] || fail "restored files must verify again (got: $(setup_state))"
rm -f /tmp/receipt.good

say "5. doctor after setup"
assert_ok "doctor runs after setup" as_user /usr/bin/stynpilot doctor --config "$H/.config/stynpilot/owner.json"
assert_said "owner state files" "doctor sees the state"
assert_said "Nothing was changed" "doctor says it changed nothing"

say "6. owner backup, lose state, service REFUSES to start, restore, identical"
assert_ok "owner backup" as_user /usr/bin/stynpilot backup --config "$H/.config/stynpilot/owner.json" --out "$H/owner.tar"
before=$(cd "$H/.local/state/stynpilot" && sha256sum revoked-clients.json provisioned.json)
inject keep_state || rm -rf "$H/.local/state/stynpilot"/*
assert_refused "service must refuse to start without its state" as_user /usr/bin/stynpilot service owner --config "$H/.config/stynpilot/owner.json"
assert_said "not_provisioned_or_state_missing" "refusal is because the state is missing"
assert_absent "$H/.local/state/stynpilot/revoked-clients.json" "the service did not recreate the revocation list"
assert_ok "owner restore" as_user /usr/bin/stynpilot restore --config "$H/.config/stynpilot/owner.json" --archive "$H/owner.tar"
after=$(cd "$H/.local/state/stynpilot" && sha256sum revoked-clients.json provisioned.json)
[ "$before" = "$after" ] || fail "restored owner state is not identical"
assert_refused "owner restore must not overwrite" as_user /usr/bin/stynpilot restore --config "$H/.config/stynpilot/owner.json" --archive "$H/owner.tar"

say "7. root-side records: backup, complete-set validation, restore (separate from owner state)"
python3 -IB - <<PY || fail "build installer state fixture"
import sys; sys.path[:0] = ["/usr/lib/stynpilot/lib", "/usr/lib/stynpilot/vendor"]
import json, hashlib, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from stynpilot.broker.executor import Executor
from stynpilot.broker.proof import ProofVerifier
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True); pub.update(kid="k1", use="sig", alg="RS256")
v = ProofVerifier(issuer="https://tenant.example.auth/", approval_client_id="approval-app", jwks={"keys": [pub]})
Executor(state_dir="/var/lib/stynpilot-installer", owner="acct_" + "0" * 40, device="dtdev_FIXTUREdevice", verifier=v)
snap = Path("/var/lib/stynpilot-installer/snapshots/abc123"); (snap / "debs").mkdir(parents=True); (snap / "files").mkdir()
deb = b"fake deb bytes"; (snap / "debs" / "htop_1.deb").write_bytes(deb)
(snap / "manifest.json").write_text(json.dumps({"debs": {"htop": {"version": "1", "file": "htop_1.deb", "sha256": hashlib.sha256(deb).hexdigest()}}, "files": {}}))
PY
ROOTTAR="$H/root.tar"
LOCKED="$H/locked.tar"
if inject no_lock; then
    assert_refused "backup must be refused while an install/rollback holds the lock" env PKEXEC_UID=$UIDN /usr/libexec/stynpilot/root-helper root-backup --out "$LOCKED"
else
    assert_refused "backup must be refused while an install/rollback holds the lock" flock -x /var/lib/stynpilot-installer/installer.lock env PKEXEC_UID=$UIDN /usr/libexec/stynpilot/root-helper root-backup --out "$LOCKED"
fi
assert_said "is_running" "the refusal says an install is running"
assert_absent "$LOCKED" "no partial backup is left behind"
assert_ok "root backup" helper root-backup --out "$ROOTTAR"
[ "$(stat -c %U $ROOTTAR)" = "$U" ] || fail "root backup must be owned by the caller"
[ "$(stat -c %a $ROOTTAR)" = 600 ] || fail "root backup must be 0600"
assert_refused "a root backup must never overwrite a file" helper root-backup --out "$ROOTTAR"
assert_refused "an owner backup must not be accepted as root records" helper root-restore --archive "$H/owner.tar"
assert_said "this_is_a_owner_backup_not_a_root_one" "kind confusion is named"
cp "$ROOTTAR" "$H/tampered.tar"; chown $U "$H/tampered.tar"; chmod 600 "$H/tampered.tar"
python3 -IB - <<PY
import tarfile, io
src = tarfile.open("$ROOTTAR"); dst = tarfile.open("$H/tampered2.tar", "w")
for m in src.getmembers():
    d = src.extractfile(m).read()
    if m.name.endswith("htop_1.deb"): d = b"changed"; m.size = len(d)
    dst.addfile(m, io.BytesIO(d))
dst.close()
PY
chown $U "$H/tampered2.tar"; chmod 600 "$H/tampered2.tar"
rm -rf /var/lib/stynpilot-installer/*
assert_refused "a tampered root archive must be refused" helper root-restore --archive "$H/tampered2.tar"
assert_ok "root restore into an empty folder" helper root-restore --archive "$ROOTTAR"
assert_present /var/lib/stynpilot-installer/runs.sqlite3 "runs ledger restored"
assert_present /var/lib/stynpilot-installer/snapshots/abc123/debs/htop_1.deb "snapshot restored"
assert_refused "root restore must not overwrite" helper root-restore --archive "$ROOTTAR"

say "8. remove the package: only the program goes; config and state stay; reinstall works"
DEBIAN_FRONTEND=noninteractive apt-get remove -y stynpilot >/dev/null 2>&1 || fail "package did not remove"
assert_absent /usr/bin/stynpilot "program removed"
assert_absent /usr/lib/stynpilot "package files removed"
inject remove_config && rm -f /etc/stynpilot/installer.json
assert_present /etc/stynpilot/installer.json "installer config preserved"
assert_present "$H/.local/state/stynpilot/revoked-clients.json" "owner state preserved"
assert_present /var/lib/stynpilot-installer/snapshots/abc123/manifest.json "rollback records preserved"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$DEB" >/dev/null 2>&1 || fail "reinstall failed"
assert_ok "reinstalled program runs" /usr/bin/stynpilot version

say "9. owner service with the issuer unreachable exits instead of hanging"
assert_refused "service exits when the issuer can't be reached" as_user timeout 60 /usr/bin/stynpilot service owner --config "$H/.config/stynpilot/owner.json"
assert_said "OIDCError" "failure reason is the unreachable issuer"

printf '\nRESULT: PASS %s\n' "$HASH"
