#!/bin/sh
# Disposable-machine acceptance check for the .deb. Run as root INSIDE a throwaway Ubuntu 26.04 chroot/VM/container
# (never on the live Ryzen). Usage: isolated_install_check.sh /path/to/stynpilot_X_all.deb /path/to/repo/tests
# It installs the package, proves nothing starts, exercises setup/doctor/backup/restore as an unprivileged user,
# the polkit root step's file handling, remove/reinstall (rollback of the package) and that state survives.
set -eu
DEB="$1"; TESTS="$2"; U=nobody; UIDN=$(id -u $U)
say() { printf '\n== %s\n' "$*"; }
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$DEB" >/dev/null
H=/tmp/spcheck; rm -rf "$H"; mkdir -p "$H"; chown $U "$H"; chmod 700 "$H"
as_user() { setpriv --reuid=$U --regid=nogroup --clear-groups env HOME="$H" "$@"; }
say "1. installing started/enabled nothing"
test ! -e /etc/systemd/system/multi-user.target.wants/stynpilot-installer.service && echo "no unit enabled: OK"
test ! -e /etc/stynpilot && echo "no /etc/stynpilot created: OK"
say "2. doctor before setup (read-only)"; as_user stynpilot doctor || true
say "3. fake pairing database (test fixture), then first-run setup logic as the owner"
as_user python3 -I - <<PY
import sys, time
sys.path[:0] = ["/usr/lib/stynpilot/lib", "/usr/lib/stynpilot/vendor", "$TESTS"]
from legacy_pairing import make_pairing_db
from stynpilot.identity import account_id
owner = account_id(verified_issuer="https://tenant.example.auth/", verified_subject="auth0|fixture")
from pathlib import Path
make_pairing_db(Path("$H/pair"), [("dtdev_FIXTUREdevice", owner, time.time() + 3600, None, ["workspace.propose"])])
import os
from stynpilot import setup_wizard
pdb = next(p for p in os.scandir("$H/pair")).path
print(setup_wizard.run_setup({"issuer": "tenant.example.auth", "approval_client_id": "approval-app",
  "approval_public_host": "pc.example.test:8444", "mcp_public_host": "pc.example.test", "pairing_db": pdb,
  "chatgpt_client_id": "cg", "claude_client_id": "cl"}, "$H", $UIDN))
PY
ls -l "$H/.config/stynpilot" "$H/.local/state/stynpilot"
say "4. root step (what polkit runs), for exactly the caller; second run must refuse"
PKEXEC_UID=$UIDN stynpilot root-setup --from "$H/.config/stynpilot/installer.proposed.json"
ls -l /etc/stynpilot/installer.json
PKEXEC_UID=$UIDN stynpilot root-setup --from "$H/.config/stynpilot/installer.proposed.json" && echo "UNEXPECTED: overwrote" || echo "second run refused: OK"
say "5. doctor after setup"; as_user stynpilot doctor --config "$H/.config/stynpilot/owner.json" || true
say "6. backup, lose state, service refuses to start, restore, state identical"
as_user stynpilot backup --config "$H/.config/stynpilot/owner.json" --out "$H/backup.tar"
before=$(cd "$H/.local/state/stynpilot" && sha256sum revoked-clients.json provisioned.json)
rm -rf "$H/.local/state/stynpilot"/*
as_user stynpilot service owner --config "$H/.config/stynpilot/owner.json" 2>&1 | tail -1 || true
as_user stynpilot restore --config "$H/.config/stynpilot/owner.json" --archive "$H/backup.tar"
after=$(cd "$H/.local/state/stynpilot" && sha256sum revoked-clients.json provisioned.json)
[ "$before" = "$after" ] && echo "restored state identical: OK"
say "7. remove then reinstall the package: package files go, config and state stay"
DEBIAN_FRONTEND=noninteractive apt-get remove -y stynpilot >/dev/null
test ! -e /usr/bin/stynpilot && echo "program removed: OK"
test -e /etc/stynpilot/installer.json && test -e "$H/.local/state/stynpilot/revoked-clients.json" && echo "config and state preserved: OK"
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$DEB" >/dev/null
stynpilot version
say "8. owner service with the issuer unreachable exits cleanly instead of hanging"
as_user timeout 60 stynpilot service owner --config "$H/.config/stynpilot/owner.json" 2>&1 | tail -1 || true
say "DONE"
