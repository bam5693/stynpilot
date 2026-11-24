#!/bin/sh
# The LAST manual StyNpilot install: dev3 -> dev4, in one command, with automatic preflight, backup, install, service
# restart, health verification and rollback to dev3 on any failure. After dev4, upgrades are requested by ChatGPT or
# Claude, approved on the owner's phone, and verified by StyNpilot itself (docs/M2_DEV4_UPGRADE_AND_ROLLBACK.md).
#
#   sh install_dev4.sh COMMIT SHA256        (both come from the owner's chat; the package is rebuilt from that exact
#                                            commit and refused unless its SHA-256 matches)
#
# Run as the normal owner account (NOT root, not with sudo in front); it asks for the password once.
# Order: nothing is changed until every preflight check and the backups pass. From the first package change on, ANY
# failure (or Ctrl-C, or a closed terminal) puts dev3 back and re-checks it. Files are only added to the owner's
# home (releases, backups, logs); nothing is ever deleted. No secret is printed or logged.
set -u
umask 077

FROM_VERSION="0.1.0~dev3"; TO_VERSION="0.1.0~dev4"
DEV3_COMMIT="859b66e901782276a97b3580a6e96f62d357f733"
DEV3_SHA256="fe8b270e143397bed6faa64b9bfa51123159f2e05135e1ac0b42b26d4997975f"
REPO="${STYNPILOT_REPO:-https://github.com/bam5693/stynpilot.git}"
COMMIT="${1:-}"; EXPECT="${2:-}"
OWNERCFG="$HOME/.config/stynpilot/owner.json"
INSTALLER_UNIT="stynpilot-installer.service"; OWNER_UNIT="stynpilot-owner.service"
HEALTH_WAIT=90
case "${STYNPILOT_HEALTH_WAIT:-}" in [5-9]|[1-8][0-9]) HEALTH_WAIT="$STYNPILOT_HEALTH_WAIT";; esac   # can only be SHORTER (for drills)

[ -n "${XDG_RUNTIME_DIR:-}" ] || export XDG_RUNTIME_DIR="/run/user/$(id -u)"      # so `systemctl --user` works over SSH
TS=$(date +%Y%m%d-%H%M%S)
HOME_LOGS="$HOME/stynpilot-upgrade-logs"; REL="$HOME/stynpilot-releases"
LOG="$HOME_LOGS/dev4-$TS.log"
WORK=""; KEEPALIVE=""; INSTALL_STARTED=0; DONE=0; ROLLING=0
OLD_DEB="$REL/stynpilot_${FROM_VERSION}_all.deb"; NEW_DEB="$REL/stynpilot_${TO_VERSION}_all.deb"

say()  { printf '== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
die()  { printf 'STOPPED BEFORE ANY CHANGE: %s\n' "$*" >&2; cleanup; exit 2; }

cleanup() {
  [ -n "$KEEPALIVE" ] && kill "$KEEPALIVE" 2>/dev/null
  [ -n "$WORK" ] && [ -d "$WORK" ] && rm -rf "$WORK"
  KEEPALIVE=""; WORK=""
}

installed_version() { dpkg-query -W -f '${Version}' stynpilot 2>/dev/null || echo none; }
unit_active() { [ "$(systemctl is-active "$INSTALLER_UNIT" 2>/dev/null)" = active ]; }
owner_active() { [ "$(systemctl --user is-active "$OWNER_UNIT" 2>/dev/null)" = active ]; }

doctor_code() { stynpilot doctor >"$1" 2>&1; echo $?; }

config_digest() {   # one digest over every settings file the upgrade must not change (root files read via sudo)
  { sudo sha256sum /etc/stynpilot/installer.json 2>/dev/null
    [ -f /etc/stynpilot/setup-receipt.json ] && sudo sha256sum /etc/stynpilot/setup-receipt.json 2>/dev/null
    sha256sum "$OWNERCFG" 2>/dev/null; } | sort
}

endpoint_check() {  # the local MCP endpoint must answer and demand a token (not just "the service is running")
  python3 -I - "$OWNERCFG" <<'PY'
import http.client, json, sys
try:
    c = json.load(open(sys.argv[1]))
    conn = http.client.HTTPConnection("127.0.0.1", int(c["mcp_port"]), timeout=10)
    conn.request("POST", "/mcp", body="{}", headers={"Host": c["mcp_public_host"], "Content-Type": "application/json"})
    r = conn.getresponse(); r.read()
    ok = r.status == 401 and "bearer" in (r.getheader("WWW-Authenticate") or "").lower()
    sys.exit(0 if ok else 1)
except Exception:
    sys.exit(1)
PY
}

wait_healthy() {   # $1 = expected version, $2 = baseline doctor code, $3 = baseline endpoint (0 ok / 1 not checkable)
  want="$1"; base="$2"; ep="$3"; start=$(date +%s); why="not checked"
  while :; do
    why=""
    if [ "$(installed_version)" != "$want" ]; then why="wrong version installed"
    elif ! unit_active; then why="installer service not running"
    elif ! owner_active; then why="owner service not running"
    else
      code=$(doctor_code "$WORK/doctor-now.txt")
      if [ "$code" != 0 ] && [ "$code" != "$base" ]; then why="doctor reports problems"
      elif [ "$ep" = 0 ] && ! endpoint_check; then why="the MCP endpoint does not answer"
      fi
    fi
    if [ -z "$why" ]; then
      sleep 8                                                  # it must STAY up, not merely start
      owner_active && unit_active && return 0
      why="a service stopped again after starting"
    fi
    [ $(( $(date +%s) - start )) -ge "$HEALTH_WAIT" ] && { WHY="$why"; return 1; }
    sleep 3
  done
}

restart_services() {
  sudo systemctl daemon-reload || return 1
  sudo systemctl restart "$INSTALLER_UNIT" || return 1
  systemctl --user restart "$OWNER_UNIT" || return 1
}

rollback() {
  [ "$ROLLING" = 1 ] && return 1
  ROLLING=1
  say "ROLLING BACK to $FROM_VERSION"
  if sudo dpkg -i --force-downgrade --force-confold "$OLD_DEB" && restart_services \
     && wait_healthy "$FROM_VERSION" "$BASE_DOCTOR" "$BASE_ENDPOINT"; then
    if [ "$(config_digest)" = "$BASE_CONFIG" ]; then
      echo "RESULT: ROLLED BACK. dev3 is installed and healthy again; your settings are unchanged. ($WHY_FAILED)"
      DONE=1; return 0
    fi
  fi
  echo "RESULT: NEEDS HELP. The upgrade failed and dev3 could not be fully verified. Run this, then paste the output to ChatGPT:"
  echo "  sudo dpkg -i --force-downgrade --force-confold $OLD_DEB && stynpilot doctor"
  DONE=1; return 1
}

fail_after_change() {   # $1 = what went wrong
  WHY_FAILED="$1"
  echo "PROBLEM: $1"
  rollback
  cleanup
  exit 1
}

on_signal() {
  [ "$ROLLING" = 1 ] && return                      # already putting dev3 back: a second Ctrl-C must not abort that
  echo "Interrupted."
  if [ "$INSTALL_STARTED" = 1 ] && [ "$DONE" = 0 ]; then WHY_FAILED="interrupted"; rollback; fi
  cleanup; exit 1
}

main() {
  trap '' HUP                    # a dropped connection must not stop the upgrade half-way; the log keeps everything
  trap on_signal INT TERM
  say "StyNpilot dev4: the last manual install (log: $LOG)"

  # ---- 0. arguments and environment (no changes) ---------------------------------------------------------------
  case "$COMMIT" in ""|*[!0-9a-f]*) die "first argument must be the full lowercase commit hash";; esac
  [ "${#COMMIT}" = 40 ] || die "use the full 40-character commit hash"
  case "$EXPECT" in ""|*[!0-9a-f]*) die "second argument must be the lowercase SHA-256";; esac
  [ "${#EXPECT}" = 64 ] || die "the SHA-256 must be 64 characters"
  [ "$(id -u)" != 0 ] || die "run this as your normal account, not root and not with sudo in front"
  for c in git python3 sudo dpkg dpkg-deb dpkg-query systemctl sha256sum stynpilot; do
    command -v "$c" >/dev/null 2>&1 || die "missing required tool: $c"
  done
  [ -f "$OWNERCFG" ] || die "owner settings not found: $OWNERCFG"
  WORK=$(mktemp -d) || die "cannot make a temporary folder"
  say "1. password (asked once; used only to install and restart)"
  sudo -v || die "sudo did not accept the password"
  ( while :; do sudo -n true 2>/dev/null; sleep 40; done ) >/dev/null 2>&1 & KEEPALIVE=$!

  # ---- 1. preflight (no changes) -------------------------------------------------------------------------------
  say "2. preflight"
  have=$(installed_version)
  if [ "$have" = "$TO_VERSION" ]; then
    note "dev4 is already installed; verifying it instead"
    BASE_DOCTOR=$(doctor_code "$WORK/doctor.txt"); BASE_ENDPOINT=1; endpoint_check && BASE_ENDPOINT=0
    wait_healthy "$TO_VERSION" "$BASE_DOCTOR" "$BASE_ENDPOINT" || die "dev4 is installed but not healthy: $WHY"
    echo "RESULT: OK. dev4 is installed and healthy. Nothing was changed."; DONE=1; cleanup; return 0
  fi
  [ "$have" = "$FROM_VERSION" ] || die "installed version is '$have'; this script only upgrades $FROM_VERSION"
  unit_active || die "the installer service is not running; fix that first (nothing changed)"
  owner_active || die "the owner service is not running; fix that first (nothing changed)"
  BASE_DOCTOR=$(doctor_code "$WORK/doctor-before.txt")
  note "doctor before: exit $BASE_DOCTOR (an existing problem is not blamed on the upgrade)"
  BASE_ENDPOINT=1; endpoint_check && BASE_ENDPOINT=0
  note "MCP endpoint before: $( [ "$BASE_ENDPOINT" = 0 ] && echo answering || echo 'not checkable (not required)' )"
  BASE_CONFIG=$(config_digest)
  [ -n "$BASE_CONFIG" ] || die "could not fingerprint the settings files"
  free=$(df -Pk "$HOME" /var /tmp 2>/dev/null | awk 'NR>1 {print $4}' | sort -n | head -1)
  [ "${free:-0}" -ge 300000 ] || die "less than 300 MB free disk"
  mkdir -p "$HOME_LOGS" "$REL" && chmod 700 "$HOME_LOGS" "$REL" || die "cannot create $REL"

  # ---- 2. build both packages from their pinned commits and check their hashes ---------------------------------
  build() {   # $1 commit  $2 sha256  $3 destination file
    d="$WORK/src-$1"; mkdir -p "$d"
    git init -q "$d" && git -C "$d" fetch -q --depth 1 "$REPO" "$1" && git -C "$d" checkout -q FETCH_HEAD \
      || return 1
    [ "$(git -C "$d" rev-parse HEAD)" = "$1" ] || return 1
    ( umask 022; cd "$d" && python3 tools/build_deb.py >/dev/null ) || return 1
    f=$(ls "$d"/dist/stynpilot_*_all.deb 2>/dev/null | head -1); [ -n "$f" ] || return 1
    [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$2" ] || return 1
    [ -e "$3" ] || install -m 600 "$f" "$3"
    [ "$(sha256sum "$3" | cut -d' ' -f1)" = "$2" ]
  }
  say "3. build dev4 from commit $COMMIT and check the checksum"
  build "$COMMIT" "$EXPECT" "$NEW_DEB" || die "could not build a package that matches the SHA-256 you were given. Do not use it."
  SRC="$WORK/src-$COMMIT"
  cmp -s "$0" "$SRC/tools/install_dev4.sh" || note "(this copy of the script differs from the one in the commit; the package check above is what matters)"
  say "4. make sure the dev3 rollback package is present and correct"
  if [ -e "$OLD_DEB" ] && [ "$(sha256sum "$OLD_DEB" | cut -d' ' -f1)" = "$DEV3_SHA256" ]; then note "found $OLD_DEB"
  else build "$DEV3_COMMIT" "$DEV3_SHA256" "$OLD_DEB" || die "could not prepare the dev3 rollback package"; note "rebuilt dev3 from its pinned commit"; fi

  say "5. inspect the dev4 package"
  [ "$(dpkg-deb -f "$NEW_DEB" Version)" = "$TO_VERSION" ] || die "package is not version $TO_VERSION"
  [ "$(dpkg-deb -f "$NEW_DEB" Package)" = stynpilot ] || die "package name is wrong"
  dpkg-deb -e "$NEW_DEB" "$WORK/ctl" || die "cannot read package control data"
  [ -z "$(ls "$WORK/ctl" | grep -vx -e control -e md5sums)" ] || die "package contains install scripts; refusing"
  [ "$(dpkg-deb -f "$NEW_DEB" Depends)" = "$(dpkg-query -W -f '${Depends}' stynpilot)" ] \
    || die "package dependencies differ from the installed ones; refusing"

  say "6. back up your settings and records"
  sh "$SRC/tools/preflight_backup.sh" "$HOME/stynpilot-pre-dev4-$TS" || die "backup failed"
  sh "$SRC/tools/preflight_backup.sh" --verify "$HOME/stynpilot-pre-dev4-$TS" || die "backup did not verify"
  [ "$(config_digest)" = "$BASE_CONFIG" ] || die "a settings file changed during the backup"

  # ---- 3. the change: from here on every failure rolls back ----------------------------------------------------
  say "7. installing dev4 (automatic rollback to dev3 if anything is wrong)"
  INSTALL_STARTED=1
  sudo dpkg -i --force-confold "$NEW_DEB" || fail_after_change "the package could not be installed"
  restart_services || fail_after_change "a service could not be restarted"
  say "8. checking that it works (up to ${HEALTH_WAIT}s)"
  wait_healthy "$TO_VERSION" "$BASE_DOCTOR" "$BASE_ENDPOINT" || fail_after_change "health check failed: $WHY"
  [ "$(config_digest)" = "$BASE_CONFIG" ] || fail_after_change "a settings file changed during the upgrade"

  DONE=1
  say "9. result"
  echo "installed version : $(installed_version)"
  echo "installer service : active"
  echo "owner service     : active (stayed up)"
  echo "settings files    : unchanged"
  echo "doctor            : exit $(doctor_code "$WORK/doctor-after.txt") (before: $BASE_DOCTOR)"
  echo "MCP endpoint      : $( [ "$BASE_ENDPOINT" = 0 ] && echo 'answers and demands a token' || echo 'not checked' )"
  echo "rollback package  : $OLD_DEB"
  echo "backups           : $HOME/stynpilot-pre-dev4-$TS"
  echo "RESULT: SUCCESS. dev4 is live. This was the last manual install: from now on ChatGPT or Claude request upgrades and you approve them on your phone."
  cleanup
}

mkdir -p "$HOME_LOGS" 2>/dev/null && chmod 700 "$HOME_LOGS" 2>/dev/null
RC="$(mktemp 2>/dev/null || echo /tmp/stynpilot-rc.$$)"
# The wrapper layers only swallow signals (a no-op handler, which sub-shells reset); main() handles them itself.
trap ':' INT TERM HUP
( trap ':' INT TERM HUP; ( main ); echo $? >"$RC" ) 2>&1 | tee -a "$LOG"
rc=$(cat "$RC" 2>/dev/null || echo 1); rm -f "$RC"
exit "$rc"
