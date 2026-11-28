#!/bin/sh
# Prepare synthetic guest media from the local, verified package cache.
set -eu
umask 077
test "$#" -ge 1 && test "$#" -le 2
if [ "$#" -eq 2 ]; then
    case "$2" in --fault-cases|--power-case|--limits-case|--oom-case|--upgrade-case|--lab-mcp-case|--archive-mcp-case|--repository-auth-case|--deckplay-checkout-case) ;; *) exit 2;; esac
fi
package=$(realpath "$1")
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
dev_dir=${STYNPILOT_DEV_DIR:-"$HOME/.local/share/stynpilot-dev"}
test -f "$package"
run=$(mktemp -d "$dev_dir/work/restore-media.XXXXXXXX")
mkdir -p "$run/seed" "$run/payload/repo"
cp "$package" "$run/payload/repo/"
(
    cd "$dev_dir/cache/guest-debs"
    sha256sum --strict -c SHA256SUMS.local >&2
    cp ./*.deb "$run/payload/repo/"
)
cp "$repo/tools/dev/guest-limits.py" "$repo/tools/dev/guest-restore.py" "$repo/tests/legacy_pairing.py" "$repo/tests/softauth.py" "$run/payload/"
if [ "${2-}" = --archive-mcp-case ]; then
    cp "$repo/tools/dev/guest-archive-mcp.py" "$run/payload/"
fi
if [ "${2-}" = --repository-auth-case ]; then
    cp "$repo/tools/dev/guest-repository-auth.py" "$repo/tools/dev/guest-archive-mcp.py" "$repo/tests/test_repository_auth.py" "$run/payload/"
fi
if [ "${2-}" = --deckplay-checkout-case ]; then
    cp "$repo/tools/dev/guest-deckplay-checkout.py" "$run/payload/"
fi
if [ "${2-}" = --lab-mcp-case ] || [ "${2-}" = --deckplay-checkout-case ]; then
    cp "$repo/tools/dev/guest-lab-mcp.py" "$run/payload/"
    (
        cd "$dev_dir/cache/lab-guest-debs"
        sha256sum --strict -c SHA256SUMS.local >&2
        cp ./*.deb "$run/payload/repo/"
    )
fi
(cd "$run/payload/repo" && dpkg-scanpackages --multiversion . /dev/null > Packages)
cat > "$run/seed/meta-data" <<'EOF'
instance-id: stynpilot-restore-synthetic
local-hostname: stynpilot-guest
EOF
cat > "$run/seed/user-data" <<'EOF'
#cloud-config
bootcmd:
  - [systemctl, stop, --no-block, systemd-networkd-wait-online.service]
runcmd:
  - [sh, -c, 'mkdir -p /mnt/stynpilot-fixture; systemctl stop serial-getty@ttyS0.service; mount -o ro /dev/sr1 /mnt/stynpilot-fixture && bash /mnt/stynpilot-fixture/run.sh >/var/log/stynpilot-fixture.log 2>&1; result=$?; cat /var/log/stynpilot-fixture.log >/dev/ttyS0; echo FIXTURE_EXIT=$result >/dev/ttyS0; systemctl poweroff --no-block']
EOF
if [ "$#" -eq 2 ]; then
    touch "$run/payload/${2#--}"
    if [ "$2" = "--upgrade-case" ]; then
        baseline="$dev_dir/cache/baseline/dev24.deb"
        printf '%s  %s\n' 4d23df45c1216354cd96dff0b77ef55b2a5abe12548f206f78c84dd00ad97d10 "$baseline" | sha256sum --strict -c >&2
        cp "$baseline" "$run/payload/dev24.deb"
    fi
fi
cat > "$run/payload/run.sh" <<'EOF'
#!/bin/bash
set -euxo pipefail
test "$(cat /sys/class/dmi/id/product_name)" = STYNPILOT-DISPOSABLE
export DEBIAN_FRONTEND=noninteractive
printf 'deb [trusted=yes] file:/mnt/stynpilot-fixture/repo ./\n' > /tmp/stynpilot.list
apt_local=(apt-get -o Dir::Etc::sourcelist=/tmp/stynpilot.list -o Dir::Etc::sourceparts=- -o Acquire::Languages=none -o Dpkg::Use-Pty=false)
"${apt_local[@]}" update
if [[ -e /mnt/stynpilot-fixture/upgrade-case ]]; then
    "${apt_local[@]}" -y --no-install-recommends install /mnt/stynpilot-fixture/dev24.deb acl
else
    "${apt_local[@]}" -y --no-install-recommends install stynpilot acl
fi
dpkg-query -W stynpilot
/usr/bin/stynpilot version
fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-restore.py)
if [[ -e /mnt/stynpilot-fixture/fault-cases ]]; then fixture+=(--fault-cases); fi
if [[ -e /mnt/stynpilot-fixture/power-case ]]; then fixture+=(--power-case); fi
if [[ -e /mnt/stynpilot-fixture/limits-case || -e /mnt/stynpilot-fixture/oom-case || -e /mnt/stynpilot-fixture/upgrade-case ]]; then
    fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-limits.py)
fi
if [[ -e /mnt/stynpilot-fixture/lab-mcp-case ]]; then
    "${apt_local[@]}" -y --no-install-recommends install bubblewrap python3-pytest
    fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-lab-mcp.py)
fi
if [[ -e /mnt/stynpilot-fixture/archive-mcp-case ]]; then
    fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-archive-mcp.py)
fi
if [[ -e /mnt/stynpilot-fixture/repository-auth-case ]]; then
    fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-repository-auth.py)
fi
if [[ -e /mnt/stynpilot-fixture/deckplay-checkout-case ]]; then
    "${apt_local[@]}" -y --no-install-recommends install bubblewrap python3-pytest
    fixture=(/usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-deckplay-checkout.py)
fi
if ! "${fixture[@]}"; then
    journalctl -b -u stynpilot-installer.service -u stynpilot-restore.service -u stynpilot-restore.path -u 'run-*.service' -u 'stynpilot-lab-*.service' -u 'stynpilot-archive-*.service' --no-pager -n 160
    journalctl -b _SYSTEMD_USER_UNIT=stynpilot-owner.service --no-pager -n 40
    if [[ -r /var/lib/stynpilot-installer/runner-selftest.json ]]; then
        cat /var/lib/stynpilot-installer/runner-selftest.json
    fi
    exit 1
fi
EOF
genisoimage -quiet -output "$run/seed.iso" -volid cidata -joliet -rock "$run/seed"
genisoimage -quiet -output "$run/payload.iso" -volid SPARTIFACT -joliet -rock "$run/payload"
echo "$run"
