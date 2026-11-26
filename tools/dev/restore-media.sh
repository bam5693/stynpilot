#!/bin/sh
# Prepare synthetic guest media from the local, verified package cache.
set -eu
umask 077
test "$#" -eq 1
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
cp "$repo/tools/dev/guest-restore.py" "$repo/tests/legacy_pairing.py" "$repo/tests/softauth.py" "$run/payload/"
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
cat > "$run/payload/run.sh" <<'EOF'
#!/bin/bash
set -euxo pipefail
test "$(cat /sys/class/dmi/id/product_name)" = STYNPILOT-DISPOSABLE
export DEBIAN_FRONTEND=noninteractive
printf 'deb [trusted=yes] file:/mnt/stynpilot-fixture/repo ./\n' > /tmp/stynpilot.list
apt_local=(apt-get -o Dir::Etc::sourcelist=/tmp/stynpilot.list -o Dir::Etc::sourceparts=- -o Acquire::Languages=none -o Dpkg::Use-Pty=false)
"${apt_local[@]}" update
"${apt_local[@]}" -y --no-install-recommends install stynpilot acl
dpkg-query -W stynpilot
/usr/bin/stynpilot version
if ! /usr/bin/python3 -IB /mnt/stynpilot-fixture/guest-restore.py; then
    journalctl -b -u stynpilot-installer.service -u stynpilot-restore.service -u stynpilot-restore.path --no-pager -n 140
    exit 1
fi
EOF
genisoimage -quiet -output "$run/seed.iso" -volid cidata -joliet -rock "$run/seed"
genisoimage -quiet -output "$run/payload.iso" -volid SPARTIFACT -joliet -rock "$run/payload"
echo "$run"
