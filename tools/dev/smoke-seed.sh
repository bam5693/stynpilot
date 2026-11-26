#!/bin/sh
set -eu
umask 077
test "$#" -eq 1
stage=$(mktemp -d)
trap 'rm -f -- "$stage/meta-data" "$stage/user-data"; rmdir "$stage"' EXIT
cat > "$stage/meta-data" <<'YAML'
instance-id: stynpilot-smoke
local-hostname: stynpilot-guest
YAML
cat > "$stage/user-data" <<'YAML'
#cloud-config
bootcmd:
  - [systemctl, stop, --no-block, systemd-networkd-wait-online.service]
runcmd:
  - [sh, -c, 'test "$(cat /proc/1/comm)" = systemd && systemctl --version | head -1 >/dev/ttyS0 && echo STYNPILOT_GUEST_BOOT_OK >/dev/ttyS0; systemctl poweroff']
YAML
genisoimage -quiet -output "$1" -volid cidata -joliet -rock "$stage"
