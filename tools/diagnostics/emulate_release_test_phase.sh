#!/bin/sh
# Developer tool: emulates the release builder offline test phase (see runner.unit_command). Runs as uid 992 like stynpilot-build
# on the Ryzen (SB_UID to change); FAKETAR=1 makes tar fail like there (ENOSYS). Needs seccomp_wrap.py, loopback_up.py as in the script.
# Emulation of the release builder's offline test phase (runner.unit_command, network=False): see the property list in runner.py.
W=/var/sbw
rm -rf $W/src && git clone -q /home/claude/stynpilot $W/src && cp -r /home/claude/stynpilot/src /home/claude/stynpilot/tests /home/claude/stynpilot/tools /home/claude/stynpilot/pyproject.toml $W/src/
[ -d $W/cache ] || { mkdir -p $W/cache && cp /home/claude/stynpilot/.build-cache/*.whl $W/cache/; }
chown -R 992:992 $W; chmod 700 $W
printf '%s\n' "umask 077; ulimit -n 1024; ulimit -c 0; ulimit -f 524288; cd $W && rm -rf vendor && mkdir -p vendor && for w in cache/*.whl; do /usr/bin/python3 -m zipfile -e \"\$w\" vendor || exit 97; done && cd src && PYTHONPATH=src:../vendor exec /usr/bin/python3.12 /tmp/seccomp_wrap.py /usr/local/bin/python3 -m pytest -p no:cacheprovider $* " > /tmp/sb_inner.sh
chmod 755 /tmp/sb_inner.sh; cp /tmp/sb_inner.sh /tmp/seccomp_wrap.py /tmp/loup.py /var/ 2>/dev/null
FAKETAR=${FAKETAR:-} unshare -m -n -p -f --mount-proc=/proc sh -c '
set -e
mount --make-rprivate /
python3 /var/loup.py
mount --bind /var/sbw /var/sbw
[ -n "$FAKETAR" ] && touch /usr/local/bin/tar && mount --bind /var/faketar /usr/local/bin/tar
mount -o remount,bind,ro /
mount -t tmpfs -o mode=1777,nosuid,nodev,size=256M tmpfs /tmp
mount -t tmpfs -o mode=0755,nosuid,nodev,size=8M tmpfs /run
mount -t tmpfs -o mode=0755 tmpfs /home
mount -t tmpfs -o mode=0700 tmpfs /root
cp /var/sb_inner.sh /var/seccomp_wrap.py /tmp/ 2>/dev/null || true
exec setpriv --reuid=${SB_UID:-992} --regid=${SB_UID:-992} --clear-groups --inh-caps=-all --bounding-set=-all env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8 TERM=dumb CI=1 NO_COLOR=1 PYTHONDONTWRITEBYTECODE=1 sh /tmp/sb_inner.sh'
