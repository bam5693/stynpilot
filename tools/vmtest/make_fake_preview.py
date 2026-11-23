"""Builds a stand-in for the owner's Preview26 package (name, unit names, file locations and state paths follow what the
GitLab build is known to use) so backup/restore can be rehearsed without the real thing. All content is fictional."""
import os
import subprocess
import sys
import tempfile

CONTROL = """Package: stynpilot-preview
Version: 0.5.13~preview26
Architecture: all
Maintainer: test <test@invalid>
Depends: python3
Description: STAND-IN for the Preview26 build (test only)
"""
UNIT_USER = """[Unit]
Description=Stand-in Preview26 commander (user)
[Service]
ExecStart=/usr/bin/python3 /usr/share/stynpilot-preview/commander.py
Restart=on-failure
[Install]
WantedBy=default.target
"""
UNIT_ROOT = """[Unit]
Description=Stand-in Preview26 root broker
ConditionPathExists=/etc/stynpilot/remote-broker.json
[Service]
ExecStart=/usr/bin/python3 /usr/share/stynpilot-preview/broker.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
"""
POLICY = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig><action id="com.stynpilot.preview.stand-in"><description>stand-in</description><message>stand-in</message>
<defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults></action></policyconfig>
"""
PROGRAM = "import socket, time\ns = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', %d)); s.listen(5)\nwhile True: time.sleep(60)\n"


def build(out):
    with tempfile.TemporaryDirectory() as root:
        def put(path, text, mode=0o644):
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").write(text)
            os.chmod(full, mode)
        put("DEBIAN/control", CONTROL)
        put("usr/share/stynpilot-preview/commander.py", PROGRAM % 18991, 0o755)
        put("usr/share/stynpilot-preview/broker.py", PROGRAM % 18992, 0o755)
        put("usr/lib/systemd/user/stynpilot-commander-user.service", UNIT_USER)
        put("usr/lib/systemd/system/stynpilot-remote-broker.service", UNIT_ROOT)
        put("usr/share/polkit-1/actions/com.stynpilot.preview.policy", POLICY)
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", root, out], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    build(sys.argv[1])
