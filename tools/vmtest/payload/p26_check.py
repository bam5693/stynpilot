"""Prints a fingerprint of everything the Preview26 stand-in owns: file hashes+modes+owners, the pairing database's
logical content, which of its units are active, and which of its ports answer. Used before/after backup, upgrade, damage, restore."""
import hashlib, json, os, socket, sqlite3, subprocess, sys

ROOTS = ["/usr/share/stynpilot-ryzen", "/usr/lib/systemd/user/stynpilot-commander-user.service",
         "/usr/lib/systemd/system/stynpilot-remote-broker.service", "/usr/share/polkit-1/actions/com.stynpilot.preview.policy",
         "/etc/stynpilot/remote-broker.json", "/home/owner/.local/state/stynpilot-owner"]


def files():
    out = {}
    for root in ROOTS:
        paths = [root] if os.path.isfile(root) else [os.path.join(d, n) for d, _, ns in os.walk(root) for n in ns] if os.path.isdir(root) else []
        for p in sorted(paths):
            if p.endswith(("-wal", "-shm", "-journal")):        # SQLite companions come and go; the database is the state
                continue
            st = os.lstat(p)
            if p.endswith(".sqlite3"):
                try:
                    db = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
                    digest = hashlib.sha256("\n".join(db.iterdump()).encode()).hexdigest()
                    ok = db.execute("PRAGMA integrity_check").fetchone()[0]
                    db.close()
                    digest += ":" + ok
                except sqlite3.Error as error:
                    digest = "UNREADABLE:%s" % error
            else:
                digest = hashlib.sha256(open(p, "rb").read()).hexdigest()
            out[p] = "%s %o %d" % (digest, st.st_mode & 0o7777, st.st_uid)
    return out


def sh(*argv):
    return subprocess.run(argv, capture_output=True, text=True).stdout.strip()


def main():
    env = dict(os.environ, XDG_RUNTIME_DIR="/run/user/1000")
    units = {"system:stynpilot-remote-broker": sh("systemctl", "is-active", "stynpilot-remote-broker"),
             "user:stynpilot-commander-user": subprocess.run(["runuser", "-u", "owner", "--", "systemctl", "--user", "is-active", "stynpilot-commander-user"],
                                                            capture_output=True, text=True, env=env).stdout.strip()}
    ports = {}
    for port in (18991, 18992):
        s = socket.socket(); s.settimeout(2)
        ports[port] = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
    print(json.dumps({"files": files(), "units": units, "ports": ports,
                      "dpkg": sh("dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", "stynpilot-preview")}, sort_keys=True))


main()
