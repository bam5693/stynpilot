"""Test-only backend: the same validated argv, run by a real uid drop inside REAL Linux namespaces (new network and mount
namespaces, home hidden behind a tmpfs with only the workspace bound back in, hidden paths masked). It is how the live
self-test's probe is exercised for real in a root sandbox that has no systemd. It does NOT prove systemd's own unit
properties: those are proven on the owner's machine by the same self-test."""
import os
import pwd
import subprocess

from stynpilot import runner
from stynpilot.broker.jobs import _kill_group

SCRIPT = r'''set -e
stash=$(mktemp -d)
mount --bind "$NS_WS" "$stash"
mount -t tmpfs -o mode=0755 none "$NS_HOME"
if [ -z "$NS_KEEP_RUN" ]; then mount -t tmpfs -o mode=0755 none /run; fi      # = TemporaryFileSystem=/run
nothing=$(mktemp); chmod 000 "$nothing"
mkdir -p "$NS_WS"
mount --bind "$stash" "$NS_WS"
for h in $NS_HIDDEN; do [ -d "$h" ] && mount -t tmpfs -o mode=000 none "$h"; done
for m in $NS_MASKED; do
  if [ -d "$m" ]; then mount -t tmpfs -o mode=000 none "$m"; elif [ -e "$m" ]; then mount --bind "$nothing" "$m"; fi
done
cd "$NS_WS"
exec "$@"
'''


class NamespaceBackend:
    def __init__(self, home, hidden=(), network=False, keep_run=False):
        self.home, self.extra_hidden, self.network, self.keep_run = home, tuple(hidden), network, keep_run

    enforces_limits = False

    def start(self, job_id, argv, workspace, limits, run_user, masked=()):
        pw = pwd.getpwnam(run_user)
        drop = ["setpriv", "--reuid=%d" % pw.pw_uid, "--regid=%d" % pw.pw_gid, "--clear-groups", "--no-new-privs",
                "--bounding-set=-all", "--inh-caps=-all", "--"]
        env_pairs = ["%s=%s" % kv for kv in runner.ENV.items()]
        hidden = [p for p in runner.HIDDEN_PATHS + self.extra_hidden if os.path.isdir(p)]
        cmd = ["unshare", "--mount", "--propagation", "private"] + ([] if self.network else ["--net"]) + \
              ["--", "sh", "-c", SCRIPT, "sh", "env", "-i"] + env_pairs + drop + list(argv)
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "NS_WS": workspace, "NS_HOME": self.home, "NS_HIDDEN": " ".join(hidden), "NS_MASKED": " ".join(masked)}
        if self.keep_run:
            env["NS_KEEP_RUN"] = "1"
        return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                start_new_session=True)

    def cancel(self, job_id, proc):
        _kill_group(proc)
