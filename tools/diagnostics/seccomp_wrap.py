import os, re, subprocess, sys, seccomp
o = re.sub(r'\x1b\[[0-9;]*m', '', subprocess.run(["systemd-analyze", "syscall-filter"], capture_output=True, text=True).stdout)
S, cur = {}, None
for l in o.splitlines():
    if l.startswith("@"): cur = S.setdefault(l.strip(), set()); continue
    t = l.strip()
    if cur is not None and t and not t.startswith("#"): cur.add(t)
def exp(g):
    r = set()
    for x in S.get(g, ()): r |= exp(x) if x.startswith("@") else {x}
    return r
allowed = (exp("@system-service") - exp("@privileged") - exp("@resources")) | {"setfsuid"}
f = seccomp.SyscallFilter(defaction=seccomp.KILL_PROCESS)
n = 0
import errno
# RestrictAddressFamilies=AF_UNIX: systemd makes socket() fail with EAFNOSUPPORT for every other family
f.add_rule(seccomp.ALLOW, "socket", seccomp.Arg(0, seccomp.EQ, 1))
f.add_rule(seccomp.ERRNO(errno.EAFNOSUPPORT), "socket", seccomp.Arg(0, seccomp.NE, 1))
allowed.discard("socket")
for name in sorted(allowed):
    try:
        f.add_rule(seccomp.ALLOW, name); n += 1
    except Exception:
        pass
f.load()
os.execvp(sys.argv[1], sys.argv[1:])
