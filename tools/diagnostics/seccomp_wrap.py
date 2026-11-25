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
# RestrictSUIDSGID=yes: systemd answers openat2 with ENOSYS (it cannot inspect openat2's mode) -- the live Ryzen probe confirmed 38
f.add_rule(seccomp.ERRNO(errno.ENOSYS), "openat2")
allowed.discard("openat2")
# RestrictSUIDSGID=yes also refuses (EPERM) setting setuid/setgid bits: chmod-family mode argument, and creating files with them
for name, arg in (("chmod", 1), ("fchmod", 1), ("fchmodat", 2), ("fchmodat2", 2), ("creat", 1), ("mkdir", 1), ("mkdirat", 2),
                  ("mknod", 1), ("mknodat", 2), ("open", 2), ("openat", 3)):
    try:
        f.add_rule(seccomp.ALLOW, name, seccomp.Arg(arg, seccomp.MASKED_EQ, 0o6000, 0))
        for bit in (0o4000, 0o2000):
            f.add_rule(seccomp.ERRNO(errno.EPERM), name, seccomp.Arg(arg, seccomp.MASKED_EQ, bit, bit))
        allowed.discard(name)
    except Exception:
        pass
for name in sorted(allowed):
    try:
        f.add_rule(seccomp.ALLOW, name); n += 1
    except Exception:
        pass
f.load()
os.execvp(sys.argv[1], sys.argv[1:])
