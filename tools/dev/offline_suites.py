"""Run offline candidate tests in disposable namespaces with no host home or host service sockets."""
from pathlib import Path
import os
import subprocess
import sys

if len(sys.argv) < 3:
    raise SystemExit("usage: offline_suites.py PREPARED_WORK_DIRECTORY normal sandbox check")
work = Path(sys.argv[1]).resolve()
if os.geteuid() == 0:
    raise SystemExit("run offline suites as a normal user")
base = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/sbin', '/sbin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/run',
        '--size', '268435456', '--tmpfs', '/tmp', '--dir', '/home/test']
for path in ['/etc/passwd', '/etc/group', '/etc/alternatives', '/etc/os-release', '/etc/ld.so.cache',
             '/etc/ssl/certs/ca-certificates.crt', '/var/lib/dpkg']:
    base += ['--ro-bind', path, path]
for name in ['src', 'cache', 'vendor']:
    base += ['--ro-bind', str(work / name), '/work/' + name]
base += ['--ro-bind', str(work / 'vendor'), '/tmp/deps/lib/python3.14/site-packages',
         '--setenv', 'PYTHONUSERBASE', '/tmp/deps', '--setenv', 'PATH', '/usr/sbin:/usr/bin:/sbin:/bin',
         '--setenv', 'HOME', '/tmp', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
         '--setenv', 'PYTHONPATH', '/work/src/src:/work/vendor', '--chdir', '/work/src']
pytest = ['/usr/bin/python3', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests']
normal = base + pytest + ['--ignore=tests/test_g7.py', '--ignore=tests/test_compat_check.py']
seccomp_dir = str(work / 'seccomp/usr/lib/python3/dist-packages')
release = base + ['--uid', '992', '--gid', '992', '--ro-bind', seccomp_dir, '/test-seccomp',
                  '--setenv', 'PYTHONPATH', '/work/src/src:/work/vendor:/test-seccomp',
                  '/usr/bin/setpriv', '--no-new-privs', '/bin/sh', '-ec',
                  'umask 077; ulimit -n 1024; ulimit -c 0; ulimit -f 1048576; '
                  'exec /usr/bin/python3 tools/diagnostics/seccomp_wrap.py "$@"', 'sandbox'] + pytest
commands = {'normal': normal, 'sandbox': release, 'check': base + ['./scripts/check.sh']}
runs = []
for name in sys.argv[2:]:
    log = (work / (name + '-suite.log')).open('w')
    runs.append((name, subprocess.Popen(commands[name], stdout=log, stderr=subprocess.STDOUT), log))
failed = False
for name, proc, log in runs:
    code = proc.wait()
    failed |= code != 0
    print(name, "exit", code, flush=True)
    log.close()
    lines = (work / (name + "-suite.log")).read_text(errors="replace").splitlines()
    print("\n".join(lines[-4:]), flush=True)
raise SystemExit(1 if failed else 0)
