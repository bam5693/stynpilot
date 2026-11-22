"""Ubuntu package operations for the installer: fixed command lines, no shell, parsed output.

Every command is a fixed argument list built here. Package names and versions come only
from an already validated plan. Nothing an AI typed is ever part of a command line.
``run(argv) -> (returncode, stdout)`` is injectable, so tests use a fake machine.
"""
from __future__ import annotations

import os
import re
import subprocess

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
       "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"}
_PKG = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_VER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:~.+-]{0,127}\Z")
# apt-get -s lines look like: "Inst htop (3.3.0-4build1 Ubuntu:24.04/noble [amd64])"
# or, for an upgrade: "Inst libfoo [1.0-1] (1.1-1 Ubuntu:24.04/noble [amd64])"
_INST = re.compile(r"^Inst (\S+)(?: \[(\S+)\])? \((\S+) ")
_REMV = re.compile(r"^(Remv|Purg) (\S+)")


def real_run(argv, timeout=1800):
    result = subprocess.run(argv, env=ENV, capture_output=True, text=True, timeout=timeout, check=False,
                            stdin=subprocess.DEVNULL)
    return result.returncode, result.stdout


def _pins(packages):
    pins = []
    for name, version in packages:
        if not _PKG.fullmatch(name) or not _VER.fullmatch(version):
            raise ValueError("invalid package pin")
        pins.append("%s=%s" % (name, version))
    return pins


def simulate_install(names_or_pins, run=real_run):
    """What apt WOULD do: ({package: new_version}, [removed]). Read-only; works as any user."""
    code, out = run(["apt-get", "-s", "-q", "-y", "--no-install-recommends", "install", "--", *names_or_pins])
    if code != 0:
        raise RuntimeError("apt_simulation_failed")
    installs, removals = {}, []
    for line in out.splitlines():
        m = _INST.match(line)
        if m:
            installs[m.group(1)] = m.group(3)
            continue
        r = _REMV.match(line)
        if r:
            removals.append(r.group(2))
    return installs, removals


def resolve(names, run=real_run):
    """At request time: the exact full set (requested packages AND dependencies) with versions.

    Returns a sorted list of {"name", "version"}. Any removal makes it refuse: a catalog
    install must never remove something.
    """
    if not names or not all(isinstance(n, str) and _PKG.fullmatch(n) for n in names):
        raise ValueError("invalid package names")
    installs, removals = simulate_install(list(names), run)
    if removals:
        raise RuntimeError("would_remove_packages")
    return [{"name": n, "version": v} for n, v in sorted(installs.items())]


def installed_versions(names, run=real_run):
    """{name: version or None} for the given packages, read from dpkg."""
    code, out = run(["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\t${db:Status-Abbrev}\\n", "--", *names])
    found = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii"):
            found[parts[0]] = parts[1]
    return {name: found.get(name) for name in names}


def install(packages, run=real_run):
    argv = ["apt-get", "install", "-q", "-y", "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confold", "--", *_pins(packages)]
    return run(argv)[0] == 0


def remove(names, run=real_run):
    """Remove packages but KEEP their configuration files (retire, don't purge)."""
    if not all(_PKG.fullmatch(n) for n in names):
        raise ValueError("invalid package names")
    return run(["apt-get", "remove", "-q", "-y", "--", *names])[0] == 0


def simulate_remove(names, run=real_run):
    return run(["apt-get", "-s", "-q", "-y", "remove", "--", *names])[0] == 0


def is_root():
    return os.geteuid() == 0
