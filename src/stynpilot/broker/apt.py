"""Ubuntu package operations for the installer: fixed command lines, no shell, parsed output.

Every command is a fixed argument list built here. Package names and versions come only
from an already validated plan. Nothing an AI typed is ever part of a command line.
``run(argv) -> (returncode, stdout)`` is injectable, so tests use a fake machine.

Safety building blocks used by the executor:
- ``untrusted_sources``: refuse if any apt source is configured with trusted=yes or
  allow-insecure (signature checks switched off);
- ``origin_is_ubuntu``: every package version must come from a source whose signed
  Release file says Origin Ubuntu and Label Ubuntu (the catalog promises the Ubuntu archive);
- ``download``: fetch the exact .deb files into a root-only folder first (apt checks
  them against the signed index), then simulate and install with ``--no-download``, so
  the archive changing in between can't add anything;
- ``state``: the complete dpkg package list, so before/after diffs prove that nothing
  outside the approved set changed.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
       "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"}
_PKG = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}\Z")
_VER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:~.+-]{0,127}\Z")
# apt-get -s lines: "Inst htop (3.3.0-4build1 Ubuntu:24.04/noble [amd64])"
# upgrade/downgrade: "Inst libfoo [1.0-1] (1.1-1 Ubuntu:24.04/noble [amd64])"
_INST = re.compile(r"^Inst (\S+)(?: \[(\S+)\])? \((\S+) (.*?)\s*\[")
_REMV = re.compile(r"^(Remv|Purg) (\S+)")
_SOURCE_LINE = re.compile(r"^\s+(-?\d+) (\S+) (\S+) (\S+) Packages$")
_BAD_CONFIG = ("allowunauthenticated", "allowinsecurerepositories", "allowdowngradetoinsecurerepositories",
               "allowweakrepositories")
# Always passed to apt on top of whatever the machine's config says: signatures stay on, nothing may be removed.
SAFE_OPTS = ["-o", "APT::Get::AllowUnauthenticated=false", "-o", "Acquire::AllowInsecureRepositories=false",
             "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "-o", "Acquire::AllowWeakRepositories=false"]
_INSECURE = re.compile(r"trusted\s*[=:]\s*yes|allow-insecure|allow-weak|allow-downgrade-to-insecure", re.I)


def real_run(argv, timeout=1800):
    result = subprocess.run(argv, env=ENV, capture_output=True, text=True, timeout=timeout, check=False,
                            stdin=subprocess.DEVNULL)
    return result.returncode, result.stdout


def _check_names(names):
    if not names or not all(isinstance(n, str) and _PKG.fullmatch(n) for n in names):
        raise ValueError("invalid package names")
    return list(names)


def _pins(packages):
    pins = []
    for name, version in packages:
        if not _PKG.fullmatch(name) or not _VER.fullmatch(version):
            raise ValueError("invalid package pin")
        pins.append("%s=%s" % (name, version))
    return pins


def _cache_opts(cache):
    return [] if cache is None else ["-o", "Dir::Cache::archives=%s" % cache]


def parse_transaction(out):
    """({package: new_version}, {package: old_version or None}, [removed], {package: [origins]}) from apt-get -s."""
    installs, olds, removals, origins = {}, {}, [], {}
    for line in out.splitlines():
        m = _INST.match(line)
        if m:
            installs[m.group(1)] = m.group(3)
            olds[m.group(1)] = m.group(2)
            origins[m.group(1)] = [o.strip() for o in m.group(4).split(",") if o.strip()]
            continue
        r = _REMV.match(line)
        if r:
            removals.append(r.group(2))
    return installs, olds, removals, origins


def simulate_install(names_or_pins, run=real_run, *, cache=None, no_download=False, allow_downgrades=False,
                     with_origins=False):
    argv = ["apt-get", "-s", "-q", "-y", "--no-install-recommends", *SAFE_OPTS, *_cache_opts(cache)]
    if no_download:
        argv.append("--no-download")
    if allow_downgrades:
        argv.append("--allow-downgrades")
    code, out = run(argv + ["install", "--", *names_or_pins])
    if code != 0:
        raise RuntimeError("apt_simulation_failed")
    installs, _, removals, origins = parse_transaction(out)
    return (installs, removals, origins) if with_origins else (installs, removals)


def simulate_remove(names, run=real_run):
    """[removed packages] apt WOULD remove, including anything that depends on them."""
    code, out = run(["apt-get", "-s", "-q", "-y", "remove", "--", *_check_names(names)])
    if code != 0:
        raise RuntimeError("apt_simulation_failed")
    return parse_transaction(out)[2]


def resolve(names, run=real_run):
    """At request time: the exact full set (requested packages AND dependencies) with versions.

    Returns a sorted list of {"name", "version"}. Any removal makes it refuse: a catalog
    install must never remove something.
    """
    installs, removals = simulate_install(_check_names(names), run)
    if removals:
        raise RuntimeError("would_remove_packages")
    return [{"name": n, "version": v} for n, v in sorted(installs.items())]


def untrusted_sources(sources_root="/etc/apt"):
    """Names of apt source files that switch off signature checking OR can't be read (should be empty).

    Fail closed: a source file that exists but can't be read counts as untrusted.
    """
    root = Path(sources_root)
    found = []
    try:
        listing = sorted((root / "sources.list.d").glob("*"))
    except OSError:
        return ["sources.list.d"]
    for path in [root / "sources.list", *listing]:
        try:
            if not path.exists():
                continue
            text = path.read_text(errors="replace")
        except OSError:
            found.append(path.name)
            continue
        if any(_INSECURE.search(line) for line in text.splitlines() if not line.lstrip().startswith("#")):
            found.append(path.name)
    return found


def insecure_config(run=real_run):
    """Effective apt settings (``apt-config dump``) that weaken signature checks. Unreadable config -> refuse."""
    code, out = run(["apt-config", "dump"])
    if code != 0 or not out.strip():
        return ["apt_config_unreadable"]
    bad = []
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        if value.strip().strip(";").strip('"').lower() in ("true", "1", "yes", "on") \
                and any(word in key.lower().replace("-", "") for word in _BAD_CONFIG):
            bad.append(key)
    return bad


_QUERY = re.compile(r"[A-Za-z0-9][A-Za-z0-9 +._-]{0,39}\Z")
SEARCH_SCAN = 40            # candidates examined per search (each needs an origin check)


def check_query(query):
    if not isinstance(query, str) or not _QUERY.fullmatch(query.strip()):
        raise ValueError("invalid search text")
    return query.strip()


def package_info(names, run=real_run):
    """{name: {version, essential, priority, section, installed_size_kb, description}} for the CANDIDATE version.

    Reads the local signed package indexes only (``apt-cache show``); never the network.
    """
    code, out = run(["apt-cache", "show", "--no-all-versions", "--", *_check_names(names)])
    info = {}
    for stanza in out.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields.setdefault(key.strip(), value.strip())
        name = fields.get("Package")
        if name and name not in info:
            try:
                size = int(fields.get("Installed-Size", "0"))
            except ValueError:
                size = 0
            info[name] = {"version": fields.get("Version", ""), "essential": fields.get("Essential", "").lower() == "yes",
                          "priority": fields.get("Priority", ""), "section": fields.get("Section", ""),
                          "installed_size_kb": size, "description": fields.get("Description", "")[:160]}
    return info


def search(query, run=real_run, *, limit=8):
    """Ubuntu-archive packages whose NAME matches the text. [{name, version, summary, section, installed}]

    Only packages whose candidate version is offered by the signed Ubuntu archive are listed. Bounded.
    """
    query = check_query(query)
    code, out = run(["apt-cache", "search", "--names-only", "--", query])
    if code != 0:
        raise RuntimeError("apt_search_failed")
    names = []
    for line in out.splitlines():
        name = line.split(" - ", 1)[0].strip()
        if _PKG.fullmatch(name) and name not in names:
            names.append(name)
    names.sort(key=lambda n: (n != query.lower(), len(n), n))
    names = names[:SEARCH_SCAN]
    if not names:
        return []
    info = package_info(names, run)
    installed = installed_versions([n for n in names if n in info], run) if info else {}
    found = []
    for name in names:
        meta = info.get(name)
        if meta and meta["version"] and origin_is_ubuntu(name, meta["version"], run):
            found.append({"name": name, "version": meta["version"], "summary": meta["description"],
                          "section": meta["section"], "installed": installed.get(name)})
        if len(found) >= limit:
            break
    return found


def analyze(names, run=real_run):
    """Simulate installing exactly these names (no changes made). Everything the impact gate and the owner need.

    {"installs": {name: version}, "upgrades": {name: old_version}, "removals": [...], "origins": {name: [...]},
     "meta": {name: package_info}}. Raises RuntimeError("apt_simulation_failed") if apt cannot resolve them.
    """
    argv = ["apt-get", "-s", "-q", "-y", "--no-install-recommends", *SAFE_OPTS, "install", "--", *_check_names(names)]
    code, out = run(argv)
    if code != 0:
        raise RuntimeError("apt_simulation_failed")
    installs, olds, removals, origins = parse_transaction(out)
    meta = package_info(sorted(installs), run) if installs else {}
    return {"installs": installs, "upgrades": {n: o for n, o in olds.items() if o}, "removals": removals,
            "origins": origins, "meta": meta}


def deb_listing(path, run=real_run):
    """``dpkg-deb -c`` of a downloaded package (a list of the files it will install); '' if unreadable."""
    code, out = run(["dpkg-deb", "-c", str(path)])
    return out if code == 0 else ""


def deb_script(path, which="postinst", run=real_run):
    """Text of one maintainer script of a downloaded package ('' if it has none)."""
    if which not in ("preinst", "postinst"):
        raise ValueError("invalid script")
    code, out = run(["dpkg-deb", "-I", str(path), which])
    return out if code == 0 else ""


def sha256_of_version(name, version, run=real_run):
    """The set of SHA256 values the package indexes list for this exact version (one value if unambiguous)."""
    code, out = run(["apt-cache", "show", "--", "%s=%s" % (name, version)])
    if code != 0:
        return set()
    return {line.split(":", 1)[1].strip() for line in out.splitlines() if line.startswith("SHA256:")}


def origins_trusted(origins):
    """True if the sources apt actually chose for a package are all the Ubuntu archive (apt-get -s 'Inst' origin)."""
    return bool(origins) and all(o.startswith("Ubuntu:") for o in origins)


def origin_is_ubuntu(name, version, run=real_run):
    """True if this exact version is offered by a source whose signed Release says Origin/Label Ubuntu."""
    code, global_policy = run(["apt-cache", "policy"])
    if code != 0:
        return False
    releases, current = {}, None
    for line in global_policy.splitlines():
        m = _SOURCE_LINE.match(line)
        if m:
            current = (m.group(2), m.group(3))
            continue
        stripped = line.strip()
        if current and stripped.startswith("release "):
            fields = dict(item.split("=", 1) for item in stripped[8:].split(",") if "=" in item)
            releases[current] = fields
            current = None
    code, policy = run(["apt-cache", "policy", "--", name])
    if code != 0:
        return False
    in_version = False
    offered_by_ubuntu = False
    for line in policy.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit() and not line.startswith("        "):
            in_version = parts[-2] == version or (parts[0] == "***" and parts[1] == version)
            continue
        if in_version:
            m = _SOURCE_LINE.match(line)
            if m:
                release = releases.get((m.group(2), m.group(3)), {})
                if release.get("o") == "Ubuntu" and release.get("l") == "Ubuntu":
                    offered_by_ubuntu = True
                else:
                    return False            # ambiguous: another source offers this very version
    return offered_by_ubuntu


def download(packages, cache, run=real_run):
    """Fetch the exact .deb files into ``cache`` (root-only); apt verifies them against the signed index."""
    Path(cache, "partial").mkdir(parents=True, exist_ok=True, mode=0o700)
    argv = ["apt-get", "install", "-q", "-y", "--no-remove", "--download-only", "--no-install-recommends",
            "--allow-downgrades", *SAFE_OPTS, *_cache_opts(cache), "--", *_pins(packages)]
    return run(argv)[0] == 0


def install(packages, run=real_run, *, cache=None, no_download=False, allow_downgrades=False):
    argv = ["apt-get", "install", "-q", "-y", "--no-remove", "--no-install-recommends",
            "-o", "Dpkg::Options::=--force-confold", *SAFE_OPTS, *_cache_opts(cache)]
    if no_download:
        argv.append("--no-download")
    if allow_downgrades:
        argv.append("--allow-downgrades")
    return run(argv + ["--", *_pins(packages)])[0] == 0


def remove(names, run=real_run):
    """Remove packages but KEEP their configuration files (retire, don't purge)."""
    return run(["apt-get", "remove", "-q", "-y", "--", *_check_names(names)])[0] == 0


def state(run=real_run):
    """The complete installed-package list: {package: version} for every 'ii' package."""
    code, out = run(["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\t${db:Status-Abbrev}\\n"])
    if code != 0:
        raise RuntimeError("dpkg_query_failed")
    found = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii"):
            found[parts[0]] = parts[1]
    return found


def installed_versions(names, run=real_run):
    """{name: version or None} for just these packages. Doesn't depend on the full listing working
    (recovery must still work if that listing is what broke); a missing package is simply absent."""
    code, out = run(["dpkg-query", "-W", "-f", "${Package}\\t${Version}\\t${db:Status-Abbrev}\\n", "--",
                     *_check_names(names)])
    found = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii"):
            found[parts[0]] = parts[1]
    return {name: found.get(name) for name in names}


def manual_packages(run=real_run):
    code, out = run(["apt-mark", "showmanual"])
    if code != 0:
        raise RuntimeError("apt_mark_failed")
    return set(out.split())


def set_marks(manual, auto, run=real_run):
    ok = True
    if manual:
        ok = run(["apt-mark", "manual", "--", *_check_names(sorted(manual))])[0] == 0 and ok
    if auto:
        ok = run(["apt-mark", "auto", "--", *_check_names(sorted(auto))])[0] == 0 and ok
    return ok


def conffiles(names, run=real_run):
    """Configuration files (absolute paths) that dpkg tracks for these installed packages."""
    files = []
    for name in _check_names(names):
        code, out = run(["dpkg-query", "-W", "-f", "${Conffiles}\\n", "--", name])
        if code == 0:
            for line in out.splitlines():
                parts = line.split()
                if parts and parts[0].startswith("/") and ".." not in parts[0].split("/"):
                    files.append(parts[0])
    return sorted(set(files))


def is_root():
    return os.geteuid() == 0
