"""A small fake Ubuntu machine: answers the exact apt-get / apt-cache / apt-mark / dpkg-query commands the installer uses.

Models what the safety checks depend on: package origins, a download cache that ``--no-download``
must honour, old versions that may or may not still be downloadable, conffiles on disk,
auto/manual marks, and packages that depend on others (so removing could cascade).
"""
from pathlib import Path


class FakeMachine:
    def __init__(self, installed=None, available=None, deps=None, *, file_root=None):
        self.installed = dict(installed or {})          # name -> version
        self.available = dict(available or {})          # name -> candidate version
        self.deps = dict(deps or {})                     # name -> [dependency names]
        self.archive = {}                                # name -> {older versions still downloadable}
        self.origin = {}                                 # name -> "Evil" for a non-Ubuntu source (default Ubuntu)
        self.conffiles = {}                              # name -> [absolute paths]
        self.rdeps = {}                                  # name -> [installed packages that need it]
        self.manual = set(self.installed)
        self.file_root = Path(file_root) if file_root else None
        self.commands, self.fail_install = [], False
        self.removes_on_install = []                     # shows up in the simulation
        self.extra_on_install = {}                       # silently installed by the real install
        self.also_offered_by = {}                        # name -> "Evil": same version also in a third-party source
        self.sim_origin = {}                             # name -> origin text apt would report when simulating
        self.config = []                                 # extra `apt-config dump` lines
        self.bad_hash = set()                            # names whose index hash differs from the file apt fetches
        self.ambiguous_hash = set()                      # names listed with two different hashes
        self.config_ok = True
        self.fail_state_while_installed = None           # name: the full dpkg listing fails while it is installed
        self.fail_remove = False

    def changes(self):
        return [c for c in self.commands if c[:2] in (["apt-get", "install"], ["apt-get", "remove"])
                and "-s" not in c and "--download-only" not in c]

    def _closure(self, names):
        out, todo = [], list(names)
        while todo:
            name = todo.pop(0)
            if name not in out:
                out.append(name)
                todo.extend(self.deps.get(name, []))
        return out

    @staticmethod
    def _cache(argv):
        for i, a in enumerate(argv):
            if a == "-o" and argv[i + 1].startswith("Dir::Cache::archives="):
                return Path(argv[i + 1].split("=", 1)[1])
        return None

    def _downloadable(self, name, version):
        return version in (self.available.get(name),) or version in self.archive.get(name, ())

    def _plan(self, targets):
        pins = {t.split("=")[0]: (t.split("=", 1)[1] if "=" in t else None) for t in targets}
        order = self._closure(pins)
        return [(n, pins.get(n) or self.available.get(n)) for n in order]

    def __call__(self, argv):
        self.commands.append(list(argv))
        tool = argv[0]
        if tool == "dpkg-query":
            if "--" in argv and "${Conffiles}\\n" in argv:
                name = argv[argv.index("--") + 1]
                return 0, "".join(" %s abcdef\n" % p for p in self.conffiles.get(name, []))
            if "--" in argv:                                   # per-package query: only these, installed ones
                names = argv[argv.index("--") + 1:]
                return (0 if all(n in self.installed for n in names) else 1,
                        "".join("%s\t%s\tii \n" % (n, self.installed[n]) for n in names if n in self.installed))
            if self.fail_state_while_installed in self.installed:
                return 2, ""
            return 0, "".join("%s\t%s\tii \n" % (n, v) for n, v in sorted(self.installed.items()))
        if tool == "apt-mark":
            if argv[1] == "showmanual":
                return 0, "".join(n + "\n" for n in sorted(self.manual & set(self.installed)))
            names = set(argv[argv.index("--") + 1:])
            self.manual = (self.manual | names) if argv[1] == "manual" else (self.manual - names)
            return 0, ""
        if tool == "apt-config":
            return (0, "".join(l + "\n" for l in ["Acquire::Languages \"none\";", *self.config])) if self.config_ok else (1, "")
        if tool == "apt-cache" and argv[1] == "show":
            name, _, version = argv[-1].partition("=")
            if not self._downloadable(name, version):
                return 100, "E: no such version\n"
            import hashlib
            digest = hashlib.sha256(b"deb:%s:%s" % (name.encode(), version.encode())).hexdigest()
            if name in self.bad_hash:
                digest = "0" * 64
            out = "Package: %s\nVersion: %s\nSHA256: %s\n" % (name, version, digest)
            if name in self.ambiguous_hash:
                out += "\nPackage: %s\nVersion: %s\nSHA256: %s\n" % (name, version, "1" * 64)
            return 0, out
        if tool == "apt-cache":
            return self._policy(argv)
        if tool != "apt-get":
            return 127, ""
        targets = argv[argv.index("--") + 1:] if "--" in argv else []
        cache, simulate = self._cache(argv), "-s" in argv
        verb = "remove" if "remove" in argv else "install"
        if verb == "remove":
            names = list(targets)
            todo = list(names)
            while todo:                                   # dependents go too
                for dependent in self.rdeps.get(todo.pop(), []):
                    if dependent in self.installed and dependent not in names:
                        names.append(dependent)
                        todo.append(dependent)
            if self.fail_remove and not simulate:
                return 100, "E: remove failed\n"
            if simulate:
                return 0, "".join("Remv %s [%s]\n" % (t, self.installed[t]) for t in names if t in self.installed)
            for name in names:
                self.installed.pop(name, None)
                self.manual.discard(name)
            return 0, ""
        plan = self._plan(targets)
        for name, version in plan:
            pinned = any(t.split("=")[0] == name and "=" in t for t in targets)
            if version is None or (pinned and not self._downloadable(name, version)
                                   and version != self.installed.get(name)):
                return 100, "E: Version not found\n"
            if pinned and self.installed.get(name) and self.installed[name] != version and "--allow-downgrades" not in argv \
                    and version != self.available.get(name):
                return 100, "E: Packages were downgraded and -y was used without --allow-downgrades.\n"
        if "--download-only" in argv:
            if any(not self._downloadable(n, v) for n, v in plan):
                return 100, "E: Version not found (not in any archive)\n"
            for name, version in plan:
                (cache / ("%s_%s_amd64.deb" % (name, version.replace(":", "%3a")))).write_bytes(b"deb:%s:%s" % (name.encode(), version.encode()))
            return 0, ""
        if "--no-download" in argv:
            for name, version in plan:
                if self.installed.get(name) != version and not (cache and (cache / ("%s_%s_amd64.deb" % (name, version))).exists()):
                    return 100, "E: Can't download %s (no-download)\n" % name
        if simulate:
            lines = []
            for name, version in plan:
                if self.installed.get(name) != version:
                    old = self.installed.get(name)
                    origin = self.sim_origin.get(name, "Ubuntu:24.04/noble")
                    lines.append("Inst %s%s (%s %s [amd64])\n" % (name, " [%s]" % old if old else "", version, origin))
            return 0, "".join(lines) + "".join("Remv %s [1]\n" % r for r in self.removes_on_install)
        if self.fail_install:
            name, version = plan[0]
            self.installed[name] = version                    # half-done install
            return 100, "E: dpkg was interrupted\n"
        for name, version in plan:
            if self.installed.get(name) != version:
                if name not in self.installed:
                    self.manual.add(name)
                self.installed[name] = version
                if self.file_root:                             # dpkg replaces the package's settings files
                    for path in self.conffiles.get(name, []):
                        target = self.file_root / path.lstrip("/")
                        if target.exists():
                            target.write_text("config from %s\n" % version)
        self.installed.update(self.extra_on_install)
        return 0, ""

    def _policy(self, argv):
        sources = [("http://archive.ubuntu.com/ubuntu", "noble/main", "Ubuntu"),
                   ("http://ppa.example.test/evil", "noble/main", "Evil")]
        if len(argv) == 2:
            out = "Package files:\n"
            for url, suite, origin in sources:
                out += " 500 %s %s amd64 Packages\n     release v=24.04,o=%s,a=noble,n=noble,l=%s,c=main,b=amd64\n" % (
                    url, suite, origin, origin)
            return 0, out
        name = argv[-1]
        versions = {self.available.get(name), self.installed.get(name), *self.archive.get(name, ())} - {None}
        out = "%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n" % (
            name, self.installed.get(name, "(none)"), self.available.get(name, "(none)"))
        for version in sorted(versions):
            out += "     %s 500\n" % version
            origin = self.origin.get(name, "Ubuntu")
            url, suite, _ = next(s for s in sources if s[2] == origin)
            out += "        500 %s %s amd64 Packages\n" % (url, suite)
            if name in self.also_offered_by:
                url2, suite2, _ = next(x for x in sources if x[2] == self.also_offered_by[name])
                out += "        500 %s %s amd64 Packages\n" % (url2, suite2)
        return 0, out
