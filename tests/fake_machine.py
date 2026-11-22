"""A tiny fake Ubuntu machine: answers the exact apt-get / dpkg-query commands the installer uses."""


class FakeMachine:
    def __init__(self, installed=None, available=None, deps=None):
        self.installed = dict(installed or {})          # name -> version
        self.available = dict(available or {})          # name -> candidate version
        self.deps = dict(deps or {})                     # name -> [dependency names]
        self.commands, self.fail_install, self.removes_on_install = [], False, []

    def changes(self):
        return [c for c in self.commands if c[:2] in (["apt-get", "install"], ["apt-get", "remove"])]

    def _closure(self, names):
        out, todo = [], list(names)
        while todo:
            name = todo.pop(0)
            if name not in out:
                out.append(name)
                todo.extend(self.deps.get(name, []))
        return out

    def __call__(self, argv):
        self.commands.append(list(argv))
        args = [a for a in argv if not a.startswith("-") and a != "--"]
        if argv[0] == "dpkg-query":
            names = argv[argv.index("--") + 1:]
            return 0, "".join("%s\t%s\tii \n" % (n, self.installed[n]) for n in names if n in self.installed)
        if argv[:2] == ["apt-get", "-s"]:
            verb = "install" if "install" in argv else "remove"
            targets = argv[argv.index("--") + 1:]
            if verb == "remove":
                return 0, "".join("Remv %s [%s]\n" % (t, self.installed[t]) for t in targets if t in self.installed)
            lines = []
            for target in self._closure([t.split("=")[0] for t in targets]):
                pin = next((t.split("=", 1)[1] for t in targets if "=" in t and t.split("=")[0] == target), None)
                version = pin or self.available.get(target)
                if version is None or (pin and pin not in (self.available.get(target), self.installed.get(target))
                                       and "--allow-downgrades" not in argv):
                    return 100, "E: Version not found\n"
                if self.installed.get(target) != version:
                    old = self.installed.get(target)
                    lines.append("Inst %s%s (%s Ubuntu:24.04/noble [amd64])\n" % (target, " [%s]" % old if old else "", version))
            lines += ["Remv %s [1]\n" % r for r in self.removes_on_install]
            return 0, "".join(lines)
        if argv[:2] == ["apt-get", "install"]:
            if self.fail_install:
                first = argv[argv.index("--") + 1].split("=")
                self.installed[first[0]] = first[1]               # half-done install
                return 100, "E: dpkg was interrupted\n"
            for target in argv[argv.index("--") + 1:]:
                name, version = target.split("=")
                self.installed[name] = version
            return 0, ""
        if argv[:2] == ["apt-get", "remove"]:
            for name in argv[argv.index("--") + 1:]:
                self.installed.pop(name, None)
            return 0, ""
        return 127, ""
