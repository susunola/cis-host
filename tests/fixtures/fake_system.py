"""In-memory fake shell + filesystem for CI rule-verification fixtures.

cis_engine.py's per-family check/fix functions never touch subprocess or
the filesystem directly -- they always go through a small boundary layer
of module-level helpers: sh()/out() for commands, and
read()/readlines()/exists()/atomic_write()/conf_values()/have() for the
filesystem. FakeSystem is a drop-in stand-in for that entire boundary,
so tests can exercise the *real* check/fix business logic (regex
parsing, idempotent file rewriting, dispatch) without executing any real
command or touching the real host filesystem.

Command dispatch models the handful of real-world tools the 5 initial
rule families (kmod, sysctl, svc_enabled, svc_disabled, pkg_present)
shell out to: systemctl, modprobe, lsmod, sysctl, and the apt/rpm/zypper
package-manager family. State lives in plain dicts (`services`, `kmods`,
`sysctls`, `packages`) that fixtures mutate directly to describe a
starting system state, and that check/fix functions read and mutate
through the faked sh() exactly as they would on a real host.
"""

import fnmatch
import re

_SYSTEMCTL_VERBS = (
    "is-enabled", "is-active", "list-unit-files",
    "stop", "disable", "enable", "mask", "unmask",
)


class FakeSystem:
    def __init__(self):
        self.files = {}      # path -> content (str)
        self.calls = []       # recorded argv, for test assertions
        self.services = {}    # unit -> {"enabled": bool, "active": bool, "masked": bool}
        self.kmods = {}       # module -> {"loaded": bool, "blocked": bool, "blacklisted": bool, "built": bool}
        self.sysctls = {}     # key -> str value
        self.packages = set()  # installed package names
        self.pkg_manager = "apt-get"
        self._extra_handlers = []

    # -- filesystem -----------------------------------------------------

    def write(self, path, content):
        self.files[path] = content

    def read(self, path):
        return self.files.get(path)

    def exists(self, path):
        return path in self.files

    def conf_values(self, files, key, seps=(r"\s+", r"\s*=\s*")):
        """Fake stand-in for cis_engine.py's conf_values(): scans
        self.files instead of the real disk/glob.
        """
        found = []
        for spec in files:
            is_glob = any(c in spec for c in "*?[")
            candidates = [p for p in self.files if fnmatch.fnmatch(p, spec)] if is_glob else [spec]
            for path in sorted(candidates):
                content = self.files.get(path)
                if content is None:
                    continue
                for ln in content.splitlines():
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    for sep in seps:
                        m = re.match(r"^\s*\$?" + re.escape(key) + sep + r"(.*)$", s, re.I)
                        if m:
                            found.append((path, m.group(1).split("#")[0].strip()))
                            break
        return found

    # -- ad hoc command handlers (for families beyond the 5 built-ins) --

    def add_handler(self, prefix, handler):
        """Register a handler for commands starting with `prefix` (a
        list/tuple of leading argv tokens). Checked before the built-in
        dispatch table, so tests can override or extend behavior.
        """
        self._extra_handlers.append((tuple(prefix), handler))

    # -- command dispatch -------------------------------------------------

    def run(self, cmd, timeout=60):
        """Fake stand-in for cis_engine.py's sh(): returns (rc, out, err)."""
        self.calls.append(list(cmd))
        for prefix, handler in self._extra_handlers:
            if tuple(cmd[:len(prefix)]) == prefix:
                return handler(cmd)
        dispatch = {
            "systemctl": self._systemctl,
            "modprobe": self._modprobe,
            "lsmod": self._lsmod,
            "sysctl": self._sysctl,
            "dpkg": self._dpkg,
            "apt-get": self._apt_get,
            "rpm": self._rpm,
            "zypper": self._zypper,
            "dnf": self._dnf_yum,
            "yum": self._dnf_yum,
        }
        fn = dispatch.get(cmd[0]) if cmd else None
        if fn is None:
            return 127, "", "FakeSystem: unhandled command %r" % (cmd,)
        return fn(cmd)

    # -- systemd ----------------------------------------------------------

    def _systemctl(self, cmd):
        verb = next((t for t in cmd[1:] if t in _SYSTEMCTL_VERBS), None)
        unit = cmd[-1] if cmd else None
        if verb == "list-unit-files":
            if unit in self.services:
                return 0, "%s.service                    enabled" % unit, ""
            return 1, "0 unit files listed.", ""
        if verb == "is-enabled":
            st = self.services.get(unit)
            if st is None:
                return 1, "not-found", ""
            return (0 if st.get("enabled") else 1), ("enabled" if st.get("enabled") else "disabled"), ""
        if verb == "is-active":
            st = self.services.get(unit)
            if st is None:
                return 3, "inactive", ""
            return (0 if st.get("active") else 3), ("active" if st.get("active") else "inactive"), ""
        # Mutating verbs implicitly register the unit if unknown (mirrors
        # systemctl accepting operations even on units it hasn't seen
        # queried yet in this fake).
        st = self.services.setdefault(unit, {"enabled": False, "active": False})
        if verb == "stop":
            st["active"] = False
        elif verb == "disable":
            st["enabled"] = False
            if "--now" in cmd:
                st["active"] = False
        elif verb == "enable":
            st["enabled"] = True
            if "--now" in cmd:
                st["active"] = True
        elif verb == "mask":
            st["masked"] = True
            st["enabled"] = False
        elif verb == "unmask":
            st["masked"] = False
        else:
            return 127, "", "FakeSystem: unhandled systemctl verb in %r" % (cmd,)
        return 0, "", ""

    # -- kernel modules -----------------------------------------------------

    def _modprobe(self, cmd):
        if "--showconfig" in cmd:
            # Real modprobe --showconfig reflects every install/blacklist
            # directive across /etc/modprobe.d/*.conf (and friends). Mirror
            # that by scanning both the dict-based flags (convenient for
            # generators seeding state directly) AND any config file
            # content actually written via write_file()/set_kv_in_file()
            # (e.g. by f_kmod's real remediation), so a fix that persists
            # to disk is visible on the next check without special-casing.
            lines = []
            for mod, st in self.kmods.items():
                if st.get("blocked"):
                    lines.append("install %s /bin/false" % mod)
                if st.get("blacklisted"):
                    lines.append("blacklist %s" % mod)
            for content in self.files.values():
                for ln in content.splitlines():
                    s = ln.strip()
                    if s.startswith("install ") or s.startswith("blacklist "):
                        lines.append(s)
            return 0, "\n".join(lines), ""
        if "-r" in cmd:
            mod = cmd[-1]
            self.kmods.setdefault(mod, {})["loaded"] = False
            return 0, "", ""
        if "-n" in cmd and "-v" in cmd:
            mod = cmd[-1]
            st = self.kmods.get(mod, {})
            if st.get("built", True) is False:
                return 1, "", "modprobe: FATAL: Module %s not found in directory" % mod
            return 0, "insmod /lib/modules/fake/%s.ko" % mod, ""
        return 0, "", ""

    def _lsmod(self, cmd):
        lines = ["Module                  Size  Used by"]
        for mod, st in self.kmods.items():
            if st.get("loaded"):
                lines.append("%-24s 16384  0" % mod)
        return 0, "\n".join(lines), ""

    # -- sysctl -------------------------------------------------------------

    def _sysctl(self, cmd):
        if "-n" in cmd:
            key = cmd[-1]
            val = self.sysctls.get(key)
            if val is None:
                return 1, "", "sysctl: cannot stat /proc/sys/%s: No such file or directory" % key.replace(".", "/")
            return 0, str(val), ""
        if "-w" in cmd:
            kv = cmd[-1]
            key, _, val = kv.partition("=")
            self.sysctls[key] = val
            return 0, "%s = %s" % (key, val), ""
        return 0, "", ""

    # -- package managers -----------------------------------------------------

    def _dpkg(self, cmd):
        if cmd[1:2] == ["-s"]:
            pkg = cmd[2]
            if pkg in self.packages:
                return 0, "Status: install ok installed", ""
            return 1, "", "package '%s' is not installed" % pkg
        return 0, "", ""

    def _apt_get(self, cmd):
        return self._generic_pkg_cmd(cmd, install_verb="install", remove_verb="remove")

    def _rpm(self, cmd):
        if cmd[1:2] == ["-q"]:
            pkg = cmd[2]
            if pkg in self.packages:
                return 0, "%s-1.0-1.fake.x86_64" % pkg, ""
            return 1, "", "package %s is not installed" % pkg
        return 0, "", ""

    def _zypper(self, cmd):
        return self._generic_pkg_cmd(cmd, install_verb="install", remove_verb="remove")

    def _dnf_yum(self, cmd):
        return self._generic_pkg_cmd(cmd, install_verb="install", remove_verb="remove")

    def _generic_pkg_cmd(self, cmd, install_verb, remove_verb):
        if install_verb in cmd:
            pkgs = [c for c in cmd[cmd.index(install_verb) + 1:] if not c.startswith("-")]
            self.packages.update(pkgs)
            return 0, "", ""
        if remove_verb in cmd:
            pkgs = [c for c in cmd[cmd.index(remove_verb) + 1:] if not c.startswith("-")]
            self.packages.difference_update(pkgs)
            return 0, "", ""
        return 0, "", ""
