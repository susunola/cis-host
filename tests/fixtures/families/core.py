"""Per-family FixtureGenerator implementations for the initial M0 scope:
kmod, sysctl, svc_enabled, svc_disabled, pkg_present.

Each generator's seed_noncompliant()/seed_compliant() mirror exactly what
the corresponding ohbs_engine.py check function inspects (see
ohbs-ubuntu2204-ansible/roles/ohbs-ubuntu2204/files/ohbs_engine.py):
  - kmod:         c_kmod() looks at `modprobe --showconfig` (install/
                  blacklist directives) and `lsmod` (currently loaded).
  - sysctl:       c_sysctl() looks at `sysctl -n <key>` (runtime value)
                  and persisted config files matching key<sep>value.
  - svc_enabled:  c_svc_enabled()/c_svc_disabled() look at
                  `systemctl is-enabled`/`is-active`, gated on
                  `systemctl list-unit-files` reporting the unit exists,
                  and optionally on package-installed state.
  - pkg_present:  c_pkg_present() looks at `dpkg -s <pkg>` (via
                  pkg_installed()).
"""

from typing import Any, Dict

from base import FixtureGenerator
from fake_system import FakeSystem


class KmodGenerator(FixtureGenerator):
    family = "kmod"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        mod = params["module"]
        # Loaded, with no install-override or blacklist entry: c_kmod()
        # flags "module is currently loaded" AND "no install .../blacklist
        # entry" -> fail.
        fs.kmods[mod] = {"loaded": True, "blocked": False, "blacklisted": False, "built": True}

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        mod = params["module"]
        fs.kmods[mod] = {"loaded": False, "blocked": False, "blacklisted": True, "built": True}


class SysctlGenerator(FixtureGenerator):
    family = "sysctl"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        for kv in params["params"]:
            key, want = kv["key"], kv["value"]
            # Set the runtime value to something that provably differs
            # from `want` for both numeric and string CIS values.
            wrong = (int(want) + 1) if str(want).lstrip("-").isdigit() else "cis-fixture-wrong"
            fs.sysctls[key] = str(wrong)

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        path = "/etc/sysctl.d/60-cis-hardening.conf"
        lines = []
        for kv in params["params"]:
            key, want = kv["key"], str(kv["value"])
            fs.sysctls[key] = want
            lines.append("%s = %s" % (key, want))
        fs.write(path, "\n".join(lines) + "\n")


class SvcEnabledGenerator(FixtureGenerator):
    family = "svc_enabled"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        for pkg in params.get("packages") or []:
            fs.packages.add(pkg)
        for unit in params.get("units") or []:
            fs.services[unit] = {"enabled": False, "active": False}

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        for pkg in params.get("packages") or []:
            fs.packages.add(pkg)
        for unit in params.get("units") or []:
            fs.services[unit] = {"enabled": True, "active": True}


class SvcDisabledGenerator(FixtureGenerator):
    family = "svc_disabled"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        for pkg in params.get("packages") or []:
            fs.packages.add(pkg)
        for unit in params.get("units") or []:
            fs.services[unit] = {"enabled": True, "active": True}

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        for pkg in params.get("packages") or []:
            fs.packages.add(pkg)
        for unit in params.get("units") or []:
            fs.services[unit] = {"enabled": False, "active": False, "masked": True}


class PkgPresentGenerator(FixtureGenerator):
    family = "pkg_present"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        # Ensure none of the required packages are present.
        fs.packages.difference_update(params["packages"])

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        fs.packages.update(params["packages"])


GENERATORS = {
    "kmod": KmodGenerator(),
    "sysctl": SysctlGenerator(),
    "svc_enabled": SvcEnabledGenerator(),
    "svc_disabled": SvcDisabledGenerator(),
    "pkg_present": PkgPresentGenerator(),
}
