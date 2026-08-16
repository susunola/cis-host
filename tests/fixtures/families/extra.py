"""FixtureGenerator implementations for M1's Top-10 target families:
the initial 5 (kmod, sysctl, svc_enabled, svc_disabled, pkg_present,
already covered by families/core.py) plus mount_opt, kv_conf, banner,
partition, and audit_immutable.

Each generator's seed_noncompliant()/seed_compliant() mirror exactly
what the corresponding ohbs_engine.py check function inspects:
  - mount_opt:       c_mount_opt() reads /proc/mounts (via readlines(),
                     faked); f_mount_opt() remounts live (fake `mount`
                     command) then rewrites /etc/fstab.
  - kv_conf:         c_kv_conf() reads target config files via
                     conf_values() (faked); most ops (ge/le_pos/umask/
                     tmout/bool_present) compare a persisted value
                     against rule["params"]["value"].
  - banner:          c_banner() reads p["path"] via read() (faked) and
                     flags OS/escape-sequence references
                     (BANNER_BAD regex); f_banner() overwrites with a
                     neutral banner.
  - partition:       c_partition() only reads /proc/mounts; there is no
                     registered fix() for this family (CIS explicitly
                     leaves partition layout to manual remediation), so
                     only seed_compliant()/seed_noncompliant() for the
                     *check* side are meaningful -- run_already_compliant()
                     is the only applicable verification for this family.
  - audit_immutable: c_audit_immutable() requires the audit package to
                     be "installed" (faked via fs.packages) and reads
                     the on-disk rules.d files (via conf_values()-style
                     scanning) plus `auditctl -s` (faked) for the
                     runtime "enabled" state; f_audit_immutable() writes
                     a finalize rule file.
"""

from typing import Any, Dict

from base import FixtureGenerator
from fake_system import FakeSystem


class MountOptGenerator(FixtureGenerator):
    family = "mount_opt"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        mp = params["mount"]
        fs.write("/proc/mounts", "tmpfs %s tmpfs rw,relatime 0 0\n" % mp)

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        mp, opt = params["mount"], params["option"]
        fs.write("/proc/mounts", "tmpfs %s tmpfs rw,relatime,%s 0 0\n" % (mp, opt))


class KvConfGenerator(FixtureGenerator):
    family = "kv_conf"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        # Simply don't write the target file at all -- c_kv_conf() treats
        # "not configured in <files>" as fail for every op it supports.
        pass

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        target = (params.get("files") or ["/etc/cis-hardening.conf"])[0]
        key = params["key"]
        value = str(params.get("value", ""))
        sep = " = " if params.get("sep", "=") == "=" else " "
        op = params.get("op", "eq")
        if op == "bool_present":
            fs.write(target, "%s\n" % key)
        else:
            fs.write(target, "%s%s%s\n" % (key, sep, value))


class BannerGenerator(FixtureGenerator):
    family = "banner"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        # Contains an OS name reference -> matches BANNER_BAD.
        fs.write(params["path"], "Welcome to CentOS Linux\n")

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        fs.write(params["path"],
                 "Authorized uses only. All activity may be monitored and reported.\n")


class PartitionGenerator(FixtureGenerator):
    """No fix() is registered for this family (CIS leaves partition
    layout changes to manual remediation) -- only the check side is
    exercised, via run_already_compliant()'s scan step.
    """

    family = "partition"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        # Mount point simply doesn't exist in /proc/mounts.
        fs.write("/proc/mounts", "")

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        mp = params["mount"]
        fstype = "tmpfs" if params.get("require_tmpfs") else "ext4"
        fs.write("/proc/mounts", "src %s %s rw,relatime 0 0\n" % (mp, fstype))


class AuditImmutableGenerator(FixtureGenerator):
    family = "audit_immutable"

    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        fs.packages.add("audit")
        # No "-e 2" anywhere on disk, and auditctl -s (faked) reports
        # enabled=1 until a finalize rule is written.
        fs.write("/etc/audit/rules.d/10-base.rules", "-D\n-b 8192\n")

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        fs.packages.add("audit")
        fs.write("/etc/audit/rules.d/99-finalize.rules", "-e 2\n")


GENERATORS = {
    "mount_opt": MountOptGenerator(),
    "kv_conf": KvConfGenerator(),
    "banner": BannerGenerator(),
    "partition": PartitionGenerator(),
    "audit_immutable": AuditImmutableGenerator(),
}
