"""Fixture framework core: FixtureGenerator (per-family plugin interface),
FixtureResult (per-rule outcome), and EngineHarness (loads a real
cis_engine.py module for one OS and drives it against a FakeSystem
instead of the real host).

Design intent: every family (kmod, sysctl, svc_enabled, svc_disabled,
pkg_present, ...) gets one FixtureGenerator subclass that knows how to
seed a FakeSystem into a *non-compliant* state for a given rule's
params. The runner (see runner.py) then drives the real
cis_engine.run_rule() through the standard scan -> fail -> apply -> pass
-> re-scan -> pass closed loop, using the actual production check/fix
functions -- only the OS/subprocess boundary is faked.
"""

import importlib.util
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from fake_system import FakeSystem

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Boundary functions inside cis_engine.py that every family's check/fix
# ultimately goes through. Patching exactly these (and nothing else)
# means the real regex parsing / idempotent file-rewriting / dispatch
# logic in the engine still runs untouched -- only real subprocess and
# real disk I/O are replaced.
_PATCHED_NAMES = ("sh", "read", "exists", "atomic_write", "conf_values", "have")


class _NoopMakedirsOs:
    """Proxy for the `os` module used inside a faked cis_engine.py module.

    write_file()/set_kv_in_file() call os.makedirs(dirname, exist_ok=True)
    directly before delegating to the (already-faked) atomic_write(). Real
    os.makedirs would try to create real directories like /etc/sysctl.d/
    on the actual host filesystem, which needs root and pollutes real
    disk. This proxy no-ops makedirs and otherwise delegates every other
    attribute (os.path, os.environ, ...) to the real os module, so it is
    safe to swap in as a whole-module replacement for one engine copy's
    `os` global without touching the real, process-wide os module.
    """

    def __getattr__(self, name):
        import os as _real_os
        return getattr(_real_os, name)

    def makedirs(self, *args, **kwargs):
        return None


@dataclass
class FixtureResult:
    """Outcome of driving one rule through the scan->apply->re-scan loop."""

    rule_id: str
    family: str
    ok: bool
    scan_status: Optional[str] = None
    apply_status: Optional[str] = None
    apply_detail: Optional[str] = None
    rescan_status: Optional[str] = None
    message: str = ""
    calls: List[list] = field(default_factory=list)

    def __bool__(self):
        return self.ok


class FixtureGenerator(ABC):
    """Per-family plugin: knows how to seed a FakeSystem to represent a
    non-compliant (and, optionally, an already-compliant) system for a
    rule with this generator's `family`.
    """

    family: str = ""

    @abstractmethod
    def seed_noncompliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        """Mutate `fs` so that a scan against `params` would fail."""
        raise NotImplementedError

    def seed_compliant(self, fs: FakeSystem, params: Dict[str, Any]) -> None:
        """Optional: mutate `fs` so that a scan against `params` would
        already pass (used to test the apply_status == 'already' path).
        Default: not supported by this generator.
        """
        raise NotImplementedError(
            "%s does not implement seed_compliant()" % type(self).__name__)


class EngineHarness:
    """Loads one OS's real cis_engine.py and drives run_rule() against an
    in-memory FakeSystem, with the OS/subprocess boundary functions
    monkeypatched out.
    """

    def __init__(self, engine_path: str):
        self.engine_path = engine_path
        self._module_name = "cis_engine_fixture_%s" % abs(hash(engine_path))
        spec = importlib.util.spec_from_file_location(self._module_name, engine_path)
        self.engine = importlib.util.module_from_spec(spec)
        sys.modules[self._module_name] = self.engine
        spec.loader.exec_module(self.engine)
        self.fs = FakeSystem()
        self._install_fakes()

    @classmethod
    def for_os(cls, os_id: str) -> "EngineHarness":
        """Build a harness for `os_id` by resolving its engine path via
        the repo-root presets.py registry (same source of truth the CLI
        uses), so fixtures never hardcode per-OS paths.
        """
        sys.path.insert(0, _REPO_ROOT)
        try:
            from presets import OS_PRESETS
        finally:
            sys.path.pop(0)
        preset = OS_PRESETS[os_id]
        engine_path = os.path.join(_REPO_ROOT, preset["engine"])
        return cls(engine_path)

    def catalog_path(self, os_id: str) -> str:
        sys.path.insert(0, _REPO_ROOT)
        try:
            from presets import OS_PRESETS
        finally:
            sys.path.pop(0)
        return os.path.join(_REPO_ROOT, OS_PRESETS[os_id]["catalog"])

    def _install_fakes(self):
        fs = self.fs
        self.engine.sh = lambda cmd, timeout=60: fs.run(cmd, timeout)
        self.engine.read = lambda path: fs.read(path)
        self.engine.exists = lambda path: fs.exists(path)
        self.engine.atomic_write = lambda path, content, mode=None, preserve_owner=True: fs.write(path, content)
        self.engine.conf_values = lambda files, key, seps=(r"\s+", r"\s*=\s*"): fs.conf_values(files, key, seps)
        self.engine.have = lambda binname: True
        self.engine._pkg_manager = lambda: fs.pkg_manager
        # write_file()/set_kv_in_file() call os.makedirs(dirname, ...)
        # directly (not through a patchable module-level helper) before
        # delegating to atomic_write(). Swap the engine module's `os`
        # binding for a thin proxy that no-ops filesystem-mutating calls
        # while delegating pure path-string helpers (dirname, join, ...)
        # to the real os module -- this must NOT touch the real,
        # process-wide `os` module object, only this one module's
        # reference to it.
        self.engine.os = _NoopMakedirsOs()

    def make_ctx(self, mode="scan", allow_disruptive=False, simulate=False,
                variables=None, waivers=None):
        opts = SimpleNamespace(
            mode=mode,
            allow_disruptive=allow_disruptive,
            backup_dir=None,  # disables backup() side effects entirely (see cis_engine.backup)
            variables=variables or {},
            waivers=waivers or {},
            simulate=simulate,
            profile="L1",
        )
        ctx = self.engine.Ctx(opts)
        ctx._hostname = "fixture-host"
        return ctx

    def run_rule(self, rule: Dict[str, Any], mode: str, allow_disruptive=True) -> Dict[str, Any]:
        ctx = self.make_ctx(mode=mode, allow_disruptive=allow_disruptive)
        return self.engine.run_rule(ctx, rule)
