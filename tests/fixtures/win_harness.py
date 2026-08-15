"""Driver for running cis_engine.ps1's Invoke-Check/Invoke-Fix against
FAKE_WINDOWS_SYSTEM_PS1 (see win_fake_system.py) via a single `pwsh`
subprocess per test, using JSON on stdin/stdout to pass rule params and
seed state in and get check/fix results back out.

Design notes:
  - $env:TEMP is empty by default under pwsh on macOS/Linux (verified
    directly), which breaks secedit's temp-file paths inside
    Get-SecPol()/Invoke-Fix()'s password-policy/lockout-policy/
    user-right branches. WinHarness sets $env:TEMP to a per-run temp
    directory before dot-sourcing the engine, exactly mirroring what a
    real Windows host provides automatically.
  - The generated script dot-sources FAKE_WINDOWS_SYSTEM_PS1's function
    definitions *before* dot-sourcing cis_engine.ps1, so PowerShell's
    function-over-cmdlet resolution makes every Get-ItemProperty/
    secedit/auditpol/Get-NetFirewallProfile call inside the engine
    resolve to the fake instead of a real cmdlet/external command.
  - cis_engine.ps1 itself runs its own full scan over the real
    rules.json on dot-source (that's just how the script is written --
    there's no function-only mode) and writes a throwaway result file;
    WinHarness points -Catalog/-Out at disposable temp paths and
    ignores that output entirely, since only the Invoke-Check/
    Invoke-Fix function calls emitted after dot-sourcing matter to the
    fixture.
  - Each WinHarness.run_rule() call spawns a fresh `pwsh` process (seed
    state -> Invoke-Check/Invoke-Fix calls -> print JSON), rather than
    keeping one long-lived process across scan/apply/re-scan steps like
    the Linux EngineHarness does with in-process Python state. This is
    simpler and safe because each script explicitly re-seeds the fake
    registry/secedit/auditpol/firewall state passed in via
    WinFixtureState before every call, so process boundaries don't lose
    any state that matters to the closed-loop contract.
"""

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from win_fake_system import FAKE_WINDOWS_SYSTEM_PS1

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from presets import OS_PRESETS  # noqa: E402

PWSH_BIN = "pwsh"


@dataclass
class WinFixtureState:
    """Seed state for one Invoke-Check/Invoke-Fix call: mirrors the
    $Global:Fake* dictionaries defined in FAKE_WINDOWS_SYSTEM_PS1.
    """

    registry: Dict[str, Any] = field(default_factory=dict)   # "path|name" -> value
    secpol: Dict[str, Any] = field(default_factory=dict)      # secedit key -> value
    user_rights: Dict[str, Any] = field(default_factory=dict)  # privilege -> "sid1,sid2"
    auditpol: Dict[str, str] = field(default_factory=dict)     # subcategory -> state string
    firewall: Dict[str, Any] = field(default_factory=dict)     # profile -> {Enabled, DefaultInboundAction, DefaultOutboundAction}


def _ps_literal(value):
    """Render a Python value as a PowerShell literal for embedding in the
    generated script (used only for the small, fully-controlled seed
    dictionaries above -- not for untrusted input).
    """
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if value is None:
        return "$null"
    if isinstance(value, (int, float)):
        return str(value)
    return "'%s'" % str(value).replace("'", "''")


def _ps_hashtable(d, value_is_dict=False):
    if not d:
        return "@{}"
    items = []
    for k, v in d.items():
        if value_is_dict:
            inner = "; ".join(
                "%s = %s" % (ik, _ps_literal(iv)) for ik, iv in v.items())
            items.append("'%s' = @{ %s }" % (str(k).replace("'", "''"), inner))
        else:
            items.append("'%s' = %s" % (str(k).replace("'", "''"), _ps_literal(v)))
    return "@{ %s }" % "; ".join(items)


class WinHarness:
    """Loads one Windows OS's real cis_engine.ps1 (dot-sourced after the
    FakeWindowsSystem functions) and drives Invoke-Check/Invoke-Fix
    against it via a fresh `pwsh` subprocess per call.
    """

    def __init__(self, engine_path: str, catalog_path: str):
        self.engine_path = engine_path
        self.catalog_path = catalog_path

    @classmethod
    def for_os(cls, os_id: str) -> "WinHarness":
        preset = OS_PRESETS[os_id]
        return cls(
            os.path.join(_REPO_ROOT, preset["engine"]),
            os.path.join(_REPO_ROOT, preset["catalog"]))

    def _run_script(self, script: str) -> Dict[str, Any]:
        # Run from a real .ps1 file via -File (not -Command - with piped
        # stdin): -Command - puts pwsh into a line-oriented interactive
        # read loop that emits terminal escape sequences (bracketed-paste
        # mode toggles) interleaved with our own Write-Output calls,
        # corrupting the JSON payload. -File runs the script verbatim,
        # non-interactively, with clean stdout.
        script = "$ProgressPreference = 'SilentlyContinue'\n" + script
        fd, path = tempfile.mkstemp(suffix=".ps1", prefix="cis-win-fixture-script-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(script)
            proc = subprocess.run(
                [PWSH_BIN, "-NoProfile", "-NonInteractive", "-File", path],
                capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(path)
        if proc.returncode != 0:
            raise RuntimeError(
                "pwsh exited %d\nSTDOUT:\n%s\nSTDERR:\n%s"
                % (proc.returncode, proc.stdout, proc.stderr))
        marker = "===FIXTURE-JSON-START==="
        if marker not in proc.stdout:
            raise RuntimeError(
                "pwsh script did not emit the expected JSON marker\n"
                "STDOUT:\n%s\nSTDERR:\n%s" % (proc.stdout, proc.stderr))
        payload = proc.stdout.split(marker, 1)[1]
        return json.loads(payload)

    def _preamble(self, state: WinFixtureState, tmpdir: str) -> str:
        return "\n".join([
            "$env:TEMP = %s" % _ps_literal(tmpdir),
            "$ErrorActionPreference = 'Stop'",
            FAKE_WINDOWS_SYSTEM_PS1,
            "$Global:FakeReg = %s" % _ps_hashtable(state.registry),
            "$Global:FakeSecPol = %s" % _ps_hashtable(state.secpol),
            "$Global:FakeUserRights = %s" % _ps_hashtable(state.user_rights),
            "$Global:FakeAuditPol = %s" % _ps_hashtable(state.auditpol),
            "$Global:FakeFirewall = %s" % _ps_hashtable(state.firewall, value_is_dict=True),
            ". %s -Catalog %s -Mode scan -Out %s 2>$null 1>$null" % (
                _ps_literal(self.engine_path),
                _ps_literal(self.catalog_path),
                _ps_literal(os.path.join(tmpdir, "discard-result.json"))),
        ])

    def check(self, rule: Dict[str, Any], state: WinFixtureState) -> Dict[str, Any]:
        """Run Invoke-Check for `rule` against `state`. Returns
        {"status": ..., "detail": ...}.
        """
        with tempfile.TemporaryDirectory(prefix="cis-win-fixture-") as tmpdir:
            rule_json = json.dumps(rule).replace("'", "''")
            script = "\n".join([
                self._preamble(state, tmpdir),
                "$rule = ConvertFrom-Json -InputObject '%s' -AsHashtable" % rule_json,
                "$r = Invoke-Check -Rule $rule",
                "Write-Output '===FIXTURE-JSON-START==='",
                "@{ status = $r.status; detail = $r.detail } | ConvertTo-Json -Compress",
            ])
            return self._run_script(script)

    def fix(self, rule: Dict[str, Any], state: WinFixtureState) -> Dict[str, Any]:
        """Run Invoke-Fix for `rule` against `state`, then immediately
        re-run Invoke-Check against the *same* mutated fake state (both
        happen inside one pwsh process, so registry/secedit/auditpol/
        firewall writes from Invoke-Fix are visible to the re-check --
        mirroring how cis_engine.ps1's own apply-mode loop re-checks
        after a successful fix). Returns
        {"apply_status": ..., "status": ..., "detail": ...}.
        """
        with tempfile.TemporaryDirectory(prefix="cis-win-fixture-") as tmpdir:
            rule_json = json.dumps(rule).replace("'", "''")
            script = "\n".join([
                self._preamble(state, tmpdir),
                "$rule = ConvertFrom-Json -InputObject '%s' -AsHashtable" % rule_json,
                "$applyStatus = Invoke-Fix -Rule $rule",
                "$r = Invoke-Check -Rule $rule",
                "Write-Output '===FIXTURE-JSON-START==='",
                "@{ apply_status = $applyStatus; status = $r.status; detail = $r.detail } | ConvertTo-Json -Compress",
            ])
            return self._run_script(script)

    def fix_twice(self, rule: Dict[str, Any], state: WinFixtureState) -> Dict[str, Any]:
        """Idempotency check (M5): run Invoke-Fix twice in a row against
        the same fake state within a single pwsh process (state must
        persist across both applies, so this cannot be split into two
        separate WinHarness.fix() calls the way it would be for the
        Linux EngineHarness's in-process FakeSystem). Snapshots the fake
        registry/secpol/user_rights/auditpol/firewall dicts after each
        apply so the caller can compare them for byte-for-byte equality.
        Returns {"apply_status_1", "status_1", "apply_status_2",
        "status_2", "detail_2", "snapshot_1", "snapshot_2"}.
        """
        with tempfile.TemporaryDirectory(prefix="cis-win-fixture-") as tmpdir:
            rule_json = json.dumps(rule).replace("'", "''")
            snapshot_expr = (
                "@{ FakeReg = $Global:FakeReg; FakeSecPol = $Global:FakeSecPol; "
                "FakeUserRights = $Global:FakeUserRights; "
                "FakeAuditPol = $Global:FakeAuditPol; FakeFirewall = $Global:FakeFirewall }")
            script = "\n".join([
                self._preamble(state, tmpdir),
                "$rule = ConvertFrom-Json -InputObject '%s' -AsHashtable" % rule_json,
                "$applyStatus1 = Invoke-Fix -Rule $rule",
                "$r1 = Invoke-Check -Rule $rule",
                "$snap1 = %s | ConvertTo-Json -Compress -Depth 10" % snapshot_expr,
                "$applyStatus2 = Invoke-Fix -Rule $rule",
                "$r2 = Invoke-Check -Rule $rule",
                "$snap2 = %s | ConvertTo-Json -Compress -Depth 10" % snapshot_expr,
                "Write-Output '===FIXTURE-JSON-START==='",
                "@{ apply_status_1 = $applyStatus1; status_1 = $r1.status; "
                "apply_status_2 = $applyStatus2; status_2 = $r2.status; "
                "detail_2 = $r2.detail; snapshot_1 = $snap1; snapshot_2 = $snap2 } "
                "| ConvertTo-Json -Compress",
            ])
            return self._run_script(script)

