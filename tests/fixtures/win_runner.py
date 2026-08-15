"""Runner for the Windows fixture harness: drives one rule through
Invoke-Check/Invoke-Fix's scan -> fail -> apply -> pass closed loop,
via win_harness.WinHarness. Mirrors the Linux runner.py's contract
(run_closed_loop/run_already_compliant + FixtureResult), adapted to
the Windows harness's per-call subprocess model: there is no "re-scan
with a fresh Ctx" step here the way Linux's run_closed_loop() has one,
because WinHarness.fix() already runs Invoke-Fix followed immediately
by Invoke-Check inside the same pwsh process/mutated state (see
win_harness.py's fix() docstring) -- that single post-fix check *is*
the re-scan, so there's nothing further to verify by spawning another
process.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from win_harness import WinHarness


@dataclass
class WinFixtureResult:
    rule_id: str
    family: str
    ok: bool
    scan_status: Optional[str] = None
    apply_status: Optional[str] = None
    rescan_status: Optional[str] = None
    message: str = ""

    def __bool__(self):
        return self.ok


def run_closed_loop(harness: WinHarness, rule: Dict[str, Any], generator) -> WinFixtureResult:
    """scan(fail) -> apply(applied) -> pass, using the params.get("params")
    dict conventionally stored under rule["params"].
    """
    rule_id, family = rule["id"], rule["family"]
    params = rule.get("params") or {}
    state = generator.seed_noncompliant(params)

    scan1 = harness.check(rule, state)
    if scan1["status"] != "fail":
        return WinFixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            message="expected initial scan status 'fail' after seeding "
                    "non-compliant state, got %r (detail: %s)"
                    % (scan1["status"], scan1["detail"]))

    fix_res = harness.fix(rule, state)
    if fix_res["apply_status"] != "applied":
        return WinFixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"], apply_status=fix_res["apply_status"],
            message="expected apply_status 'applied', got %r (post-apply "
                    "status: %s, detail: %s)"
                    % (fix_res["apply_status"], fix_res["status"], fix_res["detail"]))

    ok = fix_res["status"] == "pass"
    return WinFixtureResult(
        rule_id=rule_id, family=family, ok=ok,
        scan_status=scan1["status"], apply_status=fix_res["apply_status"],
        rescan_status=fix_res["status"],
        message="" if ok else (
            "post-apply re-check reports status %r, expected 'pass' "
            "(detail: %s)" % (fix_res["status"], fix_res["detail"])))


def run_already_compliant(harness: WinHarness, rule: Dict[str, Any], generator) -> WinFixtureResult:
    """scan(pass) -> apply(apply_status == 'already')."""
    rule_id, family = rule["id"], rule["family"]
    params = rule.get("params") or {}
    state = generator.seed_compliant(params)

    scan1 = harness.check(rule, state)
    if scan1["status"] != "pass":
        return WinFixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            message="expected initial scan status 'pass' after seeding "
                    "compliant state, got %r (detail: %s)"
                    % (scan1["status"], scan1["detail"]))

    fix_res = harness.fix(rule, state)
    ok = fix_res["apply_status"] == "already"
    return WinFixtureResult(
        rule_id=rule_id, family=family, ok=ok,
        scan_status=scan1["status"], apply_status=fix_res["apply_status"],
        message="" if ok else (
            "expected apply_status 'already' on an already-compliant "
            "system, got %r" % fix_res["apply_status"]))
