"""Runner: drives one rule through the scan -> fail -> apply -> pass ->
re-scan -> pass closed loop, using a real cis_engine.py's run_rule()
against a FakeSystem seeded by a FixtureGenerator.

This is the single place that encodes what "the CI regression matrix
passed for this rule" means, so M1-M5 (more families, more OSes) only
need to add FixtureGenerator subclasses and call run_closed_loop() --
the verification contract itself does not change.
"""

from typing import Any, Dict

from base import EngineHarness, FixtureGenerator, FixtureResult


def run_closed_loop(harness: EngineHarness, rule: Dict[str, Any],
                    generator: FixtureGenerator) -> FixtureResult:
    """Seed a non-compliant system, then verify:
      1. scan  -> status == "fail"
      2. apply -> status flips to "pass", apply_status == "applied"
      3. re-scan (fresh Ctx, same FakeSystem state) -> status == "pass"

    Returns a FixtureResult describing what happened; never raises for
    an ordinary compliance failure (that's exactly what step 1 checks
    for) -- only for a generator/harness bug does this propagate an
    exception.
    """
    rule_id = rule["id"]
    family = rule["family"]
    generator.seed_noncompliant(harness.fs, rule.get("params") or {})

    scan1 = harness.run_rule(rule, mode="scan")
    if scan1["status"] != "fail":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            message="expected initial scan status 'fail' after seeding "
                    "non-compliant state, got %r (detail: %s)"
                    % (scan1["status"], scan1["detail"]),
            calls=list(harness.fs.calls))

    apply_res = harness.run_rule(rule, mode="apply")
    if apply_res["apply_status"] != "applied":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            apply_status=apply_res["apply_status"],
            apply_detail=apply_res["apply_detail"],
            message="expected apply_status 'applied', got %r (apply_detail: "
                    "%s, post-apply status: %s)"
                    % (apply_res["apply_status"], apply_res["apply_detail"],
                       apply_res["status"]),
            calls=list(harness.fs.calls))
    if apply_res["status"] != "pass":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            apply_status=apply_res["apply_status"],
            apply_detail=apply_res["apply_detail"],
            rescan_status=apply_res["status"],
            message="apply reported 'applied' but the immediate re-check "
                    "inside run_rule() still reports status %r (detail: %s)"
                    % (apply_res["status"], apply_res["detail"]),
            calls=list(harness.fs.calls))

    scan2 = harness.run_rule(rule, mode="scan")
    ok = scan2["status"] == "pass"
    return FixtureResult(
        rule_id=rule_id, family=family, ok=ok,
        scan_status=scan1["status"],
        apply_status=apply_res["apply_status"],
        apply_detail=apply_res["apply_detail"],
        rescan_status=scan2["status"],
        message="" if ok else (
            "independent post-apply re-scan (fresh Ctx) reports status "
            "%r, expected 'pass' (detail: %s)" % (scan2["status"], scan2["detail"])),
        calls=list(harness.fs.calls))


def run_already_compliant(harness: EngineHarness, rule: Dict[str, Any],
                          generator: FixtureGenerator) -> FixtureResult:
    """Seed an already-compliant system and verify:
      1. scan  -> status == "pass"
      2. apply -> apply_status == "already" (no fix invoked)
    """
    rule_id = rule["id"]
    family = rule["family"]
    generator.seed_compliant(harness.fs, rule.get("params") or {})

    scan1 = harness.run_rule(rule, mode="scan")
    if scan1["status"] != "pass":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            scan_status=scan1["status"],
            message="expected initial scan status 'pass' after seeding "
                    "compliant state, got %r (detail: %s)"
                    % (scan1["status"], scan1["detail"]),
            calls=list(harness.fs.calls))

    apply_res = harness.run_rule(rule, mode="apply")
    ok = apply_res["apply_status"] == "already"
    return FixtureResult(
        rule_id=rule_id, family=family, ok=ok,
        scan_status=scan1["status"],
        apply_status=apply_res["apply_status"],
        apply_detail=apply_res["apply_detail"],
        rescan_status=apply_res["status"],
        message="" if ok else (
            "expected apply_status 'already' on an already-compliant "
            "system, got %r" % apply_res["apply_status"]),
        calls=list(harness.fs.calls))
