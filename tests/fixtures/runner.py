"""Runner: drives one rule through the scan -> fail -> apply -> pass ->
re-scan -> pass closed loop, using a real ohbs_engine.py's run_rule()
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


def run_idempotency_check(harness: EngineHarness, rule: Dict[str, Any],
                          generator: FixtureGenerator) -> FixtureResult:
    """Seed a non-compliant system, apply twice in a row (mode="apply"
    both times, same FakeSystem/Ctx-per-call as run_closed_loop), and
    verify:
      1. apply #1 -> apply_status == "applied", status flips to "pass"
      2. apply #2 -> apply_status == "already" (no second remediation
         attempted) AND the on-disk/state footprint left by fixture #1
         is byte-for-byte unchanged (fs.files/fs.services/fs.kmods/
         fs.sysctls/fs.packages all compare equal before vs. after
         apply #2)

    This is the M5 gate: a fix that "succeeds" on the first apply but
    silently mutates state again on every subsequent apply (e.g.
    re-appending a line to a config file instead of checking whether
    it is already present) would pass M0-M4's closed-loop check yet
    still fail this idempotency check -- exactly the class of bug this
    milestone exists to catch before it reaches a release.
    """
    rule_id = rule["id"]
    family = rule["family"]
    generator.seed_noncompliant(harness.fs, rule.get("params") or {})

    apply1 = harness.run_rule(rule, mode="apply")
    if apply1["apply_status"] != "applied" or apply1["status"] != "pass":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            apply_status=apply1["apply_status"],
            apply_detail=apply1["apply_detail"],
            rescan_status=apply1["status"],
            message="first apply did not succeed as expected: apply_status=%r "
                    "status=%r (detail: %s)"
                    % (apply1["apply_status"], apply1["status"], apply1["detail"]),
            calls=list(harness.fs.calls))

    snapshot_before = _snapshot(harness.fs)
    apply2 = harness.run_rule(rule, mode="apply")
    snapshot_after = _snapshot(harness.fs)

    if apply2["apply_status"] != "already":
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            apply_status=apply2["apply_status"],
            apply_detail=apply2["apply_detail"],
            rescan_status=apply2["status"],
            message="second apply on an already-fixed system expected "
                    "apply_status 'already', got %r (detail: %s) -- the fix "
                    "is not idempotent at the apply_status level"
                    % (apply2["apply_status"], apply2["apply_detail"]),
            calls=list(harness.fs.calls))

    if snapshot_before != snapshot_after:
        return FixtureResult(
            rule_id=rule_id, family=family, ok=False,
            apply_status=apply2["apply_status"],
            message="second apply reported apply_status 'already' but still "
                    "mutated system state -- before: %r, after: %r"
                    % (snapshot_before, snapshot_after),
            calls=list(harness.fs.calls))

    return FixtureResult(
        rule_id=rule_id, family=family, ok=True,
        apply_status=apply2["apply_status"], rescan_status=apply2["status"],
        calls=list(harness.fs.calls))


def _snapshot(fs):
    """Cheap equality snapshot of every piece of mutable state a
    FixtureGenerator/check/fix function can touch, for idempotency
    comparison. Deliberately excludes fs.calls (the recorded command
    log), since replaying the *same* idempotent fix a second time is
    expected to issue read-only verification commands again -- what
    must NOT change is the actual system state those commands observe.
    """
    return (
        dict(fs.files),
        {k: dict(v) for k, v in fs.services.items()},
        {k: dict(v) for k, v in fs.kmods.items()},
        dict(fs.sysctls),
        set(fs.packages),
    )


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
