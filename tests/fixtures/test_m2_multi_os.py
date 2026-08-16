"""M2 acceptance test: extend the fixture matrix from a single OS
(ubuntu2204, in M0/M1) to all Linux OS presets, driving the same
Top-10 family set (kmod, sysctl, svc_enabled, svc_disabled,
pkg_present, mount_opt, kv_conf, banner, partition, audit_immutable)
through the closed loop / already-compliant checks for every OS x
family combination that has a usable rule in that OS's real
rules.json.

This works unmodified across OSes because all 10 Linux ohbs_engine.py
copies are byte-identical (verified: same md5 across
tencentos3/tencentos4/rhel8/rhel9/rhel10/sles15/sles16/ubuntu2004/
ubuntu2204/ubuntu2404) -- only rules.json (the catalog) differs per OS,
so the same FixtureGenerator set from families/core.py + families/
extra.py applies everywhere without per-OS special-casing.

Known catalog gap (not a fixture bug): rhel9's rules.json has zero
sysctl-family rules, so that one (os, family) combination is simply
absent from the matrix -- see multi_os.build_matrix()'s docstring.
"""

import pytest

from base import EngineHarness
from families.registry import GENERATORS
from multi_os import LINUX_OS_IDS, NO_FIX_FAMILIES, TARGET_FAMILIES, build_matrix
from runner import run_already_compliant, run_closed_loop

_MATRIX = build_matrix()

_ALREADY_COMPLIANT_CASES = sorted(_MATRIX.keys())
_CLOSED_LOOP_CASES = sorted(
    key for key in _MATRIX if key[1] not in NO_FIX_FAMILIES)


def test_matrix_covers_every_os():
    """Sanity check on the matrix itself: every Linux OS preset must
    contribute at least one (os, family) case, and the only missing
    combination should be the known rhel9/sysctl catalog gap.
    """
    seen_os = {os_id for os_id, _ in _MATRIX}
    assert seen_os == set(LINUX_OS_IDS), (
        "expected every Linux OS to appear in the fixture matrix, missing: %s"
        % (set(LINUX_OS_IDS) - seen_os))

    all_combos = {(os_id, fam) for os_id in LINUX_OS_IDS for fam in TARGET_FAMILIES}
    missing_combos = all_combos - set(_MATRIX)
    assert missing_combos == {("rhel9", "sysctl")}, (
        "unexpected (os, family) gaps in the fixture matrix: %s" % missing_combos)


@pytest.mark.parametrize("os_id,family", _CLOSED_LOOP_CASES,
                        ids=["%s-%s" % c for c in _CLOSED_LOOP_CASES])
def test_closed_loop_multi_os(os_id, family):
    """scan(fail) -> apply(applied) -> pass -> re-scan(pass)."""
    rule = _MATRIX[(os_id, family)]
    harness = EngineHarness.for_os(os_id)
    generator = GENERATORS[family]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, (
        "closed loop failed for %s/%s rule %s: %s\ncalls: %s"
        % (os_id, family, rule["id"], result.message, result.calls))


@pytest.mark.parametrize("os_id,family", _ALREADY_COMPLIANT_CASES,
                        ids=["%s-%s" % c for c in _ALREADY_COMPLIANT_CASES])
def test_already_compliant_multi_os(os_id, family):
    """scan(pass) -> apply(apply_status == 'already')."""
    rule = _MATRIX[(os_id, family)]
    harness = EngineHarness.for_os(os_id)
    generator = GENERATORS[family]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, (
        "already-compliant check failed for %s/%s rule %s: %s\ncalls: %s"
        % (os_id, family, rule["id"], result.message, result.calls))
