"""M5 acceptance test (part 1/2 - idempotency): for every Linux OS x
family combination that has a registered fix() (i.e. everything in
multi_os.build_matrix() except NO_FIX_FAMILIES), verify that applying
the fix *twice* in a row is idempotent:
  - apply #1: apply_status "applied", status flips to "pass"
  - apply #2: apply_status "already" (no second remediation attempted)
    AND the fake system's on-disk/state footprint is byte-for-byte
    unchanged between the two applies

This is the release gate M0-M4 didn't check: a fix that "succeeds"
once but keeps mutating state on every subsequent apply (e.g.
re-appending a config line instead of checking whether it's already
present) passed every prior milestone's closed-loop check, since that
only ever applies once per rule. See runner.run_idempotency_check()
for the full contract.
"""

import pytest

from base import EngineHarness
from families.registry import GENERATORS
from multi_os import NO_FIX_FAMILIES, build_matrix
from runner import run_idempotency_check

_MATRIX = build_matrix()
_IDEMPOTENCY_CASES = sorted(
    key for key in _MATRIX if key[1] not in NO_FIX_FAMILIES)


@pytest.mark.parametrize("os_id,family", _IDEMPOTENCY_CASES,
                        ids=["%s-%s" % c for c in _IDEMPOTENCY_CASES])
def test_idempotency_multi_os(os_id, family):
    rule = _MATRIX[(os_id, family)]
    harness = EngineHarness.for_os(os_id)
    generator = GENERATORS[family]

    result = run_idempotency_check(harness, rule, generator)

    assert result.ok, (
        "idempotency check failed for %s/%s rule %s: %s\ncalls: %s"
        % (os_id, family, rule["id"], result.message, result.calls))
