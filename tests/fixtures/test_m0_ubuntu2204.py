"""M0 acceptance test: for ubuntu2204, drive one real rule per initial
target family (kmod, sysctl, svc_enabled, svc_disabled, pkg_present)
through the scan -> fail -> apply -> pass -> re-scan -> pass closed
loop, using the *real* ohbs_engine.py business logic against an
in-memory FakeSystem (see base.py, fake_system.py, families/core.py,
runner.py in this directory).

Acceptance criteria (M0): all 5 families, 1 rule each, complete the
closed loop successfully for ubuntu2204. Later milestones (M1+) reuse
this exact harness/runner and only add more FixtureGenerator subclasses
and more OSes.
"""

import json
import os

import pytest

from base import EngineHarness
from families.core import GENERATORS
from runner import run_already_compliant, run_closed_loop

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_CATALOG = os.path.join(
    _REPO_ROOT, "cis-ubuntu2204-ansible", "roles", "cis-ubuntu2204", "files", "rules.json")

TARGET_FAMILIES = ("kmod", "sysctl", "svc_enabled", "svc_disabled", "pkg_present")


def _one_rule_per_family():
    """Pick exactly one rule per target family from ubuntu2204's real
    rules.json, preferring the first automated rule encountered.
    """
    with open(_CATALOG, encoding="utf-8") as fh:
        rules = json.load(fh)
    picked = {}
    for rule in rules:
        fam = rule.get("family")
        if fam in TARGET_FAMILIES and fam not in picked and rule.get("assessment") == "Automated":
            picked[fam] = rule
    missing = set(TARGET_FAMILIES) - picked.keys()
    assert not missing, "no automated rule found in rules.json for families: %s" % missing
    return picked


_RULES_BY_FAMILY = _one_rule_per_family()


@pytest.mark.parametrize("family", TARGET_FAMILIES)
def test_closed_loop_ubuntu2204(family):
    """scan(fail) -> apply(applied) -> pass -> re-scan(pass)."""
    rule = _RULES_BY_FAMILY[family]
    harness = EngineHarness.for_os("ubuntu2204")
    generator = GENERATORS[family]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, (
        "closed loop failed for %s rule %s: %s\ncalls: %s"
        % (family, rule["id"], result.message, result.calls))


@pytest.mark.parametrize("family", TARGET_FAMILIES)
def test_already_compliant_ubuntu2204(family):
    """scan(pass) -> apply(apply_status == 'already')."""
    rule = _RULES_BY_FAMILY[family]
    harness = EngineHarness.for_os("ubuntu2204")
    generator = GENERATORS[family]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, (
        "already-compliant check failed for %s rule %s: %s\ncalls: %s"
        % (family, rule["id"], result.message, result.calls))
