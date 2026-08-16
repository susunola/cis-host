"""M3 acceptance test: build Windows FixtureGenerators for the top-3
non-manual families (reg-dword, adv-audit, firewall - ranked by rule
count on win2022: 232/34/23 respectively) and drive win2022's real
ohbs_engine.ps1 Invoke-Check/Invoke-Fix through the closed loop /
already-compliant checks, via win_harness.WinHarness (shells out to
`pwsh`, faking the registry/secedit/auditpol/firewall boundary --
see win_fake_system.py and win_harness.py for the full design).

Skipped entirely if `pwsh` isn't on PATH, since PowerShell is an
optional dependency for this Python-centric repo and CI runners may
not have it installed -- this mirrors how the existing test suite
already skips real-OS scanning (tests/test_cli.py etc. mock
subprocess rather than requiring specific OS tooling).

KNOWN CATALOG/ENGINE MISMATCH (found via this fixture, not fixed
here): reg-dword's real catalog params on all 4 Windows OSes are
{"key": "<rule id>"}, but Invoke-Check/Invoke-Fix's reg-dword branch
reads params.path/params.name/params.value, none of which the real
catalog provides. Every real reg-dword scan today returns "error", not
a meaningful pass/fail - see families_win.py's module docstring for
the full writeup. To keep this milestone about fixture-framework
coverage (not engine/catalog bugfixing), test_reg_dword_closed_loop
uses families_win.synthetic_reg_dword_rule() (a rule with the params
shape the engine actually expects) instead of a real catalog rule.
adv-audit and firewall use real catalog rules unmodified since their
params do line up with the engine.
"""

import json
import os
import shutil

import pytest

from families_win import GENERATORS, synthetic_reg_dword_rule
from win_harness import WinHarness
from win_runner import run_already_compliant, run_closed_loop

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="pwsh (PowerShell) not found on PATH; Windows fixture tests require it")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
_CATALOG = os.path.join(
    _REPO_ROOT, "ohbs-win2022-ansible", "roles", "ohbs-win2022", "files", "rules.json")


def _first_rule(family):
    with open(_CATALOG, encoding="utf-8") as fh:
        rules = json.load(fh)
    for rule in rules:
        if rule.get("family") == family and rule.get("assessment") == "Automated":
            return rule
    raise LookupError("no automated rule found for family %r" % family)


def test_reg_dword_closed_loop_win2022():
    """See the KNOWN CATALOG/ENGINE MISMATCH note above: real reg-dword
    rules don't carry usable params, so this drives a synthetic rule
    with the params shape Invoke-Check/Invoke-Fix actually expect.
    """
    harness = WinHarness.for_os("win2022")
    rule = synthetic_reg_dword_rule("2.3.1.1-fixture")
    generator = GENERATORS["reg-dword"]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, "closed loop failed for reg-dword: %s" % result.message


def test_reg_dword_already_compliant_win2022():
    harness = WinHarness.for_os("win2022")
    rule = synthetic_reg_dword_rule("2.3.1.1-fixture")
    generator = GENERATORS["reg-dword"]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, "already-compliant check failed for reg-dword: %s" % result.message


@pytest.mark.parametrize("family", ["adv-audit", "firewall"])
def test_closed_loop_win2022(family):
    harness = WinHarness.for_os("win2022")
    rule = _first_rule(family)
    generator = GENERATORS[family]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, (
        "closed loop failed for %s rule %s: %s" % (family, rule["id"], result.message))


@pytest.mark.parametrize("family", ["adv-audit", "firewall"])
def test_already_compliant_win2022(family):
    harness = WinHarness.for_os("win2022")
    rule = _first_rule(family)
    generator = GENERATORS[family]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, (
        "already-compliant check failed for %s rule %s: %s" % (family, rule["id"], result.message))
