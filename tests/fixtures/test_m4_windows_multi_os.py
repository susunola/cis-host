"""M4 acceptance test: extend the Windows fixture framework from a
single OS (win2022, in M3) to all 4 Windows OS presets
(win2016/2019/2022/2025), and add a user-right generator to cover 4
target families total: reg-dword, adv-audit, firewall, user-right.

This works unmodified across OSes because all 4 Windows ohbs_engine.ps1
copies are byte-identical (verified via md5) -- only rules.json (the
catalog) differs per OS, exactly like the Linux M2 milestone.

Skipped entirely if `pwsh` isn't on PATH (see test_m3_windows.py for
the rationale).

reg-dword and user-right both use synthetic rules rather than real
catalog rules -- see families_win.py's module docstring and
UserRightGenerator's docstring for the two pre-existing catalog/engine
mismatches this uncovered (reg-dword/user-right catalog params don't
match what Invoke-Check/Invoke-Fix read) and the user-right pipeline
single-element-unwrap bug found while building this milestone.
"""

import json
import os
import shutil

import pytest

from families_win import GENERATORS, synthetic_reg_dword_rule, synthetic_user_right_rule
from win_harness import WinHarness
from win_runner import run_already_compliant, run_closed_loop

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="pwsh (PowerShell) not found on PATH; Windows fixture tests require it")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

if _REPO_ROOT not in __import__("sys").path:
    __import__("sys").path.insert(0, _REPO_ROOT)
from presets import OS_PRESETS  # noqa: E402

WINDOWS_OS_IDS = tuple(
    os_id for os_id, preset in OS_PRESETS.items()
    if preset["engine"].endswith(".ps1"))

REAL_CATALOG_FAMILIES = ("adv-audit", "firewall")
SYNTHETIC_FAMILIES = ("reg-dword", "user-right")


def _catalog_path(os_id):
    return os.path.join(_REPO_ROOT, OS_PRESETS[os_id]["catalog"])


def _first_rule(os_id, family):
    with open(_catalog_path(os_id), encoding="utf-8") as fh:
        rules = json.load(fh)
    for rule in rules:
        if rule.get("family") == family and rule.get("assessment") == "Automated":
            return rule
    raise LookupError("no automated rule found for %s/%s" % (os_id, family))


def test_all_windows_os_presets_covered():
    assert set(WINDOWS_OS_IDS) == {"win2016", "win2019", "win2022", "win2025"}


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
@pytest.mark.parametrize("family", REAL_CATALOG_FAMILIES)
def test_closed_loop_real_catalog(os_id, family):
    harness = WinHarness.for_os(os_id)
    rule = _first_rule(os_id, family)
    generator = GENERATORS[family]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, (
        "closed loop failed for %s/%s rule %s: %s" % (os_id, family, rule["id"], result.message))


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
@pytest.mark.parametrize("family", REAL_CATALOG_FAMILIES)
def test_already_compliant_real_catalog(os_id, family):
    harness = WinHarness.for_os(os_id)
    rule = _first_rule(os_id, family)
    generator = GENERATORS[family]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, (
        "already-compliant check failed for %s/%s rule %s: %s"
        % (os_id, family, rule["id"], result.message))


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
def test_reg_dword_closed_loop_synthetic(os_id):
    harness = WinHarness.for_os(os_id)
    rule = synthetic_reg_dword_rule("2.3.1.1-fixture")
    generator = GENERATORS["reg-dword"]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, "closed loop failed for %s/reg-dword: %s" % (os_id, result.message)


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
def test_user_right_closed_loop_synthetic(os_id):
    harness = WinHarness.for_os(os_id)
    rule = synthetic_user_right_rule("2.2.1-fixture")
    generator = GENERATORS["user-right"]

    result = run_closed_loop(harness, rule, generator)

    assert result.ok, "closed loop failed for %s/user-right: %s" % (os_id, result.message)


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
def test_user_right_already_compliant_synthetic(os_id):
    harness = WinHarness.for_os(os_id)
    rule = synthetic_user_right_rule("2.2.1-fixture")
    generator = GENERATORS["user-right"]

    result = run_already_compliant(harness, rule, generator)

    assert result.ok, "already-compliant check failed for %s/user-right: %s" % (os_id, result.message)
