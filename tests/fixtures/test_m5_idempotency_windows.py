"""M5 acceptance test (part 2/2 - Windows idempotency): verify that
applying the fix twice in a row is idempotent for all 4 Windows
families (reg-dword, adv-audit, firewall, user-right) across all 4
Windows OS presets, mirroring test_m5_idempotency.py's Linux coverage.

See win_runner.run_idempotency_check() for the full contract and
win_harness.WinHarness.fix_twice() for how two applies are driven
within a single pwsh process so fake registry/secedit/auditpol/
firewall state persists between them.

Skipped entirely if `pwsh` isn't on PATH (see test_m3_windows.py for
the rationale).
"""

import json
import os
import shutil
import sys

import pytest

from families_win import GENERATORS, synthetic_reg_dword_rule, synthetic_user_right_rule
from win_harness import WinHarness
from win_runner import run_idempotency_check

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="pwsh (PowerShell) not found on PATH; Windows fixture tests require it")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from presets import OS_PRESETS  # noqa: E402

WINDOWS_OS_IDS = tuple(
    os_id for os_id, preset in OS_PRESETS.items()
    if preset["engine"].endswith(".ps1"))

REAL_CATALOG_FAMILIES = ("adv-audit", "firewall")


def _catalog_path(os_id):
    return os.path.join(_REPO_ROOT, OS_PRESETS[os_id]["catalog"])


def _first_rule(os_id, family):
    with open(_catalog_path(os_id), encoding="utf-8") as fh:
        rules = json.load(fh)
    for rule in rules:
        if rule.get("family") == family and rule.get("assessment") == "Automated":
            return rule
    raise LookupError("no automated rule found for %s/%s" % (os_id, family))


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
@pytest.mark.parametrize("family", REAL_CATALOG_FAMILIES)
def test_idempotency_real_catalog(os_id, family):
    harness = WinHarness.for_os(os_id)
    rule = _first_rule(os_id, family)
    generator = GENERATORS[family]

    result = run_idempotency_check(harness, rule, generator)

    assert result.ok, (
        "idempotency check failed for %s/%s rule %s: %s"
        % (os_id, family, rule["id"], result.message))


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
def test_idempotency_reg_dword_synthetic(os_id):
    harness = WinHarness.for_os(os_id)
    rule = synthetic_reg_dword_rule("2.3.1.1-fixture")
    generator = GENERATORS["reg-dword"]

    result = run_idempotency_check(harness, rule, generator)

    assert result.ok, "idempotency check failed for %s/reg-dword: %s" % (os_id, result.message)


@pytest.mark.parametrize("os_id", WINDOWS_OS_IDS)
def test_idempotency_user_right_synthetic(os_id):
    harness = WinHarness.for_os(os_id)
    rule = synthetic_user_right_rule("2.2.1-fixture")
    generator = GENERATORS["user-right"]

    result = run_idempotency_check(harness, rule, generator)

    assert result.ok, "idempotency check failed for %s/user-right: %s" % (os_id, result.message)
