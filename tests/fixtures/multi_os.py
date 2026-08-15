"""Shared helpers for the M2 multi-OS fixture matrix: build the list of
(os_id, family, rule) combinations to drive through the closed loop /
already-compliant checks, across every non-Windows OS preset.

Centralizing rule selection here (rather than duplicating per-OS pick
logic in the test file) keeps the "avoid this known engine bug" /
"this family has no fix()" decisions in one place as the matrix grows.
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))

if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from presets import OS_PRESETS  # noqa: E402

# All non-Windows (Linux) OS presets; Windows OSes use a PowerShell
# engine (cis_engine.ps1) and are out of scope until M3/M4.
LINUX_OS_IDS = tuple(
    os_id for os_id, preset in OS_PRESETS.items()
    if preset["engine"].endswith(".py"))

TARGET_FAMILIES = (
    "kmod", "sysctl", "svc_enabled", "svc_disabled", "pkg_present",
    "mount_opt", "kv_conf", "banner", "partition", "audit_immutable",
)

# Families with no registered fix() in cis_engine.py -- only the
# already-compliant scan path is meaningful for these; run_closed_loop()
# has nothing to apply.
NO_FIX_FAMILIES = frozenset({"partition"})

# kv_conf rules that omit an explicit "sep" param hit a pre-existing
# engine bug in _kv_current() (documented in test_m1_ubuntu2204.py):
# r"\s+" is tried before r"\s*=\s*", so a value written as "key = value"
# (f_kv_conf()'s default write format) is re-parsed as "= value" on the
# very next check. Filter those out everywhere in this matrix, not just
# ubuntu2204, since the bug lives in shared engine logic present
# identically in all 14 per-OS copies.
_KV_CONF_BUGGY_OPS = frozenset({"limits_core"})


def _kv_conf_rule_is_safe(rule):
    p = rule.get("params") or {}
    if not p.get("sep"):
        return False
    if p.get("op") in _KV_CONF_BUGGY_OPS:
        return False
    if p.get("op") == "present" and not p.get("value"):
        return False
    return True


def catalog_path(os_id):
    return os.path.join(_REPO_ROOT, OS_PRESETS[os_id]["catalog"])


def rules_for_os(os_id):
    with open(catalog_path(os_id), encoding="utf-8") as fh:
        return json.load(fh)


def pick_rule(rules, family):
    """Return the first automated rule of `family` in `rules` that is
    safe to drive through this fixture matrix (see
    _kv_conf_rule_is_safe for the one family-specific exception), or
    None if the catalog has no such rule (e.g. rhel9 has zero sysctl
    rules -- a real catalog gap, not a fixture bug).
    """
    for rule in rules:
        if rule.get("family") != family or rule.get("assessment") != "Automated":
            continue
        if family == "kv_conf" and not _kv_conf_rule_is_safe(rule):
            continue
        return rule
    return None


def build_matrix():
    """Return {(os_id, family): rule} for every (os, family) combination
    where the OS's real catalog actually has a usable rule. Combinations
    without one (e.g. rhel9 x sysctl) are simply omitted -- callers that
    want to assert full coverage should check for gaps explicitly rather
    than have this raise, since a missing rule is a catalog fact about
    that OS, not a fixture-framework failure.
    """
    matrix = {}
    for os_id in LINUX_OS_IDS:
        rules = rules_for_os(os_id)
        for family in TARGET_FAMILIES:
            rule = pick_rule(rules, family)
            if rule is not None:
                matrix[(os_id, family)] = rule
    return matrix
