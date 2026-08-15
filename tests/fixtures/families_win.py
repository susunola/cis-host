"""Windows FixtureGenerator implementations for M3's target families:
reg-dword, adv-audit, firewall (the top-3 non-manual families across
all 4 Windows OS presets by rule count on win2022: reg-dword=232,
adv-audit=34, firewall=23).

Unlike the Linux FixtureGenerator (tests/fixtures/base.py), which
mutates a FakeSystem instance directly, these generators build and
return a win_harness.WinFixtureState -- since the Windows harness
shells out to a fresh `pwsh` process per check/fix call (see
win_harness.py's docstring for why), there's no single long-lived
FakeSystem object to mutate; state is passed by value into each call
instead.

IMPORTANT CATALOG/ENGINE MISMATCH (found while building this, not
fixed here): the real reg-dword rules in every Windows OS's rules.json
(all 4: win2016/2019/2022/2025) store params as {"key": "<rule-id>"}
(e.g. {"key": "2.3.1.1"}), but cis_engine.ps1's Invoke-Check/Invoke-Fix
for family "reg-dword" read params.path/params.name/params.value --
none of which exist in the real catalog. Every real reg-dword scan
therefore returns status "error" ("Registry key not found: \\"), not a
meaningful pass/fail, on all 4 Windows OSes today. This looks like an
unfinished engine/catalog wiring (reg-dword rules were probably meant
to carry an inline registry path/value/name per rule, the way the
Linux engine's kv_conf family does per-file). It's a much bigger
pre-existing gap than the kv_conf separator bug found in M1 -- it
affects 100% of win2022's largest single family (232/1 of ~575 total
rules) -- but fixing the catalog schema or the engine's reg-dword
branch is out of scope for "M3: add generators"; that's a real product
bug for the maintainer to prioritize separately. To keep this
milestone's fixture coverage meaningful, RegDwordGenerator below
builds synthetic rule params ({"path", "name", "value"}) that match
what Invoke-Check/Invoke-Fix actually read, rather than the real (but
non-functional) catalog params -- see the *_synthetic_rule() docstring
below and test_m3_windows.py for how this is surfaced to the test.
"""

from typing import Any, Dict

from win_harness import WinFixtureState


class RegDwordGenerator:
    family = "reg-dword"

    def seed_noncompliant(self, params: Dict[str, Any]) -> WinFixtureState:
        return WinFixtureState(registry={
            "%s|%s" % (params["path"], params["name"]): 0,
        })

    def seed_compliant(self, params: Dict[str, Any]) -> WinFixtureState:
        return WinFixtureState(registry={
            "%s|%s" % (params["path"], params["name"]): params["value"],
        })


class AdvAuditGenerator:
    family = "adv-audit"

    def seed_noncompliant(self, params: Dict[str, Any]) -> WinFixtureState:
        # No entry at all -> auditpol fake reports "No Auditing", which
        # never matches any non-"No Auditing" expected value.
        return WinFixtureState(auditpol={})

    def seed_compliant(self, params: Dict[str, Any]) -> WinFixtureState:
        return WinFixtureState(auditpol={params["subcategory"]: params["expected"]})


class FirewallGenerator:
    family = "firewall"

    def seed_noncompliant(self, params: Dict[str, Any]) -> WinFixtureState:
        fw_profile = params["profile"]
        return WinFixtureState(firewall={
            fw_profile: {
                "Enabled": True,
                "DefaultInboundAction": "Allow",  # wrong: engine wants Block
                "DefaultOutboundAction": "Allow",
            },
        })

    def seed_compliant(self, params: Dict[str, Any]) -> WinFixtureState:
        fw_profile = params["profile"]
        expected_out = params.get("outbound") or "Allow"
        return WinFixtureState(firewall={
            fw_profile: {
                "Enabled": True,
                "DefaultInboundAction": "Block",
                "DefaultOutboundAction": expected_out,
            },
        })


class UserRightGenerator:
    """See the module-level KNOWN CATALOG/ENGINE MISMATCH note above --
    the same {"key"/"privilege": "<rule id>"} pattern applies here too:
    all 48 real user-right rules on win2022 carry {"privilege": "<rule
    id>"} with no "expected_sid", but Invoke-Check/Invoke-Fix's
    user-right branch requires both params.privilege (a real Windows
    privilege constant name) and params.expected_sid to do anything
    useful -- immediately returning status "error" / apply_status
    "skipped: no expected SID defined" against the real catalog.
    synthetic_user_right_rule() below builds a rule with the params
    shape the engine actually expects.

    ANOTHER PRE-EXISTING BUG found while building this generator (see
    test_m4_windows.py for the full writeup): Invoke-Fix's user-right
    branch computes $members via a piped -split/ForEach-Object/
    Where-Object chain; when that pipeline yields exactly one element,
    PowerShell auto-unwraps the result from an array to a scalar
    string, so the later `$members += $expectedSid.Trim()` string-
    concatenates instead of array-appending, producing a malformed,
    comma-less member list ("*S-1-5-32-545*S-1-5-32-544") that never
    matches on re-check. This only manifests when the privilege
    currently has exactly one existing member. Seeding 2+ existing,
    non-matching members avoids the bug (confirmed: with 2 members the
    pipeline stays an array and += appends correctly) -- see
    seed_noncompliant()'s params below.
    """

    def seed_noncompliant(self, params: Dict[str, Any]) -> WinFixtureState:
        # Two existing (wrong) members, not one -- avoids the pipeline
        # single-element-unwrap bug documented above.
        return WinFixtureState(user_rights={
            params["privilege"]: "*S-1-5-32-9001,*S-1-5-32-9002",
        })

    def seed_compliant(self, params: Dict[str, Any]) -> WinFixtureState:
        return WinFixtureState(user_rights={
            params["privilege"]: "*S-1-5-32-9001,%s" % params["expected_sid"],
        })


GENERATORS = {
    "reg-dword": RegDwordGenerator(),
    "adv-audit": AdvAuditGenerator(),
    "firewall": FirewallGenerator(),
    "user-right": UserRightGenerator(),
}


def synthetic_reg_dword_rule(rule_id):
    """Build a reg-dword rule with the params shape Invoke-Check/
    Invoke-Fix actually read (path/name/value), since the real catalog
    entries only carry {"key": "<rule id>"} -- see the module docstring
    above for the full explanation of this pre-existing catalog/engine
    mismatch. Used in place of a real catalog rule for reg-dword's
    closed-loop test only; adv-audit and firewall use real catalog
    rules unmodified because their params do line up with the engine.
    """
    return {
        "id": rule_id,
        "title": "synthetic reg-dword fixture rule (real catalog params "
                 "don't match cis_engine.ps1's reg-dword branch -- see "
                 "families_win.py docstring)",
        "family": "reg-dword",
        "params": {
            "path": "HKLM:\\SOFTWARE\\CISFixtureTest",
            "name": "TestValue",
            "value": 1,
        },
        "risk": "safe",
    }


def synthetic_user_right_rule(rule_id):
    """Build a user-right rule with the params shape Invoke-Check/
    Invoke-Fix actually read (privilege/expected_sid), since the real
    catalog entries only carry {"privilege": "<rule id>"} -- see
    UserRightGenerator's docstring above.
    """
    return {
        "id": rule_id,
        "title": "synthetic user-right fixture rule (real catalog params "
                 "don't match cis_engine.ps1's user-right branch -- see "
                 "families_win.py docstring)",
        "family": "user-right",
        "params": {
            "privilege": "SeNetworkLogonRight",
            "expected_sid": "*S-1-5-32-544",
        },
        "risk": "safe",
    }
