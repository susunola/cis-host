#!/usr/bin/env python3
"""Tests for diff (drift detection), watch helpers, apply verification and
waiver hygiene in cis_cli.py.

These tests exercise the pure logic — no root, no engine execution, no
live scans — by importing cis_cli directly and by running the CLI against
fixture result JSONs.
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cis_cli  # noqa: E402

CLI = os.path.join(ROOT, "cis_cli.py")


def run(args, check=False):
    cmd = [sys.executable, CLI] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


def make_result(rules, score=70.0, hostname="host1", started="2026-08-08T00:00:00+0800"):
    """Build a minimal engine result document shaped like cis_engine output."""
    summary = {"all": {"total": len(rules), "pass": 0, "fail": 0, "manual": 0,
                       "error": 0, "notapplicable": 0, "waived": 0,
                       "score": score}}
    for r in rules:
        st = r.get("status")
        if st == "pass":
            summary["all"]["pass"] += 1
        elif st in ("fail", "error"):
            summary["all"]["fail"] += 1
        elif st == "waived":
            summary["all"]["waived"] += 1
        else:
            summary["all"]["manual"] += 1
    return {
        "started_at": started,
        "host": {"hostname": hostname},
        "profile": "L1",
        "summary": summary,
        "results": rules,
    }


def rule(rid, status, title="rule", waived=False):
    # Mirror real engine output: a waived rule carries both the status and
    # the waived flag (cis_engine sets waived=True and status='waived').
    if status == "waived":
        waived = True
    d = {"id": rid, "status": status, "title": f"{title} {rid}",
         "family": "file", "waived": waived}
    return d


@pytest.fixture()
def before_doc():
    return make_result([
        rule("1.1.1.1", "pass"),
        rule("1.1.1.2", "fail"),
        rule("1.1.1.3", "fail"),
        rule("1.1.1.4", "pass"),
        rule("1.1.1.5", "pass"),
        rule("1.1.1.6", "waived"),
    ], score=60.0)


@pytest.fixture()
def after_doc():
    return make_result([
        rule("1.1.1.1", "fail"),          # drift: pass -> fail
        rule("1.1.1.2", "pass"),          # recovered
        rule("1.1.1.3", "fail"),          # still failing
        rule("1.1.1.4", "pass"),
        rule("1.1.1.5", "fail"),          # also drift
        rule("1.1.1.6", "pass"),          # unwaived + passing
    ], score=40.0)


# ─── diff_results ─────────────────────────────────────────────────────

def test_diff_classifies_drift_recovery_and_still_fail(before_doc, after_doc):
    diff = cis_cli.diff_results(before_doc, after_doc)
    ch = diff["changes"]

    new_ids = {rid for rid, _ in ch["new_fail"]}
    assert new_ids == {"1.1.1.1", "1.1.1.5"}

    rec_ids = {rid for rid, _ in ch["recovered"]}
    assert rec_ids == {"1.1.1.2"}

    still_ids = {rid for rid, _ in ch["still_fail"]}
    assert still_ids == {"1.1.1.3"}

    unwaived_ids = {rid for rid, _ in ch["unwaived"]}
    assert unwaived_ids == {"1.1.1.6"}

    assert cis_cli.diff_has_drift(diff) is True


def test_diff_no_drift_is_quiet():
    doc = make_result([rule("1.1.1.1", "pass"), rule("1.1.1.2", "fail")], score=50.0)
    diff = cis_cli.diff_results(doc, doc)
    assert cis_cli.diff_has_drift(diff) is True  # still_fail counts as drift
    assert diff["changes"]["new_fail"] == []


def test_diff_handles_rules_only_on_one_side(before_doc):
    after = make_result([rule("1.1.1.1", "pass"), rule("9.9.9.9", "pass")], score=90.0)
    diff = cis_cli.diff_results(before_doc, after)
    before_only = {rid for rid, _ in diff["changes"]["before_only"]}
    after_only = {rid for rid, _ in diff["changes"]["after_only"]}
    assert "9.9.9.9" in after_only
    assert "1.1.1.2" in before_only
    # The drifted baseline-only rule is not silently counted as new_fail.
    assert "1.1.1.2" not in {rid for rid, _ in diff["changes"]["recovered"]}


def test_diff_waived_rule_does_not_count_as_drift(before_doc):
    after = make_result([rule("1.1.1.1", "fail", waived=True), rule("1.1.1.2", "pass")], score=80.0)
    diff = cis_cli.diff_results(before_doc, after)
    now_waived = {rid for rid, _ in diff["changes"]["now_waived"]}
    assert "1.1.1.1" in now_waived
    # A newly waived failing rule is an exception, not new drift.
    assert "1.1.1.1" not in {rid for rid, _ in diff["changes"]["new_fail"]}


def test_diff_cli_output_and_exit_code(before_doc, after_doc, tmp_path):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before_doc), encoding="utf-8")
    after_path.write_text(json.dumps(after_doc), encoding="utf-8")

    res = run(["diff", str(before_path), str(after_path), "--format", "cli"])
    assert res.returncode == 0
    assert "NEW FAILURES" in res.stdout
    assert "1.1.1.1" in res.stdout
    assert "Recovered" in res.stdout

    res = run(["diff", str(before_path), str(after_path), "--format", "cli", "--exit-code"])
    assert res.returncode == 2
    assert "FAIL" in res.stdout  # Gate: FAIL (ANSI-colored)


def test_diff_no_drift_passes_gate(before_doc, tmp_path):
    doc = make_result([rule("1.1.1.1", "pass"), rule("1.1.1.2", "pass")], score=100.0)
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    p1.write_text(json.dumps(doc), encoding="utf-8")
    p2.write_text(json.dumps(doc), encoding="utf-8")
    res = run(["diff", str(p1), str(p2), "--format", "cli", "--exit-code"])
    assert res.returncode == 0
    assert "PASS" in res.stdout  # Gate: PASS (ANSI-colored)


def test_diff_missing_file_fails(tmp_path):
    res = run(["diff", str(tmp_path / "nope.json"), str(tmp_path / "also-nope.json"),
               "--format", "cli"])
    assert res.returncode == 1
    assert "not found" in res.stderr


def test_diff_renders_html(before_doc, after_doc, tmp_path):
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    p1.write_text(json.dumps(before_doc), encoding="utf-8")
    p2.write_text(json.dumps(after_doc), encoding="utf-8")
    out_dir = tmp_path / "out"
    res = run(["diff", str(p1), str(p2), "--format", "html", "--output", str(out_dir)])
    assert res.returncode == 0
    files = list(out_dir.glob("drift-*.html"))
    assert len(files) == 1
    assert "Configuration Drift Report" in files[0].read_text(encoding="utf-8")


def test_watch_help_and_baseline_flag():
    res = run(["watch", "--help"])
    assert res.returncode == 0
    assert "--interval" in res.stdout
    assert "--alert-cmd" in res.stdout
    assert "--baseline" in res.stdout


# ─── verify_remediation ───────────────────────────────────────────────

def test_verify_remediation_classifies_fixed_still_and_regressed():
    pre = make_result([
        rule("1.1.1.1", "fail"),
        rule("1.1.1.2", "fail"),
        rule("1.1.1.3", "pass"),
        rule("1.1.1.4", "pass"),
    ])
    post = make_result([
        rule("1.1.1.1", "pass"),   # fixed
        rule("1.1.1.2", "fail"),   # still failing
        rule("1.1.1.3", "fail"),   # regressed by remediation
        rule("1.1.1.4", "pass"),
    ])
    v = cis_cli.verify_remediation(pre, post)
    assert {rid for rid, _ in v["fixed"]} == {"1.1.1.1"}
    assert {rid for rid, _ in v["still_fail"]} == {"1.1.1.2"}
    assert {rid for rid, _ in v["regressed"]} == {"1.1.1.3"}


def test_verify_remediation_none_pre_is_safe():
    v = cis_cli.verify_remediation(None, make_result([rule("1.1.1.1", "fail")]))
    assert v == {"fixed": [], "still_fail": [], "regressed": [], "waived": []}


# ─── waiver hygiene ───────────────────────────────────────────────────

def test_validate_waivers_expired_warns(capsys):
    waivers = {
        "1.1.1.1": "reason string (legacy format, no expiry)",
        "1.1.1.2": {"reason": "accepted risk", "approved_by": "alice",
                    "expires": "2000-01-01"},
        "1.1.1.3": {"reason": "pending upgrade", "expires": "2999-12-31"},
    }
    problems = cis_cli.validate_waivers(waivers)
    err = capsys.readouterr().err
    assert problems == 1
    assert "EXPIRED" in err
    assert "1.1.1.2" in err
    assert "alice" in err


def test_validate_waivers_invalid_date_warns(capsys):
    waivers = {"1.1.1.1": {"expires": "not-a-date"}}
    problems = cis_cli.validate_waivers(waivers)
    assert problems == 1
    assert "invalid expires" in capsys.readouterr().err


def test_validate_waivers_clean():
    waivers = {"1.1.1.1": "no metadata", "1.1.1.2": {"expires": "2999-12-31"}}
    assert cis_cli.validate_waivers(waivers) == 0
    assert cis_cli.validate_waivers({}) == 0
    assert cis_cli.validate_waivers(None) == 0
