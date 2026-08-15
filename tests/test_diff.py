#!/usr/bin/env python3
"""Tests for drift detection, apply verification, waiver hygiene and the
periodic watch session (cis_host_diff.py) plus CLI integration.

Pure-logic tests import cis_host_diff directly — no root, no engine, no
subprocess — so they run anywhere. CLI integration tests run the command
against fixture JSONs.
"""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cis_host_diff  # noqa: E402

CLI = os.path.join(ROOT, "cis_cli.py")


def run(args, check=False):
    cmd = [sys.executable, CLI] + args
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


# ─── fixtures ─────────────────────────────────────────────────────────


def make_result(rules, score=70.0, hostname="host1", started="2026-08-08T00:00:00+0800",
                os_name="rhel9", profile="L1"):
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
        "host": {"hostname": hostname, "os": os_name},
        "os": os_name,
        "profile": profile,
        "benchmark": "CIS X Benchmark",
        "summary": summary,
        "results": rules,
    }


def rule(rid, status, title="rule", waived=False):
    # Mirror real engine output: a waived rule carries both the status and
    # the waived flag.
    if status == "waived":
        waived = True
    return {"id": rid, "status": status, "title": f"{title} {rid}",
            "family": "file", "waived": waived}


@pytest.fixture()
def before_doc():
    return make_result([
        rule("1.1.1.1", "pass"), rule("1.1.1.2", "fail"), rule("1.1.1.3", "fail"),
        rule("1.1.1.4", "pass"), rule("1.1.1.5", "pass"), rule("1.1.1.6", "waived"),
    ], score=60.0)


@pytest.fixture()
def after_doc():
    return make_result([
        rule("1.1.1.1", "fail"), rule("1.1.1.2", "pass"), rule("1.1.1.3", "fail"),
        rule("1.1.1.4", "pass"), rule("1.1.1.5", "fail"), rule("1.1.1.6", "pass"),
    ], score=40.0)


def make_scanner(results, fail_on=()):
    """Return a scan callable yielding results in sequence; raise on runs
    whose 1-based index is in `fail_on` (indexing the results list)."""
    calls = {"n": 0}

    def scan():
        calls["n"] += 1
        if calls["n"] - 1 in fail_on:
            raise RuntimeError("scan boom")
        return results[min(calls["n"] - 1, len(results) - 1)]

    return scan


# ─── diff_results ─────────────────────────────────────────────────────

def test_diff_classifies_drift_recovery_and_still_fail(before_doc, after_doc):
    report = cis_host_diff.diff_results(before_doc, after_doc)
    ch = report.changes

    assert {c.rule_id for c in ch[cis_host_diff.NEW_FAIL]} == {"1.1.1.1", "1.1.1.5"}
    assert {c.rule_id for c in ch[cis_host_diff.RECOVERED]} == {"1.1.1.2"}
    assert {c.rule_id for c in ch[cis_host_diff.STILL_FAIL]} == {"1.1.1.3"}
    assert {c.rule_id for c in ch[cis_host_diff.UNWAIVED]} == {"1.1.1.6"}
    assert report.has_drift() is True
    assert report.drift_count() == 3
    assert report.score_delta == -20.0


def test_diff_rule_change_severity_meta():
    r = cis_host_diff.RuleChange("1.1.1.1", cis_host_diff.NEW_FAIL, "fail", "pass",
                               "x", meta={"family": "file"})
    assert r.severity == "critical"
    assert r.meta["family"] == "file"


def test_diff_waived_rule_does_not_count_as_drift(before_doc):
    after = make_result([rule("1.1.1.1", "fail", waived=True),
                         rule("1.1.1.2", "pass")], score=80.0)
    report = cis_host_diff.diff_results(before_doc, after)
    assert {c.rule_id for c in report.changes[cis_host_diff.NOW_WAIVED]} == {"1.1.1.1"}
    assert report.changes[cis_host_diff.NEW_FAIL] == []


def test_diff_handles_rules_only_on_one_side(before_doc):
    after = make_result([rule("1.1.1.1", "pass"), rule("9.9.9.9", "pass")], score=90.0)
    report = cis_host_diff.diff_results(before_doc, after)
    assert {c.rule_id for c in report.changes[cis_host_diff.AFTER_ONLY]} == {"9.9.9.9"}
    assert "1.1.1.2" in {c.rule_id for c in report.changes[cis_host_diff.BEFORE_ONLY]}


def test_diff_warns_on_mismatched_targets(before_doc):
    other = make_result([rule("1.1.1.1", "pass")], os_name="ubuntu2204", score=80.0)
    report = cis_host_diff.diff_results(before_doc, other)
    assert any("different OS" in w for w in report.warnings)


def test_diff_sorting_is_stable():
    before = make_result([rule("2.1.1", "pass"), rule("10.1.1", "pass"),
                          rule("1.1.1.1", "pass")], score=100.0)
    after = make_result([rule("2.1.1", "fail"), rule("10.1.1", "fail"),
                         rule("1.1.1.1", "fail")], score=0.0)
    report = cis_host_diff.diff_results(before, after)
    ids = [c.rule_id for c in report.changes[cis_host_diff.NEW_FAIL]]
    assert ids == ["1.1.1.1", "2.1.1", "10.1.1"]  # natural-ish ordering, not lexicographic


# ─── verify_remediation ───────────────────────────────────────────────

def test_verify_remediation_classifies_fixed_still_and_regressed():
    pre = make_result([rule("1.1.1.1", "fail"), rule("1.1.1.2", "fail"),
                       rule("1.1.1.3", "pass"), rule("1.1.1.4", "pass")])
    post = make_result([rule("1.1.1.1", "pass"), rule("1.1.1.2", "fail"),
                        rule("1.1.1.3", "fail"), rule("1.1.1.4", "pass")])
    v = cis_host_diff.verify_remediation(pre, post)
    assert {c.rule_id for c in v.fixed} == {"1.1.1.1"}
    assert {c.rule_id for c in v.still_fail} == {"1.1.1.2"}
    assert {c.rule_id for c in v.regressed} == {"1.1.1.3"}


def test_verify_remediation_no_baseline_is_safe():
    v = cis_host_diff.verify_remediation(None, make_result([rule("1.1.1.1", "fail")]))
    assert v.is_empty() is True
    assert v.warnings


# ─── waiver hygiene ───────────────────────────────────────────────────

def test_audit_waivers_statuses_and_catalog():
    waivers = {
        "1.1.1.1": "legacy reason",
        "1.1.1.2": {"reason": "accepted", "approved_by": "alice",
                    "expires": "2000-01-01"},
        "1.1.1.3": {"reason": "pending", "expires": "2999-12-31"},
        "typo.rule": {"reason": "oops"},
    }
    catalog = {"1.1.1.1", "1.1.1.2", "1.1.1.3"}
    entries = {e.rule_id: e for e in cis_host_diff.audit_waivers(waivers, catalog)}
    assert entries["1.1.1.1"].status == "active"
    assert entries["1.1.1.2"].status == "expired"
    assert entries["1.1.1.2"].approved_by == "alice"
    assert entries["1.1.1.3"].status == "active"
    assert entries["typo.rule"].in_catalog is False


def test_waiver_problems_lists_expired_invalid_and_noop():
    waivers = {
        "1.1.1.1": {"expires": "2000-01-01", "approved_by": "alice"},
        "1.1.1.2": {"expires": "not-a-date"},
        "typo.rule": "reason",
    }
    problems = cis_host_diff.waiver_problems(waivers, catalog_ids={"1.1.1.1", "1.1.1.2"})
    text = "\n".join(problems)
    assert "EXPIRED" in text and "alice" in text
    assert "invalid expires" in text
    assert "no-op" in text


def test_waiver_problems_clean():
    waivers = {"1.1.1.1": "reason", "1.1.1.2": {"expires": "2999-12-31"}}
    assert cis_host_diff.waiver_problems(waivers, {"1.1.1.1", "1.1.1.2"}) == []
    assert cis_host_diff.waiver_problems(None) == []
    assert cis_host_diff.waiver_problems("not json {") == []


# ─── renderers ────────────────────────────────────────────────────────

def test_render_cli_contains_drift_sections(before_doc, after_doc):
    out = cis_host_diff.render_cli(cis_host_diff.diff_results(before_doc, after_doc))
    assert "NEW FAILURES" in out
    assert "Recovered" in out
    assert "1.1.1.1" in out


def test_render_html_has_filter_and_severity(before_doc, after_doc):
    out = cis_host_diff.render_html(cis_host_diff.diff_results(before_doc, after_doc),
                                  name="CIS RHEL 9", profile="L1", org="ACME")
    assert "Configuration Drift Report" in out
    assert "sev-critical" in out
    assert 'id="f"' in out  # live filter box
    assert "ACME" in out


def test_render_verify_html(before_doc):
    v = cis_host_diff.verify_remediation(
        before_doc,
        make_result([rule("1.1.1.1", "pass"), rule("1.1.1.2", "pass"),
                     rule("1.1.1.3", "fail"), rule("1.1.1.4", "fail")], score=50.0))
    out = cis_host_diff.render_verify_html(v, name="CIS RHEL 9", profile="L1")
    assert "Apply Verification Report" in out
    assert "Fixed by apply" in out
    assert "Regressed (broken by apply)" in out  # 1.1.1.4 was passing


def test_report_to_json_roundtrip(before_doc, after_doc):
    report = cis_host_diff.diff_results(before_doc, after_doc)
    data = json.loads(report.to_json())
    assert data["has_drift"] is True
    assert data["drift_count"] == 3
    assert data["score_delta"] == -20.0
    assert "1.1.1.1" in {c["rule_id"] for c in data["changes"]["new_fail"]}


# ─── WatchSession ─────────────────────────────────────────────────────

def _events_for(results, fail_on=(), **kwargs):
    events = []
    ws = cis_host_diff.WatchSession(make_scanner(results, fail_on),
                                  max_runs=len(results),
                                  interval=0, on_event=events.append, **kwargs)
    ws.run()
    return events


def test_watch_alerts_once_until_cleared():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    drifted = make_result([rule("1.1.1.1", "fail")], score=50.0)
    events = _events_for([base, drifted, drifted, drifted, base])
    types = [e["type"] for e in events]
    assert types.count("drift") == 1        # edge-triggered: not re-alerted
    assert types.count("clear") == 1        # ...until the rule clears
    assert types.count("scan") == 5
    assert events[-1]["reason"] == "completed"


def test_watch_no_clear_while_still_failing():
    """A drifted rule that stays failing must NOT be reported as cleared."""
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    drifted = make_result([rule("1.1.1.1", "fail")], score=50.0)
    events = _events_for([base, drifted, drifted, drifted, base])
    drifts = [e for e in events if e["type"] == "drift"]
    clears = [e for e in events if e["type"] == "clear"]
    assert len(drifts) == 1        # alerted on the transition
    assert len(clears) == 1        # cleared exactly once: on recovery
    assert drifts[0]["run"] == 2
    assert clears[0]["run"] == 5


def test_watch_baseline_failure_is_not_alerted_as_drift():
    """A rule failing in the baseline is a known issue, not new drift."""
    base = make_result([rule("1.1.1.1", "fail")], score=50.0)
    same = make_result([rule("1.1.1.1", "fail")], score=50.0)
    events = _events_for([base, same])
    assert all(e["type"] != "drift" for e in events)


def test_watch_baseline_from_first_scan_is_quiet():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    same = make_result([rule("1.1.1.1", "pass")], score=100.0)
    events = _events_for([base, same])
    assert all(e["type"] != "drift" for e in events)


def test_watch_explicit_baseline_skips_first_scan_for_diffing():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    drifted = make_result([rule("1.1.1.1", "fail")], score=50.0)
    events = []
    ws = cis_host_diff.WatchSession(make_scanner([drifted]), max_runs=1, interval=0,
                                  baseline=base, on_event=events.append)
    ws.run()
    assert any(e["type"] == "drift" for e in events)


def test_watch_survives_scan_errors_and_continues():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    events = _events_for([base, base, base], fail_on={1})
    assert any(e["type"] == "error" for e in events)
    assert sum(e["type"] == "scan" for e in events) == 2  # runs 2 and 3
    assert events[-1]["reason"] == "completed"


def test_watch_interrupt_stops_gracefully():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    events = []
    ws = cis_host_diff.WatchSession(make_scanner([base]), max_runs=99, interval=0,
                                  on_event=events.append)
    original = cis_host_diff.time.sleep
    cis_host_diff.time.sleep = lambda _s: (_ for _ in ()).throw(KeyboardInterrupt())
    try:
        ws.run()
    finally:
        cis_host_diff.time.sleep = original
    assert any(e["type"] == "stop" and e["reason"] == "interrupted" for e in events)


def test_watch_alert_callback_fires_on_new_drift_only():
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    drifted = make_result([rule("1.1.1.1", "fail")], score=50.0)
    alerts = []
    events = []
    ws = cis_host_diff.WatchSession(make_scanner([base, drifted, drifted]),
                                  max_runs=3, interval=0,
                                  alert=lambda ev: alerts.append(ev),
                                  on_event=events.append)
    ws.run()
    assert len(alerts) == 1
    assert alerts[0]["rule_ids"] == ["1.1.1.1"]


def test_watch_json_events_are_line_json(capsys):
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    drifted = make_result([rule("1.1.1.1", "fail")], score=50.0)
    ws = cis_host_diff.WatchSession(make_scanner([base, drifted]), max_runs=2,
                                  interval=0, json_events=True)
    ws.run()
    captured = capsys.readouterr().out.strip().splitlines()
    assert captured
    for line in captured:
        json.loads(line)  # every event is one valid JSON line
    assert any(json.loads(l)["type"] == "drift" for l in captured)


def test_watch_persists_run_json(tmp_path):
    base = make_result([rule("1.1.1.1", "pass")], score=100.0)
    _events_for([base, base], output_dir=str(tmp_path))
    files = sorted(tmp_path.glob("watch-run-*.json"))
    assert len(files) == 2
    json.loads(files[0].read_text(encoding="utf-8"))


# ─── CLI integration ──────────────────────────────────────────────────

def test_diff_cli_output_and_exit_code(before_doc, after_doc, tmp_path):
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    p1.write_text(json.dumps(before_doc), encoding="utf-8")
    p2.write_text(json.dumps(after_doc), encoding="utf-8")

    res = run(["diff", str(p1), str(p2), "--format", "cli"])
    assert res.returncode == 0
    assert "NEW FAILURES" in res.stdout
    assert "1.1.1.1" in res.stdout

    res = run(["diff", str(p1), str(p2), "--format", "cli", "--exit-code"])
    assert res.returncode == 2
    assert "FAIL" in res.stdout


def test_diff_no_drift_passes_gate(before_doc, tmp_path):
    doc = make_result([rule("1.1.1.1", "pass"), rule("1.1.1.2", "pass")], score=100.0)
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    p1.write_text(json.dumps(doc), encoding="utf-8")
    p2.write_text(json.dumps(doc), encoding="utf-8")
    res = run(["diff", str(p1), str(p2), "--format", "cli", "--exit-code"])
    assert res.returncode == 0
    assert "PASS" in res.stdout


def test_diff_missing_file_fails(tmp_path):
    res = run(["diff", str(tmp_path / "nope.json"), str(tmp_path / "also.json"),
               "--format", "cli"])
    assert res.returncode == 1
    assert "not found" in res.stderr


def test_diff_renders_html(before_doc, after_doc, tmp_path):
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    p1.write_text(json.dumps(before_doc), encoding="utf-8")
    p2.write_text(json.dumps(after_doc), encoding="utf-8")
    out_dir = tmp_path / "out"
    res = run(["diff", str(p1), str(p2), "--format", "html", "--output", str(out_dir)])
    assert res.returncode == 0
    files = list(out_dir.glob("drift-*.html"))
    assert len(files) == 1
    assert "Configuration Drift Report" in files[0].read_text(encoding="utf-8")


def test_watch_help_exposes_options():
    res = run(["watch", "--help"])
    assert res.returncode == 0
    for flag in ("--interval", "--alert-cmd", "--baseline", "--max-runs", "--json"):
        assert flag in res.stdout


def test_list_os_still_works():
    res = run(["list-os"])
    assert res.returncode == 0
    assert "rhel9" in res.stdout
