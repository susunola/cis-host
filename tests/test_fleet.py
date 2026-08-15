#!/usr/bin/env python3
"""Unit tests for fleet.py (extracted from cis_cli.py in PR5).

Covers _normalize_list/load_fleet_hosts host-list parsing, the
aggregate_fleet_results() rollup math (per-host summaries -> fleet totals
and score), and render_fleet_report()'s use of templates/fleet_report.html.j2
(replacing the inline HTML string that used to live in cis_cli.py).
"""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fleet


def test_normalize_list_variants():
    assert fleet._normalize_list(None) == ""
    assert fleet._normalize_list("a,b") == "a,b"
    assert fleet._normalize_list(["a", "b", "c"]) == "a,b,c"
    assert fleet._normalize_list(1) == "1"


def test_load_fleet_hosts_from_cli_flag():
    args = SimpleNamespace(fleet_hosts="web1, web2 ,db1", fleet={})
    assert fleet.load_fleet_hosts(args) == ["web1", "web2", "db1"]


def test_load_fleet_hosts_from_config_list():
    args = SimpleNamespace(fleet_hosts=None, fleet={"hosts": ["web1", "web2"]})
    assert fleet.load_fleet_hosts(args) == ["web1", "web2"]


def test_load_fleet_hosts_empty():
    args = SimpleNamespace(fleet_hosts=None, fleet={})
    assert fleet.load_fleet_hosts(args) == []


def _host_summary(host, total, passed, failed, manual=0, error=0, notapplicable=0, waived=0):
    return {
        "total": total, "pass": passed, "fail": failed, "manual": manual,
        "error": error, "notapplicable": notapplicable, "waived": waived,
        "_host": host,
    }


def test_aggregate_fleet_results_rollup_math():
    host_results = [
        ("web1", {"results": [], "summary": {"all": _host_summary("web1", 10, 8, 2)}}),
        ("web2", {"results": [], "summary": {"all": _host_summary("web2", 10, 5, 5)}}),
    ]
    agg = fleet.aggregate_fleet_results(host_results)

    assert agg["fleet_size"] == 2
    assert agg["reachable"] == 2
    all_summary = agg["summary"]["all"]
    assert all_summary["total"] == 20
    assert all_summary["pass"] == 13
    assert all_summary["fail"] == 7
    # score = 100 * pass / (pass + fail) = 100 * 13 / 20 = 65.0
    assert all_summary["score"] == 65.0


def test_aggregate_fleet_results_skips_unreachable_hosts():
    host_results = [
        ("web1", {"results": [], "summary": {"all": _host_summary("web1", 10, 10, 0)}}),
        ("web2", None),  # unreachable / engine failure
    ]
    agg = fleet.aggregate_fleet_results(host_results)

    assert agg["fleet_size"] == 2  # total hosts attempted
    assert agg["reachable"] == 1  # only web1 contributed a summary
    assert agg["summary"]["all"]["pass"] == 10


def test_aggregate_fleet_results_zero_scored_gives_zero_score():
    host_results = [
        ("web1", {"results": [], "summary": {"all": _host_summary("web1", 5, 0, 0, manual=5)}}),
    ]
    agg = fleet.aggregate_fleet_results(host_results)
    assert agg["summary"]["all"]["score"] == 0.0


def test_aggregate_fleet_results_tags_results_with_host():
    host_results = [
        ("web1", {"results": [{"id": "1.1"}], "summary": {"all": _host_summary("web1", 1, 1, 0)}}),
    ]
    agg = fleet.aggregate_fleet_results(host_results)
    assert agg["results"][0]["_fleet_host"] == "web1"


def test_render_fleet_report_uses_template_and_writes_html(tmp_path):
    aggregate = {
        "fleet_size": 2,
        "reachable": 2,
        "summary": {"all": {"score": 87.5}},
        "summaries": [
            _host_summary("web1", 10, 9, 1),
            _host_summary("web2", 10, 8, 2),
        ],
    }
    args = SimpleNamespace(name="Test Benchmark", profile="L1", output=str(tmp_path))

    out_path = fleet.render_fleet_report(aggregate, args)

    assert os.path.exists(out_path)
    assert out_path.endswith(".html")
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "Test Benchmark" in content
    assert "web1" in content
    assert "web2" in content
    assert "87.5" in content
    assert "2 host(s)" in content
    assert "2 reachable" in content


def test_render_fleet_report_escapes_html_in_benchmark_name(tmp_path):
    aggregate = {
        "fleet_size": 1, "reachable": 1,
        "summary": {"all": {"score": 100.0}},
        "summaries": [_host_summary("web1", 1, 1, 0)],
    }
    args = SimpleNamespace(name="<script>alert(1)</script>", profile="L1", output=str(tmp_path))

    out_path = fleet.render_fleet_report(aggregate, args)
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "<script>alert(1)</script>" not in content
