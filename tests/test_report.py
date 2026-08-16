#!/usr/bin/env python3
"""Unit tests for report.py (extracted from ohbs_cli.py in PR3).

Covers the render_report() template context (ctx dict) completeness and
the output filename / copy_json side effects, using a minimal on-disk
Jinja2 template so no real ohbs_engine.py or report.html.j2 asset is needed.
"""

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from report import render_report

# Every cis_* key the real report.html.j2 templates (Ansible-mirrored
# variables) reference. If render_report() ever drops one of these from
# ctx, a template relying on it would silently render blank/undefined
# instead of failing loudly, so we pin the full set here.
EXPECTED_CTX_KEYS = {
    "cis_result", "cis_guidance", "cis_sections", "cis_mode_effective",
    "cis_mode", "cis_profile", "cis_platform", "cis_benchmark_name",
    "cis_benchmark_version", "cis_org_name", "ohbs_host", "cis_run_human",
    "cis_run_stamp", "cis_fleet_size", "cis_backup_dir",
    "cis_allow_disruptive", "cis_lang", "cis_report_embed_remediation",
}


def _args(tmp_path, template_body, **overrides):
    template_path = tmp_path / "report.html.j2"
    template_path.write_text(template_body, encoding="utf-8")
    defaults = dict(
        template=str(template_path), guidance="", sections="",
        profile="L1", platform="server", name="Test Benchmark",
        version="1.0", org=None, backup_dir="", allow_disruptive=False,
        output=str(tmp_path), copy_json=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _result_data():
    return {
        "summary": {"all": {"pass": 1, "fail": 0}},
        "results": [],
        "host": {},
    }


def _fake_host():
    return {"hostname": "unit-test-host", "os": "TestOS"}


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_context_has_all_expected_keys(mock_host, tmp_path):
    """Capture the ctx dict passed to template.render() via a template
    that dumps every variable name it's given, so we can assert on the
    actual keys rather than re-deriving them from source."""
    template_body = "{{ cis_result and cis_guidance is defined }}"
    args = _args(tmp_path, template_body)

    captured = {}
    import jinja2

    real_env_class = jinja2.Environment

    class _CapturingEnv(real_env_class):
        def get_template(self, name):
            tmpl = super().get_template(name)
            orig_render = tmpl.render

            def _render(**ctx):
                captured.update(ctx)
                return orig_render(**ctx)

            tmpl.render = _render
            return tmpl

    with patch("jinja2.Environment", _CapturingEnv):
        out_path = render_report(_result_data(), args, "scan", str(tmp_path / "result.json"))

    assert out_path is not None
    assert EXPECTED_CTX_KEYS <= set(captured.keys())


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_writes_html_file(mock_host, tmp_path):
    args = _args(tmp_path, "<html>{{ cis_benchmark_name }}</html>")
    out_path = render_report(_result_data(), args, "scan", str(tmp_path / "result.json"))

    assert out_path is not None
    assert os.path.exists(out_path)
    assert out_path.endswith(".html")
    assert "unit-test-host" in out_path
    with open(out_path, "r", encoding="utf-8") as fh:
        assert "Test Benchmark" in fh.read()


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_copy_json(mock_host, tmp_path):
    result_file = tmp_path / "result.json"
    result_file.write_text(json.dumps(_result_data()), encoding="utf-8")

    args = _args(tmp_path, "<html></html>", copy_json=True)
    out_path = render_report(_result_data(), args, "scan", str(result_file))

    json_path = out_path.rsplit(".", 1)[0] + ".json"
    assert os.path.exists(json_path)


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_loads_guidance_and_sections(mock_host, tmp_path):
    guidance_path = tmp_path / "guidance.json"
    guidance_path.write_text(json.dumps({"1.1": {"description": "desc"}}), encoding="utf-8")
    sections_path = tmp_path / "sections.json"
    sections_path.write_text(json.dumps({"chapters": {"1": "Chapter 1"}, "subsections": {}}), encoding="utf-8")

    args = _args(
        tmp_path,
        "{{ cis_guidance['1.1']['description'] }}/{{ cis_sections['chapters']['1'] }}",
        guidance=str(guidance_path), sections=str(sections_path),
    )
    out_path = render_report(_result_data(), args, "scan", str(tmp_path / "result.json"))

    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "desc" in content
    assert "Chapter 1" in content


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_template_error_returns_none(mock_host, tmp_path):
    args = _args(tmp_path, "{{ this is not valid jinja !! }}")
    out_path = render_report(_result_data(), args, "scan", str(tmp_path / "result.json"))
    assert out_path is None


@patch("report.collect_host", side_effect=_fake_host)
def test_render_report_registers_bool_filter(mock_host, tmp_path):
    """Regression test for the L4 e2e finding: the real report.html.j2
    templates use the `| bool` Jinja2 filter (a built-in under Ansible's
    Jinja2), but plain Jinja2 has no `bool` filter. Without registering
    one, every `ohbs-host scan/apply/audit --format html` crashed with
    `jinja2.exceptions.TemplateRuntimeError: No filter named 'bool' found`.
    render_report() must register a `bool` filter so the template renders.
    """
    template_body = "{{ (cis_allow_disruptive | bool) and 'x' }}"
    args = _args(tmp_path, template_body, allow_disruptive=True)
    out_path = render_report(_result_data(), args, "scan", str(tmp_path / "result.json"))
    assert out_path is not None, "render_report crashed; `| bool` filter not registered"
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "x" in content

