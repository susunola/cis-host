#!/usr/bin/env python3
"""Unit tests for info.py (extracted from ohbs_cli.py in PR6).

Covers cmd_info()'s not-found exit path, and render_info_html()'s
templates/rule_info.html.j2 rendering, including the levels_display
field (L1/L2 formatting) and HTML escaping of untrusted rule content.
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from info import cmd_info, render_info_html


def _detail(**overrides):
    base = dict(
        id="1.1.1.1", title="Ensure cramfs kernel module is not available",
        section="1.1.1", section_chapter="Filesystem", section_subsection="Special Purpose",
        family="kmod", levels=[1], risk="safe", platforms=["ubuntu2204"],
        automated=True, page="12", assessment="Automated",
        params={"module": "cramfs"}, description="desc text", rationale="rationale text",
        remediation="remediation text", benchmark="CIS Test Benchmark",
        benchmark_version="1.0.0", total_rules=100,
    )
    base.update(overrides)
    return base


def test_cmd_info_exits_when_rule_not_found(capsys):
    args = SimpleNamespace(id="9.9.9.9", format="cli", catalog="/fake.json",
                           guidance="", sections="", name="X", version="1.0")
    with patch("info.get_rule_detail", return_value=None):
        with pytest.raises(SystemExit) as exc_info:
            cmd_info(args)
    assert exc_info.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_cmd_info_html_format_delegates_to_render(tmp_path):
    args = SimpleNamespace(id="1.1.1.1", format="html", catalog="/fake.json",
                           guidance="", sections="", name="X", version="1.0",
                           output=str(tmp_path))
    with patch("info.get_rule_detail", return_value=_detail()):
        out_path = cmd_info(args)
    assert out_path is not None
    assert os.path.exists(out_path)


def test_render_info_html_levels_display(tmp_path):
    args = SimpleNamespace(output=str(tmp_path))
    out_path = render_info_html(_detail(levels=[1, 2]), args)
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "L1, L2" in content


def test_render_info_html_writes_expected_filename(tmp_path):
    args = SimpleNamespace(output=str(tmp_path))
    out_path = render_info_html(_detail(id="5.2.3"), args)
    assert os.path.basename(out_path) == "info-5-2-3.html"


def test_render_info_html_includes_sections(tmp_path):
    args = SimpleNamespace(output=str(tmp_path))
    out_path = render_info_html(_detail(), args)
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "desc text" in content
    assert "rationale text" in content
    assert "remediation text" in content
    assert "<td>module</td><td>cramfs</td>" in content


def test_render_info_html_omits_empty_sections(tmp_path):
    args = SimpleNamespace(output=str(tmp_path))
    out_path = render_info_html(_detail(rationale="", params={}), args)
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "Rationale" not in content
    assert "Parameters" not in content


def test_render_info_html_escapes_untrusted_content(tmp_path):
    args = SimpleNamespace(output=str(tmp_path))
    out_path = render_info_html(_detail(title="<script>alert(1)</script>"), args)
    with open(out_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "<script>alert(1)</script>" not in content
