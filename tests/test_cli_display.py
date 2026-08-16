#!/usr/bin/env python3
"""Unit tests for display.py (extracted from ohbs_cli.py in PR2).

Covers the click_style() NO_COLOR/TTY-detection behavior change: the
original ohbs_cli.py always emitted ANSI color codes; this refactor makes
click_style() a no-op when NO_COLOR is set or stdout is not a TTY (see
CHANGELOG).
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import display


def _isatty(value):
    return patch.object(sys.stdout, "isatty", return_value=value)


def _no_color(value):
    """value=True sets NO_COLOR=1, value=False ensures it's unset."""
    env = dict(os.environ)
    if value:
        env["NO_COLOR"] = "1"
    else:
        env.pop("NO_COLOR", None)
    return patch.dict(os.environ, env, clear=True)


def test_click_style_colors_when_tty_and_no_color_unset():
    with _no_color(False), _isatty(True):
        result = display.click_style("hello", "red")
    assert result == "\033[31mhello\033[0m"


def test_click_style_plain_when_not_a_tty():
    with _no_color(False), _isatty(False):
        result = display.click_style("hello", "red")
    assert result == "hello"


def test_click_style_plain_when_no_color_set():
    with _no_color(True), _isatty(True):
        result = display.click_style("hello", "red")
    assert result == "hello"


def test_click_style_unknown_color_falls_back_to_reset_code():
    with _no_color(False), _isatty(True):
        result = display.click_style("hello", "not-a-color")
    assert result == "\033[0mhello\033[0m"


# ─── print_summary / print_result_table smoke tests ────────────────────

def test_print_summary_scan_mode(capsys):
    data = {
        "summary": {"all": {"total": 10, "score": 80.0, "hardening_index": 75.0,
                              "pass": 8, "fail": 2, "manual": 0, "error": 0,
                              "notapplicable": 0, "waived": 0}},
        "profile": "L1", "platform": "server", "duration_seconds": 5.2,
    }
    display.print_summary(data, "scan")
    out = capsys.readouterr().out
    assert "Score:           80.0%" in out
    assert "Fail:            2" in out


def test_print_summary_apply_mode(capsys):
    data = {
        "summary": {"all": {"total": 5, "applied": 3, "applied_pending": 0,
                              "already": 2, "failed": 0, "skipped_disruptive": 0}},
        "profile": "L1", "platform": "server", "duration_seconds": 1.0,
    }
    display.print_summary(data, "apply")
    out = capsys.readouterr().out
    assert "Applied:         3" in out


def test_print_result_table_empty_results(capsys):
    display.print_result_table({"results": []})
    out = capsys.readouterr().out
    assert "(no results)" in out


def test_print_result_table_with_results(capsys):
    with _no_color(False), _isatty(False):
        data = {"results": [
            {"id": "1.1.1", "status": "pass", "family": "kmod", "title": "Ensure X"},
            {"id": "1.1.2", "status": "fail", "family": "sysctl", "title": "Ensure Y"},
        ]}
        display.print_result_table(data)
    out = capsys.readouterr().out
    assert "1.1.1" in out
    assert "1.1.2" in out
    assert "1 pass" in out
    assert "1 fail" in out
