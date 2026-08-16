#!/usr/bin/env python3
"""Tests for the Windows CIS engines and roles."""

import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WINDOWS_ENGINES = [
    os.path.join(ROOT, "cis-win2016-ansible/roles/cis-win2016/files/ohbs_engine.ps1"),
    os.path.join(ROOT, "cis-win2019-ansible/roles/cis-win2019/files/ohbs_engine.ps1"),
    os.path.join(ROOT, "cis-win2022-ansible/roles/cis-win2022/files/ohbs_engine.ps1"),
    os.path.join(ROOT, "cis-win2025-ansible/roles/cis-win2025/files/ohbs_engine.ps1"),
]


@pytest.mark.parametrize("engine", WINDOWS_ENGINES)
def test_engine_exists(engine):
    assert os.path.exists(engine)


@pytest.mark.parametrize("engine", WINDOWS_ENGINES)
def test_rules_count(engine):
    rules_file = os.path.join(os.path.dirname(engine), "rules.json")
    with open(rules_file, "r", encoding="utf-8") as fh:
        rules = json.load(fh)
    assert len(rules) >= 400, f"expected full Windows benchmark catalog, got {len(rules)} rules"


@pytest.mark.parametrize("engine", WINDOWS_ENGINES)
def test_no_debug_lines(engine):
    with open(engine, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "DBG:" not in content
    assert "JavaScriptSerializer" not in content


@pytest.mark.parametrize("engine", WINDOWS_ENGINES)
def test_profile_param_exists(engine):
    with open(engine, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "$ProfileLevel" in content
    assert "param(" in content
