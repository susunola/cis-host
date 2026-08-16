#!/usr/bin/env python3
"""Unit tests for presets.py and catalog.py (extracted from ohbs_cli.py in PR1)."""

import json
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import presets
import catalog

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ─── presets.py ─────────────────────────────────────────────────────────

def test_os_presets_has_all_14_os():
    expected = {
        "tencentos3", "tencentos4", "rhel8", "rhel9", "rhel10",
        "sles15", "sles16", "ubuntu2004", "ubuntu2204", "ubuntu2404",
        "win2016", "win2019", "win2022", "win2025",
    }
    assert set(presets.OS_PRESETS.keys()) == expected


def test_os_presets_paths_resolve_to_real_files():
    """Every engine/catalog/guidance/sections/template path must exist on disk
    (relative to the repo root), since ohbs_cli.py joins them with _SCRIPT_DIR."""
    for os_id, preset in presets.OS_PRESETS.items():
        for key in ("engine", "catalog", "guidance", "sections", "template"):
            path = os.path.join(ROOT, preset[key])
            assert os.path.exists(path), f"{os_id}.{key} -> {path} does not exist"


def test_os_presets_name_is_nonempty_string():
    for os_id, preset in presets.OS_PRESETS.items():
        assert isinstance(preset["name"], str) and preset["name"]


# ─── catalog.py ─────────────────────────────────────────────────────────

@pytest.fixture
def catalog_path(tmp_path):
    rules = [
        {"id": "1.1.1", "title": "Test rule", "section": "1.1"},
        {"id": "1.1.2", "title": "Another rule", "section": "1.1"},
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


def test_find_rule_found(catalog_path):
    rule, total = catalog.find_rule(catalog_path, "1.1.2")
    assert rule["title"] == "Another rule"
    assert total == 2


def test_find_rule_not_found(catalog_path):
    rule, total = catalog.find_rule(catalog_path, "9.9.9")
    assert rule is None
    assert total == 2


def test_lookup_guidance_missing_path_returns_empty():
    assert catalog.lookup_guidance("", "1.1.1") == {}
    assert catalog.lookup_guidance("/nonexistent/guidance.json", "1.1.1") == {}


def test_lookup_guidance_returns_entry(tmp_path):
    g = {"1.1.1": {"description": "desc", "rationale": "why"}}
    p = tmp_path / "guidance.json"
    p.write_text(json.dumps(g))
    assert catalog.lookup_guidance(str(p), "1.1.1") == g["1.1.1"]
    assert catalog.lookup_guidance(str(p), "9.9.9") == {}


def test_lookup_section_dict_format(tmp_path):
    s = {
        "chapters": {"1": "Initial Setup"},
        "subsections": {"1.1": "Filesystem Configuration"},
    }
    p = tmp_path / "sections.json"
    p.write_text(json.dumps(s))
    chapter, subsection = catalog.lookup_section(str(p), "1.1")
    assert chapter == "Initial Setup"
    assert subsection == "Filesystem Configuration"


def test_lookup_section_list_format_windows_style(tmp_path):
    s = [
        {"id": "1", "title": "Account Policies"},
        {"id": "1.1", "title": "Password Policy"},
    ]
    p = tmp_path / "sections.json"
    p.write_text(json.dumps(s))
    chapter, subsection = catalog.lookup_section(str(p), "1.1")
    assert chapter == "Account Policies"
    assert subsection == "Password Policy"


def test_lookup_section_missing_path_returns_empty_strings():
    assert catalog.lookup_section("", "1.1") == ("", "")


def test_get_rule_detail_builds_full_dict(tmp_path):
    rules = [{
        "id": "1.1.1", "title": "Ensure X", "section": "1.1",
        "family": "kmod", "levels": [1], "risk": "safe",
        "platforms": ["linux"], "assessment": "Automated",
        "params": {"module": "cramfs"}, "page": 12,
    }]
    catalog_p = tmp_path / "rules.json"
    catalog_p.write_text(json.dumps(rules))

    guidance = {"1.1.1": {"description": "d", "rationale": "r", "remediation": "m"}}
    guidance_p = tmp_path / "guidance.json"
    guidance_p.write_text(json.dumps(guidance))

    sections = {"chapters": {"1": "Ch1"}, "subsections": {"1.1": "Sub1"}}
    sections_p = tmp_path / "sections.json"
    sections_p.write_text(json.dumps(sections))

    args = SimpleNamespace(
        catalog=str(catalog_p), guidance=str(guidance_p), sections=str(sections_p),
        name="Test Benchmark", version="1.0",
    )
    detail = catalog.get_rule_detail(args, "1.1.1")
    assert detail["id"] == "1.1.1"
    assert detail["family"] == "kmod"
    assert detail["automated"] is True
    assert detail["section_chapter"] == "Ch1"
    assert detail["section_subsection"] == "Sub1"
    assert detail["description"] == "d"
    assert detail["benchmark"] == "Test Benchmark"
    assert detail["total_rules"] == 1


def test_get_rule_detail_returns_none_when_rule_missing(tmp_path):
    catalog_p = tmp_path / "rules.json"
    catalog_p.write_text(json.dumps([]))
    args = SimpleNamespace(catalog=str(catalog_p), guidance="", sections="",
                            name="Test", version="1.0")
    assert catalog.get_rule_detail(args, "9.9.9") is None
