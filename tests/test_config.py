#!/usr/bin/env python3
"""Tests for ciscvm.toml config loading and CLI merging."""

import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ciscvm_config


def _args(**kwargs):
    # Simulate argparse defaults after the switch to None for optional values
    # so that ciscvm.toml can supply them.
    defaults = {
        "os": None,
        "profile": None,
        "platform": None,
        "name": None,
        "version": None,
        "org": None,
        "include": None,
        "exclude": None,
        "sections_filter": None,
        "families": None,
        "output": None,
        "format": None,
        "copy_json": None,
        "strict": None,
        "timeout": None,
        "allow_disruptive": None,
        "backup_dir": None,
        "audit_log": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_load_missing_file_returns_none(tmp_path):
    assert ciscvm_config.load(str(tmp_path / "nope.toml")) is None


def test_load_valid_toml(tmp_path):
    p = tmp_path / "ciscvm.toml"
    p.write_text("""
[profile]
os = "rhel9"
profile = "L2"

[rules]
include = ["1.1.1", "1.1.2"]
exclude = "5.1.1"
""")
    cfg = ciscvm_config.load(str(p))
    assert cfg["profile"]["os"] == "rhel9"
    assert cfg["profile"]["profile"] == "L2"
    assert cfg["rules"]["include"] == ["1.1.1", "1.1.2"]
    assert cfg["rules"]["exclude"] == "5.1.1"


def test_merge_applies_defaults(tmp_path):
    p = tmp_path / "ciscvm.toml"
    p.write_text("""
[profile]
os = "ubuntu2204"
profile = "L2"
platform = "workstation"
name = "CIS Ubuntu"
version = "v1.1.0"
org = "ACME"

[rules]
include = ["1.1.1"]
exclude = ["2.1.1"]
sections = ["1.1"]
families = ["ssh"]

[output]
directory = "./reports"
format = "html"
copy_json = true
strict = true

[engine]
timeout = 300
allow_disruptive = true
backup_dir = "/tmp/backups"
audit_log = "/tmp/audit.jsonl"
""")
    args = _args()
    merged = ciscvm_config.merge(args, str(p))
    assert merged.os == "ubuntu2204"
    assert merged.profile == "L2"
    assert merged.platform == "workstation"
    assert merged.name == "CIS Ubuntu"
    assert merged.version == "v1.1.0"
    assert merged.org == "ACME"
    assert merged.include == "1.1.1"
    assert merged.exclude == "2.1.1"
    assert merged.sections_filter == "1.1"
    assert merged.families == "ssh"
    assert merged.output == "./reports"
    assert merged.format == "html"
    assert merged.copy_json is True
    assert merged.strict is True
    assert merged.timeout == 300
    assert merged.allow_disruptive is True
    assert merged.backup_dir == "/tmp/backups"
    assert merged.audit_log == "/tmp/audit.jsonl"


def test_cli_args_override_config(tmp_path):
    p = tmp_path / "ciscvm.toml"
    p.write_text("""
[profile]
os = "rhel8"
profile = "L2"
""")
    args = _args(os="rhel9", profile="L1")
    merged = ciscvm_config.merge(args, str(p))
    assert merged.os == "rhel9"
    assert merged.profile == "L1"


def test_merge_without_config_returns_args(tmp_path):
    args = _args(os="rhel9")
    merged = ciscvm_config.merge(args, str(tmp_path / "missing.toml"))
    assert merged.os == "rhel9"
