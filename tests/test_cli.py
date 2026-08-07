#!/usr/bin/env python3
"""Tests for cis_cli.py."""

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cis_cli.py")


def run(args, check=True):
    cmd = [sys.executable, CLI] + args
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if check and result.returncode != 0:
        pytest.fail(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def test_list_os():
    result = run(["list-os"])
    assert "tencentos3" in result.stdout
    assert "tencentos4" in result.stdout
    assert "win2022" in result.stdout
    assert "rhel9" in result.stdout


def test_scan_help():
    result = run(["scan", "--help"])
    assert "--engine" in result.stdout
    assert "--strict" in result.stdout


def test_apply_help():
    result = run(["apply", "--help"])
    assert "--allow-disruptive" in result.stdout


def test_check_help():
    result = run(["check", "--help"])
    assert "--template" in result.stdout


def test_info_help():
    result = run(["info", "--help"])
    assert "--id" in result.stdout


def test_audit_help():
    result = run(["audit", "--help"])
    assert "--engine" in result.stdout
    assert "--variables" in result.stdout


def test_fleet_scan_help():
    result = run(["fleet", "scan", "--help"])
    assert "--fleet-hosts" in result.stdout
    assert "--fleet-remote" in result.stdout
