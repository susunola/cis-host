#!/usr/bin/env python3
"""Baseline snapshot tests for cis_cli.py.

These tests exist purely to freeze the current CLI surface (full --help
text for every command/subcommand, plus the OS preset list output) *before*
cis_cli.py is refactored from a single 1730-line module into the cis_cli/
package (see PR1-PR8). They intentionally assert byte-for-byte equality
against recorded snapshots in tests/snapshots/cli/.

Do not "fix" these tests by regenerating snapshots to match a refactored
CLI's output unless the CHANGELOG documents the corresponding intentional
breaking change (see plan section A.4). A snapshot mismatch here is a
signal that the refactor accidentally changed user-visible CLI behavior.
"""

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cis_cli.py")
SNAPSHOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapshots", "cli")

# name -> argv (relative to cis_cli.py)
SNAPSHOT_CASES = {
    "main_help": ["-h"],
    "list_help": ["list", "--help"],
    "list_os_output": ["list-os"],
    "scan_help": ["scan", "--help"],
    "audit_help": ["audit", "--help"],
    "apply_help": ["apply", "--help"],
    "check_help": ["check", "--help"],
    "fleet_help": ["fleet", "--help"],
    "fleet_scan_help": ["fleet", "scan", "--help"],
    "diff_help": ["diff", "--help"],
    "watch_help": ["watch", "--help"],
    "info_help": ["info", "--help"],
}


def run(args):
    cmd = [sys.executable, CLI] + args
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if result.returncode != 0:
        pytest.fail(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


@pytest.mark.parametrize("name", sorted(SNAPSHOT_CASES.keys()))
def test_cli_snapshot(name):
    snapshot_path = os.path.join(SNAPSHOT_DIR, f"{name}.txt")
    with open(snapshot_path, "r") as f:
        expected = f.read()
    actual = run(SNAPSHOT_CASES[name])
    assert actual == expected, (
        f"CLI output for {name!r} drifted from recorded snapshot at "
        f"{snapshot_path}. If this is an intentional breaking change, "
        f"update the snapshot and record it in the CHANGELOG."
    )


def test_all_subcommands_covered():
    """Guard against silently missing a subcommand in SNAPSHOT_CASES."""
    result = run(["-h"])
    for cmd in ("list", "scan", "audit", "apply", "check", "fleet", "diff", "watch", "info"):
        assert cmd in result
