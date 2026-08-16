#!/usr/bin/env python3
"""Unit tests for the top-level engine.py (extracted from ohbs_cli.py in PR2).

Not to be confused with tests/test_engine.py, which tests the per-OS
ohbs_engine.py rule-checking engines under cis-<os>-ansible/.../files/.

Mocks subprocess.run so these tests exercise argv assembly and result-file
handling without invoking a real ohbs_engine.py/ohbs_engine.ps1 or requiring
root/sudo.
"""

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine as cli_engine


def _args(output_dir, **overrides):
    defaults = dict(
        os="", engine="/fake/ohbs_engine.py", catalog="/fake/rules.json",
        profile="L1", platform="server", name="Test Benchmark",
        include=None, exclude=None, sections_filter=None, families=None,
        allow_disruptive=False, backup_dir="", audit_log="",
        variables=None, waivers=None, simulate=False,
        output=output_dir, timeout=600,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _mock_proc(returncode=0):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stderr = ""
    return proc


def _write_result_file_side_effect(result_payload):
    """Return a subprocess.run replacement that writes the engine result
    JSON to whatever --out/-Out path was passed, mimicking real engine
    behavior, then returns a successful CompletedProcess mock."""
    def _run(cmd, **kwargs):
        out_flag = "--out" if "--out" in cmd else "-Out"
        idx = cmd.index(out_flag)
        result_path = cmd[idx + 1]
        with open(result_path, "w", encoding="utf-8") as fh:
            json.dump(result_payload, fh)
        return _mock_proc(0)
    return _run


# ─── is_windows / default_shell ──────────────────────────────────────

def test_is_windows_reflects_platform():
    with patch.object(sys, "platform", "win32"):
        assert cli_engine.is_windows() is True
    with patch.object(sys, "platform", "linux"):
        assert cli_engine.is_windows() is False


def test_default_shell():
    with patch.object(sys, "platform", "win32"):
        assert cli_engine.default_shell() == "powershell"
    with patch.object(sys, "platform", "linux"):
        assert cli_engine.default_shell() == "/bin/bash"


# ─── _engine_is_windows ───────────────────────────────────────────────

def test_engine_is_windows_by_os_preset():
    args = SimpleNamespace(os="win2022", engine="")
    assert cli_engine._engine_is_windows(args) is True


def test_engine_is_windows_by_engine_extension():
    args = SimpleNamespace(os="", engine="/path/to/ohbs_engine.ps1")
    assert cli_engine._engine_is_windows(args) is True


def test_engine_is_windows_false_for_linux():
    args = SimpleNamespace(os="rhel9", engine="/path/to/ohbs_engine.py")
    assert cli_engine._engine_is_windows(args) is False


# ─── _materialize_json_arg ────────────────────────────────────────────

def test_materialize_json_arg_empty_returns_empty():
    assert cli_engine._materialize_json_arg(None, "variables", "/tmp") == ""
    assert cli_engine._materialize_json_arg("", "variables", "/tmp") == ""


def test_materialize_json_arg_existing_file_returned_as_is(tmp_path):
    f = tmp_path / "vars.json"
    f.write_text('{"min_len": 14}')
    result = cli_engine._materialize_json_arg(str(f), "variables", str(tmp_path))
    assert result == os.path.abspath(str(f))


def test_materialize_json_arg_inline_json_written_to_file(tmp_path):
    result = cli_engine._materialize_json_arg('{"min_len": 14}', "variables", str(tmp_path))
    assert os.path.isfile(result)
    with open(result) as fh:
        assert json.load(fh) == {"min_len": 14}


def test_materialize_json_arg_dict_written_to_file(tmp_path):
    result = cli_engine._materialize_json_arg({"min_len": 14}, "variables", str(tmp_path))
    assert os.path.isfile(result)


def test_materialize_json_arg_invalid_json_raises(tmp_path):
    with pytest.raises(ValueError):
        cli_engine._materialize_json_arg("not valid json{{{", "variables", str(tmp_path))


# ─── _waiver_catalog_ids ──────────────────────────────────────────────

def test_waiver_catalog_ids_from_list_catalog(tmp_path):
    catalog_file = tmp_path / "rules.json"
    catalog_file.write_text(json.dumps([{"id": "1.1.1"}, {"id": "1.1.2"}]))
    args = SimpleNamespace(catalog=str(catalog_file))
    assert cli_engine._waiver_catalog_ids(args) == {"1.1.1", "1.1.2"}


def test_waiver_catalog_ids_missing_file_returns_none():
    args = SimpleNamespace(catalog="/nonexistent/rules.json")
    assert cli_engine._waiver_catalog_ids(args) is None


# ─── run_engine: argv assembly ────────────────────────────────────────

def test_run_engine_linux_argv_assembly(tmp_path):
    args = _args(str(tmp_path), include="1.1.1,1.1.2", allow_disruptive=True)
    result_payload = {"summary": {"all": {"total": 1}}}

    with patch("engine.subprocess.run", side_effect=_write_result_file_side_effect(result_payload)) as mock_run:
        data, result_file = cli_engine.run_engine(args, "scan")

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "sudo"
    assert cmd[1] == "python3"
    assert "--catalog" in cmd
    assert "--mode" in cmd and cmd[cmd.index("--mode") + 1] == "scan"
    assert "--include" in cmd and cmd[cmd.index("--include") + 1] == "1.1.1,1.1.2"
    assert "--allow-disruptive" in cmd
    assert data == result_payload


def test_run_engine_windows_argv_assembly(tmp_path):
    args = _args(str(tmp_path), os="win2022", engine="/fake/ohbs_engine.ps1", families="reg-dword")
    result_payload = {"summary": {"all": {"total": 1}}}

    with patch("engine.subprocess.run", side_effect=_write_result_file_side_effect(result_payload)) as mock_run:
        data, result_file = cli_engine.run_engine(args, "scan")

    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "powershell"
    assert "-Catalog" in cmd
    assert "-Mode" in cmd and cmd[cmd.index("-Mode") + 1] == "scan"
    assert "-Families" in cmd and cmd[cmd.index("-Families") + 1] == "reg-dword"
    # Windows engine doesn't get --allow-disruptive as sudo/python3 style flags
    assert "sudo" not in cmd


def test_run_engine_no_result_file_exits(tmp_path):
    args = _args(str(tmp_path))
    with patch("engine.subprocess.run", return_value=_mock_proc(0)):
        with pytest.raises(SystemExit):
            cli_engine.run_engine(args, "scan")


def test_run_engine_timeout_exits(tmp_path):
    import subprocess as real_subprocess
    args = _args(str(tmp_path))
    with patch("engine.subprocess.run", side_effect=real_subprocess.TimeoutExpired(cmd="x", timeout=1)):
        with pytest.raises(SystemExit):
            cli_engine.run_engine(args, "scan")


def test_run_engine_scan_nonzero_exit_without_result_propagates_code(tmp_path):
    args = _args(str(tmp_path))
    with patch("engine.subprocess.run", return_value=_mock_proc(3)):
        with pytest.raises(SystemExit) as exc_info:
            cli_engine.run_engine(args, "scan")
        assert exc_info.value.code == 3


# ─── collect_host ──────────────────────────────────────────────────────

def test_collect_host_returns_expected_keys():
    info = cli_engine.collect_host()
    for key in ("hostname", "fqdn", "os", "kernel", "arch", "ipv4", "uptime_seconds"):
        assert key in info
