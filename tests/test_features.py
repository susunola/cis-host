#!/usr/bin/env python3
"""Tests for newer cis-host features: evidence snapshot, webhook
notification, remediate mode, and config merging for those options."""

import http.server
import json
import os
import subprocess
import sys
import tarfile
import threading
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cis_cli.py")

sys.path.insert(0, ROOT)
import notify
import cis_host_config
import commands_scan


def run(args, check=True, **kwargs):
    cmd = [sys.executable, CLI] + args
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, **kwargs)
    if check and result.returncode != 0:
        pytest.fail(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


@pytest.fixture
def sample_result(tmp_path):
    path = tmp_path / "result.json"
    data = {
        "schema": 1,
        "engine_version": "1.2.0",
        "benchmark": "CIS Test Benchmark",
        "mode": "scan",
        "profile": "L1",
        "started_at": "2026-08-07T17:49:34+0800",
        "host": {"hostname": "testhost"},
        "summary": {
            "all": {
                "total": 4,
                "pass": 2,
                "fail": 1,
                "error": 0,
                "skipped": 1,
                "waived": 0,
                "score": 66.7,
            }
        },
        "results": [
            {"id": "1.1.1", "title": "Pass rule", "section": "1.1", "status": "pass",
             "detail": "ok", "duration_ms": 10, "family": "mount", "risk": "safe"},
            {"id": "5.2.1", "title": "SSH rule", "section": "5.2", "status": "fail",
             "detail": "PermitRootLogin yes", "duration_ms": 120, "family": "ssh", "risk": "safe",
             "apply_status": "applied", "apply_detail": "set PermitRootLogin no",
             "status_before": "fail"},
            {"id": "4.1.1", "title": "Logging rule", "section": "4.1", "status": "pass",
             "detail": "rsyslog installed", "duration_ms": 45, "family": "rsyslog", "risk": "safe"},
            {"id": "6.1.1", "title": "Perm rule", "section": "6.1", "status": "skipped",
             "detail": "excluded", "duration_ms": 0, "family": "perm", "risk": "safe",
             "waived": True, "waiver": {"reason": "legacy app"}},
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ─── Feature 1: evidence snapshot ─────────────────────────────────────

def test_evidence_help():
    for cmd in ("scan", "apply", "audit"):
        result = run([cmd, "--help"])
        assert "--evidence-dir" in result.stdout


def test_collect_evidence(sample_result, tmp_path):
    evidence_dir = tmp_path / "evidence"
    args = SimpleNamespace(evidence_dir=str(evidence_dir), config="")
    data = json.loads(sample_result.read_text(encoding="utf-8"))

    tar_path = notify.collect_evidence(args, data, str(sample_result), "scan")
    assert tar_path is not None
    assert os.path.isfile(tar_path)
    assert "testhost" in os.path.basename(tar_path)
    assert tar_path.endswith("-evidence.tar.gz")

    with tarfile.open(tar_path, "r:gz") as tar:
        names = tar.getnames()
        assert "result.json" in names
        assert "host.json" in names
        assert "rules/rule-1.1.1.txt" in names
        assert "rules/rule-5.2.1.txt" in names
        # No config file was used, so none should be archived
        assert "cis-host.toml" not in names

        rule_txt = tar.extractfile("rules/rule-5.2.1.txt").read().decode("utf-8")
        assert "PermitRootLogin yes" in rule_txt
        assert "apply_status:  applied" in rule_txt
        assert "status_before: fail" in rule_txt

        host = json.loads(tar.extractfile("host.json").read().decode("utf-8"))
        assert host["hostname"] == "testhost"


def test_collect_evidence_includes_config(sample_result, tmp_path):
    cfg = tmp_path / "cis-host.toml"
    cfg.write_text("[profile]\nos = \"rhel9\"\n", encoding="utf-8")
    args = SimpleNamespace(evidence_dir=str(tmp_path / "ev"), config=str(cfg))
    data = json.loads(sample_result.read_text(encoding="utf-8"))

    tar_path = notify.collect_evidence(args, data, str(sample_result), "scan")
    with tarfile.open(tar_path, "r:gz") as tar:
        assert "cis-host.toml" in tar.getnames()


def test_collect_evidence_disabled(sample_result, tmp_path):
    args = SimpleNamespace(evidence_dir="", config="")
    data = json.loads(sample_result.read_text(encoding="utf-8"))
    assert notify.collect_evidence(args, data, str(sample_result), "scan") is None


# ─── Feature 2: webhook notification ─────────────────────────────────

class _WebhookHandler(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _WebhookHandler.received.append(
            (self.headers.get("Content-Type"), json.loads(body.decode("utf-8"))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def webhook_server():
    _WebhookHandler.received = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()
    thread.join()


def _summary_data():
    return {
        "host": {"hostname": "testhost"},
        "summary": {"all": {"score": 66.7, "pass": 2, "fail": 1, "error": 0}},
    }


def test_webhook_help():
    for cmd in ("scan", "audit", "apply", "remediate"):
        result = run([cmd, "--help"])
        assert "--webhook" in result.stdout


def test_send_webhook_payload(webhook_server):
    args = SimpleNamespace(webhook=webhook_server)
    ok = notify.send_webhook(args, "scan", _summary_data(), "/tmp/report.html")
    assert ok is True
    assert len(_WebhookHandler.received) == 1
    content_type, payload = _WebhookHandler.received[0]
    assert content_type == "application/json"
    assert payload["hostname"] == "testhost"
    assert payload["mode"] == "scan"
    assert payload["score"] == 66.7
    assert payload["pass"] == 2
    assert payload["fail"] == 1
    assert payload["error"] == 0
    assert payload["report"] == "/tmp/report.html"
    assert payload["timestamp"]


def test_send_webhook_failure_warns_only():
    args = SimpleNamespace(webhook="http://127.0.0.1:1/unreachable")
    # Must not raise; returns False on delivery failure
    assert notify.send_webhook(args, "scan", _summary_data(), None) is False


def test_send_webhook_disabled():
    args = SimpleNamespace(webhook="")
    assert notify.send_webhook(args, "scan", _summary_data(), None) is False


def test_webhook_from_config(tmp_path):
    cfg = tmp_path / "cis-host.toml"
    cfg.write_text('[notify]\nwebhook_url = "http://example.com/hook"\n', encoding="utf-8")
    args = SimpleNamespace(webhook=None)
    args = cis_host_config.merge(args, str(cfg))
    assert args.webhook == "http://example.com/hook"

    # CLI value wins over config
    args = SimpleNamespace(webhook="http://cli.example.com/hook")
    args = cis_host_config.merge(args, str(cfg))
    assert args.webhook == "http://cli.example.com/hook"


def test_evidence_dir_from_config(tmp_path):
    cfg = tmp_path / "cis-host.toml"
    cfg.write_text('[engine]\nevidence_dir = "./evidence"\n', encoding="utf-8")
    args = SimpleNamespace(evidence_dir=None)
    args = cis_host_config.merge(args, str(cfg))
    assert args.evidence_dir == "./evidence"


# ─── Feature 3: remediate mode ────────────────────────────────────────

def test_remediate_help():
    result = run(["remediate", "--help"])
    assert "--result" in result.stdout
    assert "--os" in result.stdout


def test_remediate_nothing_failing(sample_result, tmp_path, monkeypatch):
    args = SimpleNamespace(result=str(sample_result), include="")
    data = json.loads(sample_result.read_text(encoding="utf-8"))
    # All failing rules have been waived in this sample except 5.2.1 which fails.
    # Construct a result with only passing rules to exercise the no-op path.
    data["results"] = [
        {"id": "1.1.1", "status": "pass"},
        {"id": "4.1.1", "status": "pass"},
    ]
    nofail = tmp_path / "nofail.json"
    nofail.write_text(json.dumps(data), encoding="utf-8")
    args.result = str(nofail)
    out = commands_scan.cmd_remediate(args)
    assert out["path"] is None


def test_remediate_targets_failing_rules(sample_result, tmp_path, monkeypatch):
    data = json.loads(sample_result.read_text(encoding="utf-8"))
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(data), encoding="utf-8")

    captured = {}

    def fake_cmd_apply(args):
        captured["include"] = args.include
        return {"data": data, "path": None}

    monkeypatch.setattr(commands_scan, "cmd_apply", fake_cmd_apply)
    args = SimpleNamespace(result=str(result_path), include="")
    commands_scan.cmd_remediate(args)
    # Only the failing rule 5.2.1 should be targeted for remediation.
    assert captured["include"] == "5.2.1"
