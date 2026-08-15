#!/usr/bin/env python3
"""Tests for scripts/export_xccdf.py and scripts/export_junit.py."""

import json
import os
import subprocess
import sys
from xml.etree import ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XCCDF_SCRIPT = os.path.join(ROOT, "scripts", "export_xccdf.py")
JUNIT_SCRIPT = os.path.join(ROOT, "scripts", "export_junit.py")
PLOT_SCRIPT = os.path.join(ROOT, "scripts", "plot_history.py")
TAILOR_EXPORT = os.path.join(ROOT, "scripts", "export_tailoring.py")
TAILOR_IMPORT = os.path.join(ROOT, "scripts", "import_tailoring.py")
PDF_SCRIPT = os.path.join(ROOT, "scripts", "export_pdf.py")

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"


def _run(script, args, check=True):
    cmd = [sys.executable, script] + args
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
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
                "total": 5,
                "pass": 1,
                "fail": 1,
                "error": 1,
                "skipped": 1,
                "waived": 1,
                "score": 50.0,
            }
        },
        "results": [
            {
                "id": "1.1.1",
                "title": "Pass rule",
                "section": "1.1",
                "status": "pass",
                "detail": "ok",
                "duration_ms": 10,
            },
            {
                "id": "1.1.2",
                "title": "Fail rule",
                "section": "1.1",
                "status": "fail",
                "detail": "missing file",
                "duration_ms": 20,
            },
            {
                "id": "1.1.3",
                "title": "Error rule",
                "section": "1.1",
                "status": "error",
                "detail": "crashed",
                "duration_ms": 30,
            },
            {
                "id": "1.1.4",
                "title": "Skipped rule",
                "section": "1.1",
                "status": "skipped",
                "detail": "excluded",
                "duration_ms": 0,
            },
            {
                "id": "1.1.5",
                "title": "Waived rule",
                "section": "1.1",
                "status": "waived",
                "detail": "waived: ticket-123",
                "duration_ms": 0,
            },
        ],
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_export_xccdf(sample_result, tmp_path):
    output = tmp_path / "result.xml"
    _run(XCCDF_SCRIPT, [str(sample_result), str(output)])

    tree = ET.parse(str(output))
    root = tree.getroot()
    assert root.tag == "{%s}Benchmark" % XCCDF_NS
    assert root.attrib.get("id", "").startswith("xccdf_cis-host_benchmark_")

    test_result = root.find("{%s}TestResult" % XCCDF_NS)
    assert test_result is not None

    score = test_result.find("{%s}score" % XCCDF_NS)
    assert score is not None
    assert float(score.text) == 50.0

    target = test_result.find("{%s}target" % XCCDF_NS)
    assert target is not None
    assert target.text == "testhost"

    identity = test_result.find("{%s}identity" % XCCDF_NS)
    assert identity is not None
    assert identity.text

    rule_results = test_result.findall("{%s}rule-result" % XCCDF_NS)
    assert len(rule_results) == 5

    mapping = {
        "1.1.1": "pass",
        "1.1.2": "fail",
        "1.1.3": "error",
        "1.1.4": "notchecked",
        "1.1.5": "notchecked",
    }
    for rr in rule_results:
        idref = rr.attrib["idref"]
        result = rr.find("{%s}result" % XCCDF_NS)
        assert result is not None
        assert result.text == mapping[idref]
        title = rr.find("{%s}title" % XCCDF_NS)
        assert title is not None
        assert title.text
        ident = rr.find("{%s}ident" % XCCDF_NS)
        assert ident is not None
        assert ident.text == idref


def test_export_junit(sample_result, tmp_path):
    output = tmp_path / "result.junit.xml"
    _run(JUNIT_SCRIPT, [str(sample_result), str(output)])

    tree = ET.parse(str(output))
    suite = tree.getroot()
    assert suite.tag == "testsuite"
    assert suite.attrib["hostname"] == "testhost"
    assert suite.attrib["tests"] == "5"
    assert suite.attrib["failures"] == "1"
    assert suite.attrib["errors"] == "1"
    assert suite.attrib["skipped"] == "2"

    cases = suite.findall("testcase")
    assert len(cases) == 5

    status_by_id = {}
    for case in cases:
        case_id = case.attrib["name"].split(":", 1)[0]
        detail = {}
        for child in case:
            detail[child.tag] = child
        status_by_id[case_id] = detail

    assert "failure" in status_by_id["1.1.2"]
    assert status_by_id["1.1.2"]["failure"].text == "missing file"
    assert "error" in status_by_id["1.1.3"]
    assert status_by_id["1.1.3"]["error"].text == "crashed"
    assert "skipped" in status_by_id["1.1.4"]
    assert "skipped" in status_by_id["1.1.5"]
    assert "failure" not in status_by_id["1.1.1"]
    assert "error" not in status_by_id["1.1.1"]
    assert "skipped" not in status_by_id["1.1.1"]


def test_plot_history(tmp_path):
    history = tmp_path / "history.jsonl"
    rows = [
        {"timestamp": "2024-01-01T00:00:00Z", "host": "h1", "mode": "scan", "profile": "L1", "score": 80.0, "pass": 8, "fail": 2, "error": 0},
        {"timestamp": "2024-01-02T00:00:00Z", "host": "h1", "mode": "scan", "profile": "L1", "score": 85.0, "pass": 9, "fail": 1, "error": 0},
        {"timestamp": "2024-01-03T00:00:00Z", "host": "h1", "mode": "scan", "profile": "L1", "score": 83.0, "pass": 8, "fail": 2, "error": 0},
    ]
    history.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    output = tmp_path / "history.html"
    _run(PLOT_SCRIPT, [str(history), str(output)])
    assert output.exists()
    text = output.read_text(encoding="utf-8")
    assert "Compliance Score" in text
    assert "Failed Rules" in text
    assert "<svg" in text


def test_tailoring_round_trip(tmp_path):
    toml = tmp_path / "cis-host.toml"
    toml.write_text("""
[profile]
os = "rhel9"
profile = "L1"
name = "CIS RHEL 9"

[rules]
include = ["1.1.1", "1.1.2"]
exclude = "5.1.1"

[variables]
min_len = 14

[waivers]
"1.1.1" = "legacy app"
""", encoding="utf-8")

    xml_out = tmp_path / "tailoring.xml"
    _run(TAILOR_EXPORT, [str(toml), str(xml_out)])
    assert xml_out.exists()
    xml_text = xml_out.read_text(encoding="utf-8")
    assert "xccdf_cis-host_rule_1.1.1" in xml_text
    assert "xccdf_cis-host_rule_5.1.1" in xml_text
    assert "xccdf_cis-host_value_min_len" in xml_text

    toml_out = tmp_path / "imported.toml"
    _run(TAILOR_IMPORT, [str(xml_out), str(toml_out)])
    assert toml_out.exists()
    toml_text = toml_out.read_text(encoding="utf-8")
    assert "min_len = 14" in toml_text
    assert '"1.1.1" = "legacy app"' in toml_text
    assert "5.1.1" in toml_text


def test_export_pdf_missing_weasyprint(tmp_path):
    import importlib.util

    html = tmp_path / "report.html"
    html.write_text("<html><body>test</body></html>", encoding="utf-8")
    pdf = tmp_path / "report.pdf"
    result = _run(PDF_SCRIPT, [str(html), str(pdf)], check=False)
    if importlib.util.find_spec("weasyprint") is not None:
        # WeasyPrint available: PDF must be produced successfully
        assert result.returncode == 0, result.stderr
        assert pdf.exists()
    else:
        # Should fail gracefully because weasyprint is not installed
        assert result.returncode != 0 or not pdf.exists() or "WeasyPrint" in result.stderr
