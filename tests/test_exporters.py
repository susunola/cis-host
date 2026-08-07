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
    assert root.attrib.get("id", "").startswith("xccdf_cis-bulwark_benchmark_")

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
