#!/usr/bin/env python3
"""Convert a CIS engine result.json to JUnit XML for CI systems.

Usage:
    python3 scripts/export_junit.py <result.json> [output.xml]
"""

import json
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree as ET


def _parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return datetime.now(timezone.utc)


def _duration(rule):
    return float(rule.get("duration_ms", 0)) / 1000.0


def to_junit(data):
    host = data.get("host", {})
    hostname = host.get("hostname") or "localhost"
    started = data.get("started_at") or datetime.now(timezone.utc).isoformat()
    started_dt = _parse_timestamp(started)

    results = data.get("results", [])
    failures = 0
    errors = 0
    skipped = 0
    total_time = 0.0

    suite = ET.Element(
        "testsuite",
        name="CIS Benchmark",
        hostname=hostname,
        timestamp=started_dt.isoformat(),
        tests=str(len(results)),
    )

    for rule in results:
        status = rule.get("status", "error")
        time_sec = _duration(rule)
        total_time += time_sec

        classname = rule.get("section") or "CIS"
        name = f"{rule['id']}: {rule.get('title', '')}"
        case = ET.SubElement(
            suite, "testcase", classname=classname, name=name, time=str(time_sec)
        )

        detail = rule.get("detail", "")
        if status == "fail":
            failures += 1
            msg = f"{rule['id']} failed"
            ET.SubElement(case, "failure", message=msg, type="CIS-rule-failure").text = detail
        elif status == "error":
            errors += 1
            msg = f"{rule['id']} errored"
            ET.SubElement(case, "error", message=msg, type="CIS-rule-error").text = detail
        elif status in ("skipped", "waived"):
            skipped += 1
            note = detail if detail else f"status={status}"
            ET.SubElement(case, "skipped", message=note)

    suite.set("failures", str(failures))
    suite.set("errors", str(errors))
    suite.set("skipped", str(skipped))
    suite.set("time", str(round(total_time, 3)))

    return ET.ElementTree(suite)


def main():
    if len(sys.argv) < 2:
        print("Usage: export_junit.py <result.json> [output.xml]", file=sys.stderr)
        sys.exit(1)
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else infile.replace(".json", ".junit.xml")
    with open(infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    tree = to_junit(data)
    with open(outfile, "wb") as fh:
        tree.write(fh, encoding="utf-8", xml_declaration=True)
    print(f"JUnit written to {outfile}: {len(data.get('results', []))} testcase(s)")


if __name__ == "__main__":
    main()
