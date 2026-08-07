#!/usr/bin/env python3
"""Convert a CIS engine result.json to SARIF v2.1.0.

Usage:
    python3 scripts/export_sarif.py <result.json> [output.sarif]
"""

import json
import sys
from datetime import datetime, timezone


def to_sarif(data):
    results = []
    for r in data.get("results", []):
        if r.get("status") == "pass":
            continue
        level = {
            "fail": "error",
            "error": "error",
            "manual": "note",
            "notapplicable": "none",
            "skipped": "warning",
        }.get(r.get("status"), "warning")
        results.append({
            "ruleId": r.get("id"),
            "message": {
                "text": f"{r.get('title', '')}: {r.get('detail', '')}"
            },
            "level": level,
            "properties": {
                "section": r.get("section"),
                "family": r.get("family"),
                "risk": r.get("risk"),
                "assessment": r.get("assessment"),
                "apply_status": r.get("apply_status"),
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cis-bulwark",
                    "version": data.get("engine_version", "1.0.0"),
                    "informationUri": "https://github.com/susunola/cis-bulwark"
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": data.get("summary", {}).get("all", {}).get("error", 0) == 0,
                "startTimeUtc": data.get("started_at") or datetime.now(timezone.utc).isoformat()
            }]
        }]
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: export_sarif.py <result.json> [output.sarif]", file=sys.stderr)
        sys.exit(1)
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else infile.replace(".json", ".sarif")
    with open(infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    sarif = to_sarif(data)
    with open(outfile, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(f"SARIF written to {outfile}: {len(sarif['runs'][0]['results'])} finding(s)")


if __name__ == "__main__":
    main()
