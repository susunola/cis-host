#!/usr/bin/env python3
"""Append a CIS result summary to a history JSONL file for trend analysis.

Usage:
    python3 scripts/append_history.py <result.json> [history.jsonl]
"""

import json
import os
import sys
from datetime import datetime, timezone


def summarize(data):
    s = data.get("summary", {}).get("all", {})
    return {
        "timestamp": data.get("started_at") or datetime.now(timezone.utc).isoformat(),
        "host": data.get("host", {}).get("hostname", "unknown"),
        "mode": data.get("mode", "scan"),
        "profile": data.get("profile", "L1"),
        "score": data.get("score", 0),
        "total": s.get("total", 0),
        "pass": s.get("pass", 0),
        "fail": s.get("fail", 0),
        "manual": s.get("manual", 0),
        "error": s.get("error", 0),
        "applied": s.get("applied", 0),
        "apply_failed": s.get("apply_failed", 0),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: append_history.py <result.json> [history.jsonl]", file=sys.stderr)
        sys.exit(1)
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else "cis-history.jsonl"
    with open(infile, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    row = summarize(data)
    with open(outfile, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    print(f"Appended history to {outfile}: {row['timestamp']} {row['host']} score={row['score']}%")


if __name__ == "__main__":
    main()
