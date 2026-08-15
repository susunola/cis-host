"""diff/watch command implementations: pure logic lives in ciscvm_diff.py
(unit-testable, dataclass-typed); this module only wires CLI arguments to
it — comparing two scan results for drift, or running a periodic
change-only, de-duplicated watch session.
"""

import json
import os
import subprocess
import sys
from datetime import datetime

import ciscvm_diff
from display import click_style
from engine import run_engine


def load_result_json(path):
    """Load an engine result JSON and fail with a clear message on error."""
    if not os.path.isfile(path):
        print(f"Result file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Cannot read result JSON {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def cmd_diff(args):
    """DIFF mode: compare two scan results and report configuration drift."""
    before = load_result_json(args.before)
    after = load_result_json(args.after)
    report = ciscvm_diff.diff_results(before, after)

    if args.format in ("cli", "both"):
        print(ciscvm_diff.render_cli(report))

    out_path = None
    if args.format in ("html", "both"):
        out_path = os.path.join(
            os.path.abspath(args.output),
            f"drift-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(ciscvm_diff.render_html(report, name=args.name,
                                             profile=args.profile, org=args.org))
        print(f"Drift report saved: {out_path}")

    if report.has_drift():
        hint = " — use --exit-code to fail CI" if not args.exit_code else ""
        print(f"\nGate: {click_style('FAIL', 'red')}  "
              f"({report.drift_count()} drift/failing rules{hint})")
        if args.exit_code:
            sys.exit(2)
    else:
        print(f"\nGate: {click_style('PASS', 'green')}  (no drift)")
    return {"path": out_path}


def _scan_alert_cmd(cmd):
    """Wrap a shell command as a WatchSession alert callback."""
    def _fire(event):
        print(f"  Running alert: {cmd}")
        try:
            subprocess.run(cmd, shell=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"  Alert command failed: {exc}", file=sys.stderr)
    return _fire


def cmd_watch(args):
    """WATCH mode: periodic scan with change-only, de-duplicated alerting."""
    interval = max(int(getattr(args, "interval", 3600)), 30)
    baseline = None
    if getattr(args, "baseline", "") and os.path.isfile(args.baseline):
        baseline = load_result_json(args.baseline)
        print(f"Baseline loaded: {args.baseline}")

    alert = _scan_alert_cmd(args.alert_cmd) if getattr(args, "alert_cmd", "") else None

    print(f"\n╔══ CIS Benchmark — WATCH ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Interval:{interval}s  Runs: "
          f"{'∞' if getattr(args, 'max_runs', 0) <= 0 else args.max_runs}")
    if alert:
        print(f"║ Alert:   {args.alert_cmd}")
    print(f"╚{'═'*26}╝\n")

    session = ciscvm_diff.WatchSession(
        scan=lambda: run_engine(args, "scan")[0],
        interval=interval,
        max_runs=getattr(args, "max_runs", 0),
        baseline=baseline,
        alert=alert,
        json_events=bool(getattr(args, "json", False)),
        output_dir=os.path.abspath(args.output),
        name=args.name,
        profile=args.profile,
        org=getattr(args, "org", "") or "",
    )
    session.run()
    return None
