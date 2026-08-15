#!/usr/bin/env python3
"""
CIS Benchmark CLI — scan, apply, audit, fleet scan, with HTML + CLI output.

Installable as the `ciscvm` command after `pip install ciscvm`.

Usage:
  # Scan only (check compliance)
  ciscvm scan --os rhel9 --profile L1 --output output/

  # Apply then re-scan (combined)
  ciscvm apply --os rhel9 --profile L1 --output output/

  # Audit / gate mode (exit non-zero on findings)
  ciscvm audit --os rhel9 --profile L1 --output output/

  # Fleet scan across multiple hosts
  ciscvm fleet scan --os rhel9 --fleet-hosts web1,web2 --output output/

  # Fine-grained: run specific rules by ID
  ciscvm scan --os rhel9 --include "1.1.1.1,1.1.1.2,5.1.1" --output output/

  # Tailor rule inputs and waive exceptions
  ciscvm scan --os rhel9 --variables '{"min_len": 14}' --waivers '{"1.1.1.1": "legacy app"}'

  # Dry-run remediation
  ciscvm apply --os rhel9 --simulate

  # Use a config file (ciscvm.toml)
  ciscvm scan --config ciscvm.toml

  # View rule detail (CLI)
  ciscvm info --os rhel9 --id 1.1.1.1

Supported --os values:
  tencentos3, tencentos4
  rhel8, rhel9, rhel10
  sles15, sles16
  ubuntu2004, ubuntu2204, ubuntu2404
  win2016, win2019, win2022, win2025
"""

import argparse
import os
import sys

import ciscvm_config
from presets import OS_PRESETS
from commands_scan import cmd_scan, cmd_audit, cmd_apply, cmd_check
from commands_watch import cmd_diff, cmd_watch
from fleet import cmd_fleet_scan
from info import cmd_info

# ─── OS Presets ──────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Main commands ────────────────────────────────────────────────────

def has_residual_failures(data, mode):
    """Return True if the result still contains failing checks."""
    s = data.get("summary", {}).get("all", {})
    if mode == "scan":
        return s.get("fail", 0) > 0 or s.get("error", 0) > 0
    return s.get("fail", 0) > 0 or s.get("error", 0) > 0 or s.get("apply_failed", 0) > 0


def cmd_list_os(args):
    """List supported OS presets."""
    print("\nSupported OS presets:\n")
    print(f"{'OS':<14} {'Engine':<10} {'Benchmark'}")
    print("-" * 70)
    for os_id, preset in sorted(OS_PRESETS.items()):
        engine_ext = os.path.splitext(preset["engine"])[1]
        engine_type = "powershell" if engine_ext == ".ps1" else "python"
        print(f"{os_id:<14} {engine_type:<10} {preset['name']}")
    print()
    return 0



# ─── Defaults & helpers ───────────────────────────────────────────────

def _apply_defaults(args):
    """Apply hard-coded defaults for args that were not set via CLI or config."""
    defaults = {
        "profile": "L1",
        "platform": "server",
        "name": "CIS Benchmark",
        "version": "v1.0.0",
        "org": "",
        "include": "",
        "exclude": "",
        "sections_filter": "",
        "families": "",
        "output": "./output",
        "format": "both",
        "copy_json": False,
        "strict": False,
        "timeout": 600,
        "allow_disruptive": False,
        "backup_dir": "",
        "audit_log": "",
        "variables": None,
        "waivers": None,
        "simulate": False,
        "fleet": {},
        "fleet_hosts": "",
        "fleet_remote": False,
    }
    for key, value in defaults.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)
    return args


# ─── CLI definition ───────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CIS Benchmark local CLI — scan, apply, audit, fleet scan, view rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pure scan
  python3 cis_cli.py scan --os rhel9 --profile L1 --output ./out/

  # Apply + auto re-scan (combined)
  python3 cis_cli.py apply --os ubuntu2204 --profile L2 --allow-disruptive --output ./out/

  # Audit / gate mode (exit non-zero on findings)
  python3 cis_cli.py audit --os rhel9 --profile L1 --output ./out/

  # Fleet scan across hosts
  python3 cis_cli.py fleet scan --os rhel9 --fleet-hosts web1,web2 --output ./out/

  # Fine-grained: only specific rules
  python3 cis_cli.py scan --os rhel8 --include "1.1.1.1,1.1.1.2,5.1.1" --output ./out/

  # Tailor rule inputs and waive exceptions
  python3 cis_cli.py scan --os rhel9 --variables '{"min_len": 14}' --waivers '{"1.1.1.1": "legacy app"}'

  # Dry-run remediation
  python3 cis_cli.py apply --os rhel9 --simulate

  # CLI-only output (no HTML)
  python3 cis_cli.py scan --os rhel9 --format cli

  # View rule detail
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1

  # View rule detail as HTML page
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1 --format html --output ./out/
        """
    )

    ap.add_argument("--config", default="",
                    help="Path to ciscvm.toml config file (default: ./ciscvm.toml or $CISCVM_CONFIG)")

    sub = ap.add_subparsers(dest="command", help="Mode: list | scan | apply | audit | check | fleet | info")
    sub.required = True

    # ── list (alias list-os for backward compatibility) ──
    p_list = sub.add_parser("list", aliases=["list-os"], help="List supported OS presets")

    # ── Common args shared by most commands ──
    def add_common_args(p):
        p.add_argument("--os", default="",
                       choices=sorted(OS_PRESETS.keys()),
                       help="OS preset (auto-fills paths): %s" % ", ".join(sorted(OS_PRESETS.keys())))
        p.add_argument("--engine",
                       help="Path to cis_engine.py (Linux) or cis_engine.ps1 (Windows). Required if --os not used.")
        p.add_argument("--catalog",
                       help="Path to rules.json. Required if --os not used.")
        p.add_argument("--guidance", default="",
                       help="Path to guidance.json (for report rendering)")
        p.add_argument("--sections", default="",
                       help="Path to sections.json (for report rendering)")
        p.add_argument("--template", default="",
                       help="Path to report.html.j2 template")
        # Defaults are intentionally None here so that ciscvm.toml can supply
        # values; hard-coded fallbacks are applied after config merging.
        p.add_argument("--profile", default=None, choices=["L1", "L2"],
                       help="Benchmark profile level (default: L1)")
        p.add_argument("--platform", default=None,
                       choices=["server", "workstation", "all"],
                       help="Target platform (default: server)")
        p.add_argument("--name", default=None,
                       help="Benchmark display name")
        p.add_argument("--version", default=None,
                       help="Benchmark version for report footer")
        p.add_argument("--org", default=None,
                       help="Organization name for report header")
        p.add_argument("--include", default=None,
                       help="Comma-separated rule IDs to include (e.g. 1.1.1,1.1.2)")
        p.add_argument("--exclude", default=None,
                       help="Comma-separated rule IDs to exclude")
        p.add_argument("--sections-filter", default=None,
                       help="Comma-separated section prefixes to filter (e.g. 1.1,5)")
        p.add_argument("--families", default=None,
                       help="Comma-separated rule families to filter")
        p.add_argument("--output", default=None,
                       help="Output directory for reports (default: ./output)")
        p.add_argument("--format", default=None, choices=["html", "cli", "both"],
                       help="Output format: html, cli, or both (default: both)")
        p.add_argument("--copy-json", default=None, action="store_true",
                       help="Also save result JSON alongside the HTML report")
        p.add_argument("--audit-log", default=None,
                       help="Write audit log (JSON-lines) to this path")
        p.add_argument("--timeout", type=int, default=None,
                       help="Engine execution timeout in seconds (default: 600)")
        p.add_argument("--no-prescan", action="store_true",
                       help="Skip pre-scan baseline in apply mode")
        p.add_argument("--strict", default=None, action="store_true",
                       help="Exit non-zero when residual failures remain")

    # ── Tailoring args ──
    def add_tailoring_args(p):
        p.add_argument("--variables", default=None,
                       help="JSON file or inline JSON with rule variable overrides")
        p.add_argument("--waivers", default=None,
                       help="JSON file or inline JSON mapping rule IDs to waiver reasons/objects")

    # ── Apply-specific args ──
    def add_apply_args(p):
        p.add_argument("--allow-disruptive", default=None, action="store_true",
                       help="Allow potentially disruptive rules to be applied")
        p.add_argument("--backup-dir", default="",
                       help="Directory to store backup files before changes")
        p.add_argument("--simulate", default=None, action="store_true",
                       help="Dry-run apply mode: report what would be remediated without changing the system")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Check compliance only, generate HTML report")
    add_common_args(p_scan)
    add_tailoring_args(p_scan)

    # ── audit ──
    p_audit = sub.add_parser("audit", help="Scan-only compliance gate (exit non-zero on findings)")
    add_common_args(p_audit)
    add_tailoring_args(p_audit)

    # ── apply ──
    p_apply = sub.add_parser("apply", help="Apply fixes, re-scan, generate report")
    add_common_args(p_apply)
    add_apply_args(p_apply)
    add_tailoring_args(p_apply)

    # ── check ──
    p_check = sub.add_parser("check", help="Dry-run: scan + show what would change")
    add_common_args(p_check)
    add_apply_args(p_check)
    add_tailoring_args(p_check)

    # ── fleet ──
    p_fleet = sub.add_parser("fleet", help="Fleet scan across multiple hosts")
    fleet_sub = p_fleet.add_subparsers(dest="fleet_command", help="Fleet subcommand")
    fleet_sub.required = True
    p_fleet_scan = fleet_sub.add_parser("scan", help="Scan multiple hosts and aggregate report")
    add_common_args(p_fleet_scan)
    add_tailoring_args(p_fleet_scan)
    p_fleet_scan.add_argument("--fleet-hosts", default=None,
                              help="Comma-separated fleet host list (or use [fleet] hosts in ciscvm.toml)")
    p_fleet_scan.add_argument("--fleet-remote", default=None, action="store_true",
                              help="Run engine over SSH on each host (requires [fleet] remote config)")

    # ── diff (drift detection) ──
    p_diff = sub.add_parser("diff", help="Compare two scan result JSONs and report configuration drift")
    p_diff.add_argument("before", metavar="BEFORE_JSON",
                        help="Baseline scan result JSON (e.g. from --copy-json or audit)")
    p_diff.add_argument("after", metavar="AFTER_JSON",
                        help="Latest scan result JSON")
    p_diff.add_argument("--name", default="CIS Benchmark",
                        help="Benchmark display name for the report")
    p_diff.add_argument("--profile", default="L1", help="Profile label for the report")
    p_diff.add_argument("--org", default="", help="Organization name for the report")
    p_diff.add_argument("--output", default="./output",
                        help="Output directory for the drift report (default: ./output)")
    p_diff.add_argument("--format", default="both", choices=["html", "cli", "both"],
                        help="Output format: html, cli, or both (default: both)")
    p_diff.add_argument("--exit-code", action="store_true",
                        help="Exit non-zero (2) when drift or failing rules remain — CI gate")

    # ── watch (periodic scan with drift alerting) ──
    p_watch = sub.add_parser("watch", help="Periodic scan; reports only when configuration drifts")
    add_common_args(p_watch)
    add_tailoring_args(p_watch)
    p_watch.add_argument("--interval", type=int, default=3600,
                         help="Seconds between scans (min 30, default 3600)")
    p_watch.add_argument("--max-runs", type=int, default=0,
                         help="Stop after N runs (0 = run forever, default 0)")
    p_watch.add_argument("--baseline", default="",
                         help="Baseline result JSON to diff against; first scan if omitted")
    p_watch.add_argument("--alert-cmd", default="",
                         help="Shell command executed when drift is detected")
    p_watch.add_argument("--json", action="store_true",
                         help="Emit one JSON event per line (SIEM/automation friendly)")

    # ── info ──
    p_info = sub.add_parser("info", help="Show rule detail by ID (CLI or HTML)")
    p_info.add_argument("--os", default="",
                        choices=sorted(OS_PRESETS.keys()),
                        help="OS preset (auto-fills paths)")
    p_info.add_argument("--engine", help="Path to cis_engine.py (Linux) or cis_engine.ps1 (Windows).")
    p_info.add_argument("--catalog", help="Path to rules.json.")
    p_info.add_argument("--guidance", default="",
                        help="Path to guidance.json (for description/remediation)")
    p_info.add_argument("--sections", default="",
                        help="Path to sections.json (for chapter names)")
    p_info.add_argument("--template", default="",
                        help="Path to report.html.j2 template (for HTML mode)")
    p_info.add_argument("--name", default="CIS Benchmark",
                        help="Benchmark display name")
    p_info.add_argument("--id", required=True, metavar="RULE_ID",
                        help="Rule ID to view (e.g. 1.1.1.1)")
    p_info.add_argument("--format", default="cli", choices=["html", "cli"],
                        help="Output format: cli (default) or html")
    p_info.add_argument("--output", default="./output",
                        help="Output directory for HTML (default: ./output)")

    args = ap.parse_args()

    # ── Resolve --os preset ──
    if getattr(args, "os", None):
        preset = OS_PRESETS[args.os]
        args.engine = args.engine or os.path.join(_SCRIPT_DIR, preset["engine"])
        args.catalog = args.catalog or os.path.join(_SCRIPT_DIR, preset["catalog"])
        args.guidance = args.guidance or os.path.join(_SCRIPT_DIR, preset["guidance"])
        args.sections = args.sections or os.path.join(_SCRIPT_DIR, preset["sections"])
        args.template = args.template or os.path.join(_SCRIPT_DIR, preset["template"])
        if not args.name or args.name == "CIS Benchmark":
            args.name = preset["name"]

    # Merge ciscvm.toml defaults; CLI args always win
    args = ciscvm_config.merge(args, args.config if args.config else None)
    args = _apply_defaults(args)

    # Validate required paths (not needed for list/list-os/diff; diff only
    # compares two existing result JSONs and needs no engine)
    if args.command not in ("list", "list-os", "diff") and (not args.engine or not args.catalog):
        print("Error: --engine and --catalog are required (or use --os)", file=sys.stderr)
        sys.exit(1)

    # Validate template exists if specified
    if getattr(args, "template", None) and not os.path.exists(args.template):
        print(f"Template not found: {args.template}", file=sys.stderr)
        sys.exit(1)

    # Dispatch
    commands = {
        "list": cmd_list_os,
        "list-os": cmd_list_os,
        "scan": cmd_scan,
        "audit": cmd_audit,
        "apply": cmd_apply,
        "check": cmd_check,
        "diff": cmd_diff,
        "watch": cmd_watch,
        "fleet": cmd_fleet_scan,
        "info": cmd_info,
    }

    try:
        result = commands[args.command](args)
        if isinstance(result, dict):
            out_path = result.get("path")
            data = result.get("data")
            if out_path:
                print(f"\nDone. Open: {out_path}")
            # Audit mode is always strict by default: fail the gate if findings remain.
            strict = getattr(args, "strict", False) or args.command == "audit"
            if strict and args.command in ("scan", "apply", "check", "audit"):
                mode = "apply" if args.command == "apply" else "scan"
                if data and has_residual_failures(data, mode):
                    sys.exit(2)
            # Fleet scan can also be strict
            if strict and args.command == "fleet" and data:
                s = data.get("summary", {}).get("all", {})
                if s.get("fail", 0) > 0 or s.get("error", 0) > 0:
                    sys.exit(2)
        elif isinstance(result, str) and result:
            print(f"\nDone. Open: {result}")
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
