"""argparse declaration: builds the top-level ArgumentParser and all
subcommand parsers (scan/audit/apply/check/fleet/diff/watch/info/list).
Pure declaration only — no runtime resolution or dispatch logic lives here.
"""

import argparse

from presets import OS_PRESETS


def _add_common_args(p):
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
    # Defaults are intentionally None here so that cis-host.toml can supply
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
    p.add_argument("--evidence-dir", default=None,
                   help="Pack evidence (result JSON, config, host facts, per-rule detail) "
                        "into <hostname>-<timestamp>-evidence.tar.gz under this directory")
    p.add_argument("--webhook", default=None,
                   help="POST a JSON run summary to this URL after the run "
                        "(overrides [notify] webhook_url in cis-host.toml)")
    p.add_argument("--timeout", type=int, default=None,
                   help="Engine execution timeout in seconds (default: 600)")
    p.add_argument("--no-prescan", action="store_true",
                   help="Skip pre-scan baseline in apply mode")
    p.add_argument("--strict", default=None, action="store_true",
                   help="Exit non-zero when residual failures remain")


def _add_tailoring_args(p):
    p.add_argument("--variables", default=None,
                   help="JSON file or inline JSON with rule variable overrides")
    p.add_argument("--waivers", default=None,
                   help="JSON file or inline JSON mapping rule IDs to waiver reasons/objects")


def _add_apply_args(p):
    p.add_argument("--allow-disruptive", default=None, action="store_true",
                   help="Allow potentially disruptive rules to be applied")
    p.add_argument("--backup-dir", default="",
                   help="Directory to store backup files before changes")
    p.add_argument("--simulate", default=None, action="store_true",
                   help="Dry-run apply mode: report what would be remediated without changing the system")


def build_parser():
    """Build and return the top-level ArgumentParser for the CLI."""
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
                    help="Path to cis-host.toml config file (default: ./cis-host.toml or $CIS_HOST_CONFIG)")

    sub = ap.add_subparsers(dest="command", help="Mode: list | scan | apply | audit | check | fleet | info")
    sub.required = True

    # ── list (alias list-os for backward compatibility) ──
    sub.add_parser("list", aliases=["list-os"], help="List supported OS presets")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Check compliance only, generate HTML report")
    _add_common_args(p_scan)
    _add_tailoring_args(p_scan)

    # ── audit ──
    p_audit = sub.add_parser("audit", help="Scan-only compliance gate (exit non-zero on findings)")
    _add_common_args(p_audit)
    _add_tailoring_args(p_audit)
    p_audit.add_argument("--fail-on-expired-waiver", default=None, action="store_true",
                         help="Treat expired waivers as gate failures")

    # ── apply ──
    p_apply = sub.add_parser("apply", help="Apply fixes, re-scan, generate report")
    _add_common_args(p_apply)
    _add_apply_args(p_apply)
    _add_tailoring_args(p_apply)

    # ── remediate ──
    p_remediate = sub.add_parser("remediate", help="Apply fixes only for rules that failed in a previous scan")
    _add_common_args(p_remediate)
    _add_apply_args(p_remediate)
    _add_tailoring_args(p_remediate)
    p_remediate.add_argument("--result", required=True, help="Path to a previous scan result JSON")

    # ── check ──
    p_check = sub.add_parser("check", help="Dry-run: scan + show what would change")
    _add_common_args(p_check)
    _add_apply_args(p_check)
    _add_tailoring_args(p_check)

    # ── fleet ──
    p_fleet = sub.add_parser("fleet", help="Fleet scan across multiple hosts")
    fleet_sub = p_fleet.add_subparsers(dest="fleet_command", help="Fleet subcommand")
    fleet_sub.required = True
    p_fleet_scan = fleet_sub.add_parser("scan", help="Scan multiple hosts and aggregate report")
    _add_common_args(p_fleet_scan)
    _add_tailoring_args(p_fleet_scan)
    p_fleet_scan.add_argument("--fleet-hosts", default=None,
                              help="Comma-separated fleet host list (or use [fleet] hosts in cis-host.toml)")
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
    _add_common_args(p_watch)
    _add_tailoring_args(p_watch)
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

    return ap
