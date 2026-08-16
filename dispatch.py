"""Runtime orchestration: resolve --os preset paths, merge ohbs-host.toml
config, apply hard-coded defaults, validate required paths/template, then
dispatch to the selected command function and apply the strict/gate
exit-code policy. This is the only module that wires together args.py,
defaults.py, ohbs_host_config.py, and the individual command modules.
"""

import os
import sys

import ohbs_host_config
from presets import OS_PRESETS
from defaults import apply_defaults
from args import build_parser
from commands_scan import cmd_scan, cmd_audit, cmd_apply, cmd_check, cmd_remediate
from commands_watch import cmd_diff, cmd_watch
from fleet import cmd_fleet_scan
from info import cmd_info
from notify import send_webhook

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


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


COMMANDS = {
    "list": cmd_list_os,
    "list-os": cmd_list_os,
    "scan": cmd_scan,
    "audit": cmd_audit,
    "apply": cmd_apply,
    "remediate": cmd_remediate,
    "check": cmd_check,
    "diff": cmd_diff,
    "watch": cmd_watch,
    "fleet": cmd_fleet_scan,
    "info": cmd_info,
}


def _resolve_os_preset(args, script_dir):
    """Fill in --engine/--catalog/--guidance/--sections/--template/--name
    from the selected --os preset, without overriding explicit CLI flags.
    """
    if getattr(args, "os", None):
        preset = OS_PRESETS[args.os]
        args.engine = args.engine or os.path.join(script_dir, preset["engine"])
        args.catalog = args.catalog or os.path.join(script_dir, preset["catalog"])
        args.guidance = args.guidance or os.path.join(script_dir, preset["guidance"])
        args.sections = args.sections or os.path.join(script_dir, preset["sections"])
        args.template = args.template or os.path.join(script_dir, preset["template"])
        if not args.name or args.name == "CIS Benchmark":
            args.name = preset["name"]
    return args


def run(script_dir=None):
    """Parse CLI args, resolve config/defaults, dispatch to the selected
    command, and apply the strict/gate exit-code policy. Returns nothing;
    exits the process directly (matching the previous ohbs_cli.py main()).
    """
    script_dir = script_dir or _SCRIPT_DIR
    args = build_parser().parse_args()

    args = _resolve_os_preset(args, script_dir)

    # Merge ohbs-host.toml defaults; CLI args always win
    args = ohbs_host_config.merge(args, args.config if args.config else None)
    args = apply_defaults(args)

    # Validate required paths (not needed for list/list-os/diff; diff only
    # compares two existing result JSONs and needs no engine)
    if args.command not in ("list", "list-os", "diff") and (not args.engine or not args.catalog):
        print("Error: --engine and --catalog are required (or use --os)", file=sys.stderr)
        sys.exit(1)

    # Validate template exists if specified
    if getattr(args, "template", None) and not os.path.exists(args.template):
        print(f"Template not found: {args.template}", file=sys.stderr)
        sys.exit(1)

    try:
        result = COMMANDS[args.command](args)
        if isinstance(result, dict):
            out_path = result.get("path")
            data = result.get("data")
            if out_path:
                print(f"\nDone. Open: {out_path}")
            # Webhook notification: fire-and-warn, never blocks the run.
            if args.command in ("scan", "audit", "apply", "remediate") and data:
                send_webhook(args, args.command, data, out_path)
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
