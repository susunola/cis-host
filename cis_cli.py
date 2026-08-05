#!/usr/bin/env python3
"""
CIS Benchmark CLI — local scan & apply with HTML report generation.

Usage:
  # Scan with --os auto-detection (recommended)
  python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

  # Apply fixes with --os
  python3 cis_cli.py apply --os ubuntu2204 --profile L1 --allow-disruptive --output output/

  # Or specify paths manually
  python3 cis_cli.py scan \\
      --engine cis-tencentos3-ansible/roles/cis_tencentos3/files/cis_engine.py \\
      --catalog cis-tencentos3-ansible/roles/cis_tencentos3/files/rules.json \\
      --guidance cis-tencentos3-ansible/roles/cis_tencentos3/files/guidance.json \\
      --sections cis-tencentos3-ansible/roles/cis_tencentos3/files/sections.json \\
      --template cis-tencentos3-ansible/roles/cis_tencentos3/templates/report.html.j2 \\
      --profile L1 --name "TencentOS Server 3.2" --output output/

Supported --os values:
  tos3, tos4, windows
  rhel8, rhel9, rhel10
  sles15, sles16
  ubuntu2004, ubuntu2204, ubuntu2404
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

# ─── OS Presets ──────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OS_PRESETS = {
    "tos3": {
        "engine": "cis-tencentos3-ansible/roles/cis_tencentos3/files/cis_engine.py",
        "catalog": "cis-tencentos3-ansible/roles/cis_tencentos3/files/rules.json",
        "guidance": "cis-tencentos3-ansible/roles/cis_tencentos3/files/guidance.json",
        "sections": "cis-tencentos3-ansible/roles/cis_tencentos3/files/sections.json",
        "template": "cis-tencentos3-ansible/roles/cis_tencentos3/templates/report.html.j2",
        "name": "CIS TencentOS Server 3 Benchmark",
    },
    "tos4": {
        "engine": "cis-tencentos4-ansible/roles/cis_tencentos4/files/cis_engine.py",
        "catalog": "cis-tencentos4-ansible/roles/cis_tencentos4/files/rules.json",
        "guidance": "cis-tencentos4-ansible/roles/cis_tencentos4/files/guidance.json",
        "sections": "cis-tencentos4-ansible/roles/cis_tencentos4/files/sections.json",
        "template": "cis-tencentos4-ansible/roles/cis_tencentos4/templates/report.html.j2",
        "name": "CIS TencentOS Server 4 Benchmark",
    },
    "windows": {
        "engine": "cis-windows-ansible/roles/cis_windows/files/cis_engine.ps1",
        "catalog": "cis-windows-ansible/roles/cis_windows/files/rules.json",
        "guidance": "cis-windows-ansible/roles/cis_windows/files/guidance.json",
        "sections": "cis-windows-ansible/roles/cis_windows/files/sections.json",
        "template": "cis-windows-ansible/roles/cis_windows/templates/report.html.j2",
        "name": "CIS Microsoft Windows Server 2025 Benchmark",
    },
    "rhel8": {
        "engine": "cis-rhel8-ansible/roles/cis_rhel8/files/cis_engine.py",
        "catalog": "cis-rhel8-ansible/roles/cis_rhel8/files/rules.json",
        "guidance": "cis-rhel8-ansible/roles/cis_rhel8/files/guidance.json",
        "sections": "cis-rhel8-ansible/roles/cis_rhel8/files/sections.json",
        "template": "cis-rhel8-ansible/roles/cis_rhel8/templates/report.html.j2",
        "name": "CIS Red Hat Enterprise Linux 8 Benchmark",
    },
    "rhel9": {
        "engine": "cis-rhel9-ansible/roles/cis_rhel9/files/cis_engine.py",
        "catalog": "cis-rhel9-ansible/roles/cis_rhel9/files/rules.json",
        "guidance": "cis-rhel9-ansible/roles/cis_rhel9/files/guidance.json",
        "sections": "cis-rhel9-ansible/roles/cis_rhel9/files/sections.json",
        "template": "cis-rhel9-ansible/roles/cis_rhel9/templates/report.html.j2",
        "name": "CIS Red Hat Enterprise Linux 9 Benchmark",
    },
    "rhel10": {
        "engine": "cis-rhel10-ansible/roles/cis_rhel10/files/cis_engine.py",
        "catalog": "cis-rhel10-ansible/roles/cis_rhel10/files/rules.json",
        "guidance": "cis-rhel10-ansible/roles/cis_rhel10/files/guidance.json",
        "sections": "cis-rhel10-ansible/roles/cis_rhel10/files/sections.json",
        "template": "cis-rhel10-ansible/roles/cis_rhel10/templates/report.html.j2",
        "name": "CIS Red Hat Enterprise Linux 10 Benchmark",
    },
    "sles15": {
        "engine": "cis-sles15-ansible/roles/cis_sles15/files/cis_engine.py",
        "catalog": "cis-sles15-ansible/roles/cis_sles15/files/rules.json",
        "guidance": "cis-sles15-ansible/roles/cis_sles15/files/guidance.json",
        "sections": "cis-sles15-ansible/roles/cis_sles15/files/sections.json",
        "template": "cis-sles15-ansible/roles/cis_sles15/templates/report.html.j2",
        "name": "CIS SUSE Linux Enterprise 15 Benchmark",
    },
    "sles16": {
        "engine": "cis-sles16-ansible/roles/cis_sles16/files/cis_engine.py",
        "catalog": "cis-sles16-ansible/roles/cis_sles16/files/rules.json",
        "guidance": "cis-sles16-ansible/roles/cis_sles16/files/guidance.json",
        "sections": "cis-sles16-ansible/roles/cis_sles16/files/sections.json",
        "template": "cis-sles16-ansible/roles/cis_sles16/templates/report.html.j2",
        "name": "CIS SUSE Linux Enterprise 16 Benchmark",
    },
    "ubuntu2004": {
        "engine": "cis-ubuntu2004-ansible/roles/cis_ubuntu2004/files/cis_engine.py",
        "catalog": "cis-ubuntu2004-ansible/roles/cis_ubuntu2004/files/rules.json",
        "guidance": "cis-ubuntu2004-ansible/roles/cis_ubuntu2004/files/guidance.json",
        "sections": "cis-ubuntu2004-ansible/roles/cis_ubuntu2004/files/sections.json",
        "template": "cis-ubuntu2004-ansible/roles/cis_ubuntu2004/templates/report.html.j2",
        "name": "CIS Ubuntu Linux 20.04 LTS Benchmark",
    },
    "ubuntu2204": {
        "engine": "cis-ubuntu2204-ansible/roles/cis_ubuntu2204/files/cis_engine.py",
        "catalog": "cis-ubuntu2204-ansible/roles/cis_ubuntu2204/files/rules.json",
        "guidance": "cis-ubuntu2204-ansible/roles/cis_ubuntu2204/files/guidance.json",
        "sections": "cis-ubuntu2204-ansible/roles/cis_ubuntu2204/files/sections.json",
        "template": "cis-ubuntu2204-ansible/roles/cis_ubuntu2204/templates/report.html.j2",
        "name": "CIS Ubuntu Linux 22.04 LTS Benchmark",
    },
    "ubuntu2404": {
        "engine": "cis-ubuntu2404-ansible/roles/cis_ubuntu2404/files/cis_engine.py",
        "catalog": "cis-ubuntu2404-ansible/roles/cis_ubuntu2404/files/rules.json",
        "guidance": "cis-ubuntu2404-ansible/roles/cis_ubuntu2404/files/guidance.json",
        "sections": "cis-ubuntu2404-ansible/roles/cis_ubuntu2404/files/sections.json",
        "template": "cis-ubuntu2404-ansible/roles/cis_ubuntu2404/templates/report.html.j2",
        "name": "CIS Ubuntu Linux 24.04 LTS Benchmark",
    },
}

# ─── Platform detection helpers ───────────────────────────────────────

def is_windows():
    return sys.platform == "win32"

def default_shell():
    return "powershell" if is_windows() else "/bin/bash"


# ─── Engine runner ────────────────────────────────────────────────────

def run_engine(args, mode):
    """Run cis_engine (Python or PowerShell) and return parsed JSON result."""
    engine = os.path.abspath(args.engine)
    catalog = os.path.abspath(args.catalog)
    engine_dir = os.path.dirname(os.path.abspath(args.engine))

    result_file = os.path.join(
        os.path.abspath(args.output),
        f"result-{mode}-{int(time.time())}.json"
    )
    os.makedirs(os.path.dirname(result_file), exist_ok=True)

    if not is_windows():
        # Linux: run cis_engine.py with python3
        cmd = [
            "sudo", "python3", engine,
            "--catalog", catalog,
            "--mode", mode,
            "--profile", args.profile,
            "--platform", args.platform,
            "--benchmark", args.name,
            "--out", result_file,
        ]
        if args.include:
            cmd += ["--include", args.include]
        if args.exclude:
            cmd += ["--exclude", args.exclude]
        if args.sections_filter:
            cmd += ["--sections", args.sections_filter]
        if args.families:
            cmd += ["--families", args.families]
        if args.allow_disruptive:
            cmd.append("--allow-disruptive")
        if args.backup_dir:
            cmd += ["--backup-dir", os.path.abspath(args.backup_dir)]
    else:
        # Windows: run cis_engine.ps1 with powershell
        cmd = [
            "powershell", "-ExecutionPolicy", "Bypass", "-File", engine,
            "-Catalog", catalog,
            "-Mode", mode,
            "-Profile", args.profile,
            "-Platform", args.platform,
            "-Benchmark", args.name,
            "-Out", result_file,
        ]
        if args.include:
            cmd += ["-Include", args.include]
        if args.exclude:
            cmd += ["-Exclude", args.exclude]
        if args.sections_filter:
            cmd += ["-Sections", args.sections_filter]
        if args.families:
            cmd += ["-Families", args.families]
        if args.allow_disruptive:
            cmd.append("-AllowDisruptive")
        if args.backup_dir:
            cmd += ["-BackupDir", os.path.abspath(args.backup_dir)]

    print(f"[{mode.upper()}] Running: {' '.join(cmd)}")
    started = time.time()

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            cwd=engine_dir
        )
        elapsed = time.time() - started
        print(f"[{mode.upper()}] Exit: {proc.returncode}  Duration: {elapsed:.1f}s")
    except subprocess.TimeoutExpired:
        print(f"[{mode.upper()}] TIMEOUT after 600s", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[{mode.upper()}] Engine not found: {e}", file=sys.stderr)
        sys.exit(1)

    if proc.returncode != 0:
        print(f"[{mode.upper()}] Engine stderr:\n{proc.stderr[-500:]}", file=sys.stderr)
        # For scan mode, engine errors are usually pre-checks (e.g. not root)
        # — still try to read the JSON if it was written.
        if mode == "scan" and not os.path.exists(result_file):
            sys.exit(proc.returncode)

    if not os.path.exists(result_file):
        print(f"[{mode.upper()}] No result JSON produced", file=sys.stderr)
        sys.exit(1)

    with open(result_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    return data, result_file


# ─── Host facts collector ─────────────────────────────────────────────

def collect_host():
    """Collect host information — mirrors what cis_engine records."""
    import platform
    import socket

    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": "",
        "kernel": platform.release(),
        "arch": platform.machine(),
        "virtualization": "",
        "ipv4": [],
        "ipv6": [],
        "mac": [],
        "interfaces": {},
        "uptime_seconds": 0,
        "ssh_address": socket.gethostname(),
    }

    # OS name
    if sys.platform.startswith("linux"):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["os"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except (OSError, UnicodeDecodeError):
            pass
    elif sys.platform == "darwin":
        info["os"] = f"macOS {platform.mac_ver()[0]}"
    elif sys.platform == "win32":
        info["os"] = platform.platform()

    # IPs
    try:
        info["ipv4"] = [addr[4][0] for addr in
                        socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                        if not addr[4][0].startswith("127.")]
    except (OSError, socket.gaierror):
        pass

    # Uptime (Linux)
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/uptime") as f:
                info["uptime_seconds"] = int(float(f.read().split()[0]))
        except (OSError, ValueError):
            pass

    return info


# ─── Report renderer ──────────────────────────────────────────────────

def render_report(result_data, args, mode, scan_result_file):
    """Render HTML report from engine result JSON using Jinja2 template."""
    from jinja2 import Environment, FileSystemLoader

    template_path = os.path.abspath(args.template)
    template_dir = os.path.dirname(template_path)
    template_name = os.path.basename(template_path)

    # Load guidance & sections
    guidance = {}
    if args.guidance:
        with open(args.guidance, "r", encoding="utf-8") as fh:
            guidance = json.load(fh)

    sections = {"chapters": {}, "subsections": {}}
    if args.sections:
        with open(args.sections, "r", encoding="utf-8") as fh:
            sections = json.load(fh)

    # Build template context (mirrors Ansible variables)
    now = datetime.now(timezone.utc).astimezone()
    host = collect_host()
    # Merge host data into result if not already present
    if "host" in result_data and result_data["host"]:
        host.update(result_data["host"])

    ctx = {
        "cis_result": result_data,
        "cis_guidance": guidance,
        "cis_sections": sections,
        "cis_mode_effective": mode,
        "cis_mode": mode,
        "cis_profile": args.profile,
        "cis_platform": args.platform,
        "cis_benchmark_name": args.name,
        "cis_benchmark_version": "1.0.0",
        "cis_org_name": args.org or "",
        "cis_host": host,
        "cis_run_human": now.strftime("%Y-%m-%d %H:%M:%S"),
        "cis_run_stamp": now.strftime("%Y%m%d-%H%M%S"),
        "cis_fleet_size": 1,
        "cis_backup_dir": os.path.abspath(args.backup_dir) if args.backup_dir else "",
        "cis_allow_disruptive": args.allow_disruptive,
        "cis_lang": "en",
        "cis_report_embed_remediation": True,
    }

    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_name)
    html = template.render(**ctx)

    # Output filename
    slug = host.get("hostname", "localhost")
    slug = "".join(c if c.isalnum() or c in "._-" else "_" for c in slug)
    out_name = f"report-{slug}-{args.profile}-{mode}-{ctx['cis_run_stamp']}.html"
    out_path = os.path.join(os.path.abspath(args.output), out_name)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    # Also copy result JSON alongside
    if args.copy_json:
        json_path = out_path.rsplit(".", 1)[0] + ".json"
        import shutil
        shutil.copy2(scan_result_file, json_path)
        print(f"  JSON saved: {json_path}")

    return out_path


# ─── Summary printer ──────────────────────────────────────────────────

def print_summary(data, mode):
    s = data.get("summary", {}).get("all", {})
    total = s.get("total", 0)
    print(f"\n{'='*60}")
    print(f"  Mode:     {mode}")
    print(f"  Profile:  {data.get('profile', '?')}")
    print(f"  Platform: {data.get('platform', '?')}")
    print(f"  Duration: {data.get('duration_seconds', 0):.1f}s")

    if mode == "scan":
        score = s.get("score") or 0
        passed = s.get("pass", 0)
        failed = s.get("fail", 0)
        manual = s.get("manual", 0)
        error = s.get("error", 0)
        na = s.get("notapplicable", 0)
        print(f"  Score:    {score:.1f}%")
        print(f"  Pass:     {passed}")
        print(f"  Fail:     {failed}")
        print(f"  Manual:   {manual}")
        print(f"  Error:    {error}")
        print(f"  N/A:      {na}")
        if total:
            print(f"  Total:    {total}")
    else:
        applied = s.get("applied", 0)
        pending = s.get("applied_pending", 0)
        already = s.get("already", 0)
        failed = s.get("failed", 0)
        skipped = s.get("skipped_disruptive", 0)
        print(f"  Applied:         {applied}")
        print(f"  Pending reboot:  {pending}")
        print(f"  Already ok:      {already}")
        print(f"  Apply failed:    {failed}")
        print(f"  Skipped (risk):  {skipped}")
        if total:
            print(f"  Total:           {total}")

    if data.get("engine_notes"):
        for note in data["engine_notes"]:
            print(f"  Note:    {note}")

    print(f"{'='*60}\n")


# ─── Main commands ────────────────────────────────────────────────────

def cmd_scan(args):
    """SCAN mode: check compliance, generate HTML report."""
    print(f"\n╔══ CIS Benchmark — SCAN ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Platform:{args.platform}")
    if args.include:
        print(f"║ Include: {args.include}")
    if args.exclude:
        print(f"║ Exclude: {args.exclude}")
    if args.sections_filter:
        print(f"║ Sections:{args.sections_filter}")
    if args.families:
        print(f"║ Families:{args.families}")
    print(f"╚{'═'*26}╝\n")

    result_data, result_file = run_engine(args, "scan")
    print_summary(result_data, "scan")

    out_path = render_report(result_data, args, "scan", result_file)
    print(f"\nReport saved: {out_path}")
    return out_path


def cmd_apply(args):
    """APPLY mode: fix rules, then re-scan, generate HTML report."""
    print(f"\n╔══ CIS Benchmark — APPLY ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Platform:{args.platform}")
    if args.include:
        print(f"║ Include: {args.include}")
    if not args.allow_disruptive:
        print(f"║ Note:    Disruptive rules skipped (use --allow-disruptive)")
    print(f"╚{'═'*26}╝\n")

    # Step 1: Pre-scan (optional baseline)
    pre_scan = None
    if not args.no_prescan:
        print("── Step 1/3: Pre-scan (baseline) ──")
        pre_scan, pre_file = run_engine(args, "scan")
        print_summary(pre_scan, "scan")
    else:
        print("── (Pre-scan skipped) ──")

    # Step 2: Apply
    print("── Step 2/3: Apply fixes ──")
    apply_data, apply_file = run_engine(args, "apply")
    print_summary(apply_data, "apply")

    # Step 3: Post-apply scan
    print("── Step 3/3: Post-apply scan (verify) ──")
    post_data, post_file = run_engine(args, "scan")
    print_summary(post_data, "scan")

    # Generate report from post-apply scan
    # Inject apply summary for richer reporting
    if pre_scan and not args.no_prescan:
        pre_score = pre_scan.get("summary", {}).get("all", {}).get("score") or 0
        post_score = post_data.get("summary", {}).get("all", {}).get("score") or 0
        print(f"\n  Score change: {pre_score:.1f}% → {post_score:.1f}%  "
              f"({post_score - pre_score:+.1f}%)")

    # Store apply stats in the post-scan result for the report
    post_data["_apply_stats"] = apply_data.get("summary", {})
    post_data["_apply_changed_files"] = apply_data.get("changed_files", [])
    if pre_scan:
        post_data["_prescan_summary"] = pre_scan.get("summary", {})

    out_path = render_report(post_data, args, "apply", post_file)
    print(f"\nReport saved: {out_path}")
    return out_path


def cmd_check(args):
    """CHECK mode: run both scan and a dry-run apply, show diff without changing."""
    print(f"\n╔══ CIS Benchmark — CHECK (dry-run) ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"╚{'═'*26}╝\n")

    print("── Scan (current state) ──")
    scan_data, scan_file = run_engine(args, "scan")
    print_summary(scan_data, "scan")

    # For "check" we only scan — we can't easily dry-run apply without
    # actually applying. Show rules that would be fixed.
    print("── Rules that need fixing ──")
    failed = [r for r in scan_data.get("results", []) if r.get("status") != "pass"]
    for r in failed:
        aid = r.get("action_id", "") or ""
        print(f"  {r['id']}  [{r.get('status','?')}]  {r.get('title','')}")
        if aid:
            print(f"         fix: {aid}")

    out_path = render_report(scan_data, args, "scan", scan_file)
    print(f"\nReport saved: {out_path}")
    return out_path


# ─── CLI definition ───────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CIS Benchmark local CLI — scan, apply, verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with --os (auto-detects paths)
  python3 cis_cli.py scan --os rhel9 --profile L1 --output ./out/

  # Apply with --os
  python3 cis_cli.py apply --os ubuntu2204 --profile L2 --allow-disruptive --output ./out/

  # Manually specify paths
  python3 cis_cli.py scan --engine .../cis_engine.py \\
      --catalog .../rules.json --profile L1 --name "TencentOS 3" --output ./out/

  # Scan only section 1.1 rules with Level 2
  python3 cis_cli.py scan --os rhel8 --profile L2 --sections "1.1" --output ./out/
        """
    )

    sub = ap.add_subparsers(dest="command", help="Mode: scan | apply | check")
    sub.required = True

    # ── Common args shared by all commands ──
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
        p.add_argument("--profile", default="L1", choices=["L1", "L2"],
                       help="Benchmark profile level (default: L1)")
        p.add_argument("--platform", default="server",
                       choices=["server", "workstation", "all"],
                       help="Target platform (default: server)")
        p.add_argument("--name", default="CIS Benchmark",
                       help="Benchmark display name")
        p.add_argument("--org", default="",
                       help="Organization name for report header")
        p.add_argument("--include", default="",
                       help="Comma-separated rule IDs to include (e.g. 1.1.1,1.1.2)")
        p.add_argument("--exclude", default="",
                       help="Comma-separated rule IDs to exclude")
        p.add_argument("--sections-filter", default="",
                       help="Comma-separated section prefixes to filter (e.g. 1.1,5)")
        p.add_argument("--families", default="",
                       help="Comma-separated rule families to filter")
        p.add_argument("--output", default="./output",
                       help="Output directory for reports (default: ./output)")
        p.add_argument("--copy-json", action="store_true",
                       help="Also save result JSON alongside the HTML report")
        p.add_argument("--no-prescan", action="store_true",
                       help="Skip pre-scan baseline in apply mode")

    # ── Apply-specific args ──
    def add_apply_args(p):
        p.add_argument("--allow-disruptive", action="store_true",
                       help="Allow potentially disruptive rules to be applied")
        p.add_argument("--backup-dir", default="",
                       help="Directory to store backup files before changes")

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Check compliance only, generate HTML report")
    add_common_args(p_scan)

    # ── apply ──
    p_apply = sub.add_parser("apply", help="Apply fixes, re-scan, generate report")
    add_common_args(p_apply)
    add_apply_args(p_apply)

    # ── check ──
    p_check = sub.add_parser("check", help="Dry-run: scan + show what would change")
    add_common_args(p_check)
    add_apply_args(p_check)

    args = ap.parse_args()

    # ── Resolve --os preset ──
    if args.os:
        preset = OS_PRESETS[args.os]
        args.engine = args.engine or os.path.join(_SCRIPT_DIR, preset["engine"])
        args.catalog = args.catalog or os.path.join(_SCRIPT_DIR, preset["catalog"])
        args.guidance = args.guidance or os.path.join(_SCRIPT_DIR, preset["guidance"])
        args.sections = args.sections or os.path.join(_SCRIPT_DIR, preset["sections"])
        args.template = args.template or os.path.join(_SCRIPT_DIR, preset["template"])
        if not args.name or args.name == "CIS Benchmark":
            args.name = preset["name"]

    # Validate required paths
    if not args.engine or not args.catalog:
        print("Error: --engine and --catalog are required (or use --os)", file=sys.stderr)
        sys.exit(1)

    # Validate template exists if specified
    if args.template and not os.path.exists(args.template):
        print(f"Template not found: {args.template}", file=sys.stderr)
        sys.exit(1)

    # Dispatch
    commands = {
        "scan": cmd_scan,
        "apply": cmd_apply,
        "check": cmd_check,
    }

    try:
        report_path = commands[args.command](args)
        if report_path:
            print(f"\nDone. Open: {report_path}")
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
