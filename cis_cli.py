#!/usr/bin/env python3
"""
CIS Benchmark CLI — scan, apply, show rule detail, with HTML + CLI output.

Usage:
  # Scan only (check compliance)
  python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

  # Apply then re-scan (combined)
  python3 cis_cli.py apply --os rhel9 --profile L1 --output output/

  # Fine-grained: run specific rules by ID
  python3 cis_cli.py scan --os rhel9 --include "1.1.1.1,1.1.1.2,5.1.1" --output output/

  # View rule detail (CLI)
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1

  # View rule detail (HTML)
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1 --format html --output output/

Supported --os values:
  tencentos3, tencentos4
  rhel8, rhel9, rhel10
  sles15, sles16
  ubuntu2004, ubuntu2204, ubuntu2404
  win2016, win2019, win2022, win2025
"""

import argparse
import html
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

# ─── OS Presets ──────────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

OS_PRESETS = {
    "tencentos3": {
        "engine": "cis-tencentos3-ansible/roles/cis_tencentos3/files/cis_engine.py",
        "catalog": "cis-tencentos3-ansible/roles/cis_tencentos3/files/rules.json",
        "guidance": "cis-tencentos3-ansible/roles/cis_tencentos3/files/guidance.json",
        "sections": "cis-tencentos3-ansible/roles/cis_tencentos3/files/sections.json",
        "template": "cis-tencentos3-ansible/roles/cis_tencentos3/templates/report.html.j2",
        "name": "CIS TencentOS Server 3 Benchmark",
    },
    "tencentos4": {
        "engine": "cis-tencentos4-ansible/roles/cis_tencentos4/files/cis_engine.py",
        "catalog": "cis-tencentos4-ansible/roles/cis_tencentos4/files/rules.json",
        "guidance": "cis-tencentos4-ansible/roles/cis_tencentos4/files/guidance.json",
        "sections": "cis-tencentos4-ansible/roles/cis_tencentos4/files/sections.json",
        "template": "cis-tencentos4-ansible/roles/cis_tencentos4/templates/report.html.j2",
        "name": "CIS TencentOS Server 4 Benchmark",
    },
    "win2016": {
        "engine": "cis-win2016-ansible/roles/cis_win2016/files/cis_engine.ps1",
        "catalog": "cis-win2016-ansible/roles/cis_win2016/files/rules.json",
        "guidance": "cis-win2016-ansible/roles/cis_win2016/files/guidance.json",
        "sections": "cis-win2016-ansible/roles/cis_win2016/files/sections.json",
        "template": "cis-win2016-ansible/roles/cis_win2016/templates/report.html.j2",
        "name": "CIS Microsoft Windows Server 2016 Benchmark",
    },
    "win2019": {
        "engine": "cis-win2019-ansible/roles/cis_win2019/files/cis_engine.ps1",
        "catalog": "cis-win2019-ansible/roles/cis_win2019/files/rules.json",
        "guidance": "cis-win2019-ansible/roles/cis_win2019/files/guidance.json",
        "sections": "cis-win2019-ansible/roles/cis_win2019/files/sections.json",
        "template": "cis-win2019-ansible/roles/cis_win2019/templates/report.html.j2",
        "name": "CIS Microsoft Windows Server 2019 Benchmark",
    },
    "win2022": {
        "engine": "cis-win2022-ansible/roles/cis_win2022/files/cis_engine.ps1",
        "catalog": "cis-win2022-ansible/roles/cis_win2022/files/rules.json",
        "guidance": "cis-win2022-ansible/roles/cis_win2022/files/guidance.json",
        "sections": "cis-win2022-ansible/roles/cis_win2022/files/sections.json",
        "template": "cis-win2022-ansible/roles/cis_win2022/templates/report.html.j2",
        "name": "CIS Microsoft Windows Server 2022 Benchmark",
    },
    "win2025": {
        "engine": "cis-win2025-ansible/roles/cis_win2025/files/cis_engine.ps1",
        "catalog": "cis-win2025-ansible/roles/cis_win2025/files/rules.json",
        "guidance": "cis-win2025-ansible/roles/cis_win2025/files/guidance.json",
        "sections": "cis-win2025-ansible/roles/cis_win2025/files/sections.json",
        "template": "cis-win2025-ansible/roles/cis_win2025/templates/report.html.j2",
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
        if args.audit_log:
            cmd += ["--audit-log", os.path.abspath(args.audit_log)]
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
        if args.audit_log:
            cmd += ["-AuditLog", os.path.abspath(args.audit_log)]

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

    try:
        with open(result_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[{mode.upper()}] Result JSON corrupt: {exc}", file=sys.stderr)
        sys.exit(1)

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
        "cis_benchmark_version": args.version,
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
    try:
        template = env.get_template(template_name)
    except Exception as exc:
        print(f"Template error ({template_name}): {exc}", file=sys.stderr)
        return None
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


def print_result_table(data):
    """Print per-rule scan results as a color-coded ASCII table."""
    results = data.get("results", [])
    if not results:
        print("  (no results)")
        return

    STATUS_SYM = {"pass": "✓", "fail": "✗", "manual": "?", "error": "!", "notapplicable": "-"}
    FAMILY_ABBR = {
        "kmod": "kmod", "sysctl": "sysctl", "pkg": "pkg", "svc": "svc",
        "ssh": "ssh", "pam": "pam", "sudo": "sudo", "perm": "perm",
        "grub": "grub", "auditd": "audit", "rsyslog": "rsyslog",
        "cron": "cron", "ntp": "ntp", "user": "user", "gdm": "gdm",
        "firewall": "fw", "modprobe": "modp", "mount": "mnt",
        "file": "file", "cmd": "cmd", "manual": "man",
        "password-policy": "passwd", "lockout-policy": "lock",
        "audit-policy": "audit", "user-right": "uright",
        "reg-dword": "reg", "adv-audit": "adv",
    }

    # Determine column widths — ID could be 1.1.1.1 or longer
    id_lens = [len(r.get("id", "")) for r in results]
    max_id = max(id_lens) if id_lens else 10
    fam_lens = [len(FAMILY_ABBR.get(r.get("family", ""), r.get("family", ""))) for r in results]
    max_fam = min(max(fam_lens) if fam_lens else 6, 8)
    term_w = 120
    title_w = term_w - max_id - max_fam - 16  # 16 for status + spacing

    header = f"  {'ID':<{max_id}}  {'S':<2} {'Family':<{max_fam}}  {'Title':<{title_w}}"
    sep = f"  {'-'*max_id}  {'--':<2} {'-'*max_fam}  {'-'*title_w}"
    print(header)
    print(sep)

    for r in results:
        rid = r.get("id", "?")
        status = r.get("status", "?")
        symb = STATUS_SYM.get(status, "?")
        fam = FAMILY_ABBR.get(r.get("family", ""), r.get("family", ""))[:max_fam]
        title = (r.get("title", "") or "")[:title_w]

        if status == "fail":
            line = click_style(f"[{symb}]", "red") + f" {rid:<{max_id}}  "
        elif status == "pass":
            line = click_style(f"[{symb}]", "green") + f" {rid:<{max_id}}  "
        elif status == "manual":
            line = click_style(f"[{symb}]", "yellow") + f" {rid:<{max_id}}  "
        elif status == "error":
            line = click_style(f"[{symb}]", "red") + f" {rid:<{max_id}}  "
        else:
            line = f"  [{symb}] {rid:<{max_id}}  "

        line += f"{fam:<{max_fam}}  {title}"
        print(line)

    print(sep)
    counts = {}
    for r in results:
        s = r.get("status", "?")
        counts[s] = counts.get(s, 0) + 1
    parts = []
    if counts.get("pass"):
        parts.append(click_style(f"✓ {counts['pass']} pass", "green"))
    if counts.get("fail"):
        parts.append(click_style(f"✗ {counts['fail']} fail", "red"))
    if counts.get("manual"):
        parts.append(click_style(f"? {counts['manual']} manual", "yellow"))
    if counts.get("error"):
        parts.append(click_style(f"! {counts['error']} error", "red"))
    if counts.get("notapplicable"):
        parts.append(f"- {counts['notapplicable']} n/a")
    print(f"  {'  '.join(parts)}  |  total: {len(results)}")
    print()


def click_style(text, color):
    """Return ANSI-colored text. Works in most terminals."""
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36", "bold": "1"}
    c = codes.get(color, "0")
    return f"\033[{c}m{text}\033[0m"


def find_rule(catalog_path, rule_id):
    """Find a rule by ID in the catalog JSON."""
    with open(catalog_path, "r", encoding="utf-8") as fh:
        rules = json.load(fh)
    for r in rules:
        if r.get("id") == rule_id:
            return r, len(rules)
    return None, len(rules)


def lookup_guidance(guidance_path, rule_id):
    """Get guidance entry for a rule ID."""
    if not guidance_path or not os.path.exists(guidance_path):
        return {}
    with open(guidance_path, "r", encoding="utf-8") as fh:
        g = json.load(fh)
    if isinstance(g, dict):
        return g.get(rule_id, {})
    return {}


def lookup_section(sections_path, section_id):
    """Resolve section/chapter names. Handles both dict {chapters, subsections} and list [{id, title}] formats."""
    if not sections_path or not os.path.exists(sections_path):
        return "", ""
    with open(sections_path, "r", encoding="utf-8") as fh:
        s = json.load(fh)

    if isinstance(s, dict):
        chapters = s.get("chapters", {})
        subsections = s.get("subsections", {})
        chapter_num = section_id.split(".")[0] if "." in section_id else section_id
        chapter_name = chapters.get(chapter_num, "")
        subsection_name = subsections.get(section_id, "")
        return chapter_name, subsection_name

    if isinstance(s, list):
        # Windows-format: [{id, title, ...}]
        chapter_num = section_id.split(".")[0] if "." in section_id else section_id
        chapter_name = ""
        subsection_name = ""
        for entry in s:
            eid = entry.get("id", "")
            if eid == section_id:
                subsection_name = entry.get("title", "")
            elif eid == chapter_num:
                chapter_name = entry.get("title", "")
        return chapter_name, subsection_name

    return "", ""


def get_rule_detail(args, rule_id):
    """Build a rich dict of rule detail from catalog + guidance + sections."""
    rule, total = find_rule(args.catalog, rule_id)
    if rule is None:
        return None

    guidance = lookup_guidance(args.guidance, rule_id)
    chapter, subsection = lookup_section(args.sections, rule.get("section", ""))

    return {
        "id": rule["id"],
        "title": rule["title"],
        "section": rule.get("section", ""),
        "section_chapter": chapter,
        "section_subsection": subsection,
        "family": rule.get("family", ""),
        "levels": rule.get("levels", [1]),
        "risk": rule.get("risk", "safe"),
        "platforms": rule.get("platforms", []),
        "automated": "Automated" in str(rule.get("assessment", "")),
        "page": rule.get("page", ""),
        "assessment": rule.get("assessment", ""),
        "params": rule.get("params", {}),
        "description": guidance.get("description", ""),
        "rationale": guidance.get("rationale", ""),
        "remediation": guidance.get("remediation", ""),
        "benchmark": args.name,
        "benchmark_version": args.version,
        "total_rules": total,
    }


# ─── Main commands ────────────────────────────────────────────────────

def cmd_scan(args):
    """SCAN mode: check compliance, generate HTML report and CLI table."""
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
    print_result_table(result_data)

    out_path = None
    if args.format in ("html", "both"):
        out_path = render_report(result_data, args, "scan", result_file)
        print(f"Report saved: {out_path}")
    return out_path


def cmd_apply(args):
    """APPLY mode: pre-scan, apply fixes, post-scan, generate report."""
    print(f"\n╔══ CIS Benchmark — APPLY ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Platform:{args.platform}")
    if args.include:
        print(f"║ Include: {args.include}")
    if not args.allow_disruptive:
        print(f"║ Note:    Disruptive rules skipped (use --allow-disruptive)")
    print(f"╚{'═'*26}╝\n")

    # Step 1: Pre-scan (baseline) — skip with --no-prescan
    pre_scan = None
    if not args.no_prescan:
        print("── Step 1/3: Pre-scan (baseline) ──")
        pre_scan, pre_file = run_engine(args, "scan")
        print_summary(pre_scan, "scan")
        print_result_table(pre_scan)
    else:
        print("── (Pre-scan skipped) ──")

    # Step 2: Apply
    print("── Step 2/3: Apply fixes ──")
    apply_data, apply_file = run_engine(args, "apply")
    print_summary(apply_data, "apply")

    # Step 3: Post-apply scan (always — verify fixes)
    print("── Step 3/3: Post-apply scan (verify) ──")
    post_data, post_file = run_engine(args, "scan")
    print_summary(post_data, "scan")
    print_result_table(post_data)

    # Generate report from post-apply scan
    if pre_scan and not args.no_prescan:
        pre_score = pre_scan.get("summary", {}).get("all", {}).get("score") or 0
        post_score = post_data.get("summary", {}).get("all", {}).get("score") or 0
        print(f"\n  Score change: {pre_score:.1f}% → {post_score:.1f}%  "
              f"({post_score - pre_score:+.1f}%)")

    post_data["_apply_stats"] = apply_data.get("summary", {})
    post_data["_apply_changed_files"] = apply_data.get("changed_files", [])
    if pre_scan:
        post_data["_prescan_summary"] = pre_scan.get("summary", {})

    out_path = None
    if args.format in ("html", "both"):
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


def cmd_info(args):
    """INFO mode: show rule detail by ID, CLI or HTML."""
    rule_id = args.id.strip()
    detail = get_rule_detail(args, rule_id)
    if detail is None:
        print(f"Rule '{rule_id}' not found in catalog.", file=sys.stderr)
        sys.exit(1)

    if args.format == "html":
        return _render_info_html(detail, args)

    # CLI output — rich formatted
    print()
    print(f"  {click_style('═══ Rule Detail ═══', 'bold')}")
    print(f"  ID:         {click_style(detail['id'], 'cyan')}")
    print(f"  Title:      {detail['title']}")
    print(f"  Benchmark:  {detail['benchmark']}  v{detail['benchmark_version']}")
    print(f"  Section:    {detail['section']}", end="")
    if detail["section_chapter"]:
        print(f" — {detail['section_chapter']}", end="")
    if detail["section_subsection"]:
        print(f" / {detail['section_subsection']}", end="")
    print()
    print(f"  Family:     {detail['family']}")
    print(f"  Level(s):   {', '.join(f'L{x}' for x in detail['levels'])}")
    print(f"  Risk:       {detail['risk']}")
    print(f"  Automated:  {'Yes' if detail['automated'] else 'No (Manual)'}")
    if detail.get("page"):
        print(f"  Page:       {detail['page']}")
    if detail.get("platforms"):
        print(f"  Platforms:  {', '.join(detail['platforms'])}")

    if detail.get("description"):
        print(f"\n  {click_style('Description', 'bold')}")
        print(f"  {detail['description']}")

    if detail.get("rationale"):
        print(f"\n  {click_style('Rationale', 'bold')}")
        print(f"  {detail['rationale']}")

    if detail.get("assessment"):
        print(f"\n  {click_style('Assessment', 'bold')}")
        print(f"  {detail['assessment']}")

    if detail.get("params"):
        print(f"\n  {click_style('Parameters', 'bold')}")
        for k, v in detail["params"].items():
            print(f"    {k}: {v}")

    if detail.get("remediation"):
        print(f"\n  {click_style('Remediation', 'bold')}")
        for line in detail["remediation"].split("\n"):
            print(f"  {line}")

    print(f"\n  Total rules in catalog: {detail['total_rules']}")
    print()
    return None


def _render_info_html(detail, args):
    """Generate a single-rule detail HTML page."""
    template_path = os.path.abspath(args.template)
    template_dir = os.path.dirname(template_path)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rule {detail['id']} — {detail['benchmark']}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a2e; background: #f8f9fa; }}
.rule-id {{ font-size: 28px; font-weight: 700; color: #0ea5e9; }}
.rule-title {{ font-size: 20px; margin: 8px 0 24px; color: #334155; }}
.meta {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 28px; }}
.meta-item {{ background: #e2e8f0; padding: 4px 12px; border-radius: 6px; font-size: 13px; color: #475569; }}
.section {{ background: #0ea5e9; color: #fff; }}
.section-title {{ font-size: 16px; font-weight: 600; color: #1e293b; margin: 24px 0 8px;
                   border-bottom: 2px solid #0ea5e9; padding-bottom: 4px; }}
.content {{ background: #fff; padding: 16px 20px; border-radius: 8px;
           line-height: 1.7; color: #475569; white-space: pre-wrap; font-size: 14px; }}
.params-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
.params-table td {{ padding: 6px 12px; border: 1px solid #e2e8f0; }}
.params-table td:first-child {{ font-weight: 600; background: #f1f5f9; width: 200px; }}
</style>
</head>
<body>
<div class="rule-id">{html.escape(detail['id'])}</div>
<div class="rule-title">{html.escape(detail['title'])}</div>
<div class="meta">
  <span class="meta-item">Benchmark: {detail['benchmark']} v{detail['benchmark_version']}</span>
  <span class="meta-item section">Section {detail['section']}</span>
  <span class="meta-item">Family: {detail['family']}</span>
  <span class="meta-item">Level: {', '.join(f'L{x}' for x in detail['levels'])}</span>
  <span class="meta-item">Risk: {detail['risk']}</span>
  <span class="meta-item">{'Automated' if detail['automated'] else 'Manual'}</span>
</div>
"""

    for label, key in [("Description", "description"), ("Rationale", "rationale"),
                        ("Assessment", "assessment"), ("Remediation", "remediation")]:
        val = detail.get(key, "")
        if val:
            html += f'<div class="section-title">{html.escape(label)}</div>\n<div class="content">{html.escape(val)}</div>\n'

    if detail.get("params"):
        html += '<div class="section-title">Parameters</div>\n<table class="params-table">\n'
        for k, v in detail["params"].items():
            html += f'<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>\n'
        html += '</table>\n'

    html += "</body></html>"

    os.makedirs(os.path.abspath(args.output), exist_ok=True)
    out_path = os.path.join(os.path.abspath(args.output),
                            f"info-{detail['id'].replace('.', '-')}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Info HTML saved: {out_path}")
    return out_path


# ─── CLI definition ───────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CIS Benchmark local CLI — scan, apply, view rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Pure scan
  python3 cis_cli.py scan --os rhel9 --profile L1 --output ./out/

  # Apply + auto re-scan (combined)
  python3 cis_cli.py apply --os ubuntu2204 --profile L2 --allow-disruptive --output ./out/

  # Fine-grained: only specific rules
  python3 cis_cli.py scan --os rhel8 --include "1.1.1.1,1.1.1.2,5.1.1" --output ./out/

  # CLI-only output (no HTML)
  python3 cis_cli.py scan --os rhel9 --format cli

  # View rule detail
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1

  # View rule detail as HTML page
  python3 cis_cli.py info --os rhel9 --id 1.1.1.1 --format html --output ./out/
        """
    )

    sub = ap.add_subparsers(dest="command", help="Mode: scan | apply | check | info")
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
        p.add_argument("--version", default="v1.0.0",
                       help="Benchmark version for report footer")
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
        p.add_argument("--format", default="both", choices=["html", "cli", "both"],
                       help="Output format: html, cli, or both (default: both)")
        p.add_argument("--copy-json", action="store_true",
                       help="Also save result JSON alongside the HTML report")
        p.add_argument("--audit-log", default="",
                       help="Write audit log (JSON-lines) to this path")
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
        "info": cmd_info,
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
