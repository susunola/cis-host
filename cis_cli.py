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
import html
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import ciscvm_config
import ciscvm_diff
from presets import OS_PRESETS
from catalog import find_rule, lookup_guidance, lookup_section, get_rule_detail
from engine import run_engine
from display import click_style, print_summary, print_result_table
from report import render_report

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
    return {"data": result_data, "path": out_path}


def cmd_audit(args):
    """AUDIT mode: scan-only compliance gate with exit-code policy.

    Behaves like `scan` but defaults to strict (exit non-zero on findings) and
    writes a concise audit artifact suitable for CI gates.
    """
    print(f"\n╔══ CIS Benchmark — AUDIT / GATE ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Platform:{args.platform}")
    if args.include:
        print(f"║ Include: {args.include}")
    if args.exclude:
        print(f"║ Exclude: {args.exclude}")
    print(f"╚{'═'*26}╝\n")

    result_data, result_file = run_engine(args, "scan")
    print_summary(result_data, "scan")
    print_result_table(result_data)

    out_path = None
    if args.format in ("html", "both"):
        out_path = render_report(result_data, args, "scan", result_file)
        print(f"Report saved: {out_path}")

    s = result_data.get("summary", {}).get("all", {})
    fail = s.get("fail", 0)
    err = s.get("error", 0)
    score = s.get("score", 0.0)
    gate_pass = fail == 0 and err == 0

    audit_summary = {
        "started_at": result_data.get("started_at"),
        "host": result_data.get("host", {}),
        "mode": "audit",
        "profile": result_data.get("profile"),
        "platform": result_data.get("platform"),
        "score": score,
        "hardening_index": s.get("hardening_index", 0.0),
        "fail": fail,
        "error": err,
        "waived": s.get("waived", 0),
        "gate_pass": gate_pass,
    }
    audit_path = os.path.join(os.path.abspath(args.output),
                              f"audit-gate-{result_data.get('host', {}).get('hostname', 'localhost')}-{args.profile}.json")
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    with open(audit_path, "w", encoding="utf-8") as fh:
        json.dump(audit_summary, fh, indent=2)
    print(f"Audit gate saved: {audit_path}")

    status = click_style("PASS", "green") if gate_pass else click_style("FAIL", "red")
    print(f"\nGate: {status}  (fail={fail}, error={err}, score={score:.1f}%)")
    return {"data": result_data, "path": out_path, "audit_path": audit_path, "gate_pass": gate_pass}


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
    if args.simulate:
        print(f"║ Mode:    SIMULATE (dry-run, no changes)")
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

    # Step 3: Post-apply scan (always — verify fixes, unless simulating)
    if args.simulate:
        print("── Step 3/3: Post-apply scan skipped in simulate mode ──")
        post_data = apply_data
        post_file = apply_file
    else:
        print("── Step 3/3: Post-apply scan (verify) ──")
        post_data, post_file = run_engine(args, "scan")
        print_summary(post_data, "scan")
        print_result_table(post_data)

    if pre_scan and not args.no_prescan:
        pre_score = pre_scan.get("summary", {}).get("all", {}).get("score") or 0
        post_score = post_data.get("summary", {}).get("all", {}).get("score") or 0
        print(f"\n  Score change: {pre_score:.1f}% → {post_score:.1f}%  "
              f"({post_score - pre_score:+.1f}%)")

    # Apply + verify: compare pre/post scans so the user sees what was
    # actually fixed, what is still failing, and what regressed.
    verify = ciscvm_diff.verify_remediation(pre_scan, post_data)
    post_data["_verify"] = verify.to_dict()
    if not verify.is_empty():
        print("\n  ── Verification (pre vs post apply) ──")
        c = verify.counts()
        print(f"  {click_style('✔', 'green')} Fixed:       {c['fixed']}")
        print(f"  {click_style('✗', 'red')} Still fail:  {c['still_fail']}")
        if c["regressed"]:
            print(f"  {click_style('!', 'red')} Regressed:   {c['regressed']}  "
                  f"← remediation may have broken these")
        if c["waived"]:
            print(f"  {click_style('W', 'cyan')} Newly waived:{c['waived']}")

        def _dump(label, items, style=None):
            if not items:
                return
            print(f"    {click_style(label, style) if style else label} ({len(items)})")
            for chg in items[:30]:
                print(f"      {chg.rule_id}  {chg.title[:60]}")
            if len(items) > 30:
                print(f"      ... and {len(items) - 30} more")

        _dump("fixed", verify.fixed, "green")
        _dump("still failing", verify.still_fail, "red")
        _dump("regressed", verify.regressed, "red")
        _dump("newly waived", verify.waived, "cyan")
        print()

        # Standalone verification report (apply + verify, audit-ready).
        verify_path = os.path.join(
            os.path.abspath(args.output),
            f"verify-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html")
        os.makedirs(os.path.dirname(verify_path), exist_ok=True)
        with open(verify_path, "w", encoding="utf-8") as fh:
            fh.write(ciscvm_diff.render_verify_html(
                verify, name=args.name, profile=args.profile, org=args.org))
        print(f"Verification report saved: {verify_path}")
    elif verify.warnings:
        for w in verify.warnings:
            print(f"  {w}")

    post_data["_apply_stats"] = apply_data.get("summary", {})
    post_data["_apply_changed_files"] = apply_data.get("changed_files", [])
    if pre_scan:
        post_data["_prescan_summary"] = pre_scan.get("summary", {})

    out_path = None
    if args.format in ("html", "both"):
        out_path = render_report(post_data, args, "apply", post_file)
        print(f"\nReport saved: {out_path}")
    return {"data": post_data, "path": out_path}


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
    return {"data": scan_data, "path": out_path}


# ─── Drift detection, verification & periodic watch ───────────────
#
# Pure logic lives in ciscvm_diff.py (unit-testable, dataclass-typed);
# this file only wires CLI arguments to it.

def _load_result_json(path):
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
    before = _load_result_json(args.before)
    after = _load_result_json(args.after)
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
        baseline = _load_result_json(args.baseline)
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


# ─── Fleet scan ─# ─── Fleet scan ───────────────────────────────────────────────────────

def _load_fleet_hosts(args):
    """Return a list of host identifiers from CLI or config."""
    hosts = []
    if getattr(args, "fleet_hosts", None):
        hosts = [h.strip() for h in args.fleet_hosts.split(",") if h.strip()]
    fleet_cfg = getattr(args, "fleet", {}) or {}
    if not hosts and fleet_cfg.get("hosts"):
        hosts = _normalize_list(fleet_cfg.get("hosts"))
        hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    return hosts


def _normalize_list(value):
    """Accept str, list, or None and return a comma-separated string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def _run_remote_scan(host, args, fleet_cfg):
    """SSH to a host and run the engine remotely.  Returns parsed JSON or None."""
    user = fleet_cfg.get("user", "root")
    key = fleet_cfg.get("key", "")
    remote_engine = fleet_cfg.get("remote_engine", "/opt/cis-host/cis_engine.py")
    remote_catalog = fleet_cfg.get("remote_catalog", "/opt/cis-host/rules.json")
    remote_guidance = fleet_cfg.get("remote_guidance", "")
    remote_sections = fleet_cfg.get("remote_sections", "")
    remote_template = fleet_cfg.get("remote_template", "")
    ssh_opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        ssh_opts += ["-i", os.path.expanduser(key)]
    target = f"{user}@{host}"

    cmd = ["ssh"] + ssh_opts + [target, "sudo", "python3", remote_engine,
           "--catalog", remote_catalog,
           "--mode", "scan",
           "--profile", args.profile,
           "--platform", args.platform,
           "--benchmark", args.name,
           "--out", "-"]
    if args.include:
        cmd += ["--include", args.include]
    if args.exclude:
        cmd += ["--exclude", args.exclude]
    if args.sections_filter:
        cmd += ["--sections", args.sections_filter]
    if args.families:
        cmd += ["--families", args.families]

    print(f"[FLEET] ssh {target}: {' '.join(cmd[3 + len(ssh_opts):])}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout,
                              stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"[FLEET] {host}: connection failed: {exc}", file=sys.stderr)
        return None

    if proc.returncode != 0:
        print(f"[FLEET] {host}: engine error: {proc.stderr[:500]}", file=sys.stderr)
        return None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        print(f"[FLEET] {host}: result JSON corrupt: {exc}", file=sys.stderr)
        return None

    # Ensure host identity reflects the fleet target
    data["host"] = data.get("host", {})
    data["host"]["hostname"] = host
    return data


def _aggregate_fleet_results(host_results):
    """Combine per-host result dicts into a fleet summary."""
    fleet_results = []
    summaries = []
    for host, data in host_results:
        if not data:
            continue
        for r in data.get("results", []):
            r["_fleet_host"] = host
            fleet_results.append(r)
        s = data.get("summary", {}).get("all", {})
        s["_host"] = host
        summaries.append(s)

    # Roll up counts
    blank = {"total": 0, "pass": 0, "fail": 0, "manual": 0, "error": 0,
             "notapplicable": 0, "waived": 0}
    for s in summaries:
        for k in blank:
            blank[k] += s.get(k, 0)
    scored = blank["pass"] + blank["fail"]
    blank["score"] = round(100.0 * blank["pass"] / scored, 1) if scored else 0.0

    return {
        "mode": "fleet_scan",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "fleet_size": len(host_results),
        "reachable": len(summaries),
        "summaries": summaries,
        "summary": {"all": blank},
        "results": fleet_results,
    }


def _render_fleet_report(aggregate, args):
    """Render a simple fleet HTML summary if a template is available."""
    now = datetime.now(timezone.utc).astimezone()
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"fleet-report-{args.profile}-{now.strftime('%Y%m%d-%H%M%S')}.html")

    rows = ""
    for s in aggregate.get("summaries", []):
        host = html.escape(s.get("_host", "?"))
        rows += (f"<tr><td>{host}</td><td>{s.get('score', 0):.1f}%</td>"
                 f"<td>{s.get('pass', 0)}</td><td>{s.get('fail', 0)}</td>"
                 f"<td>{s.get('error', 0)}</td><td>{s.get('manual', 0)}</td></tr>")

    alls = aggregate.get("summary", {}).get("all", {})
    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CIS Fleet Report — {html.escape(args.name)}</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #1a2332; background: #f8f9fa; }}
h1 {{ font-size: 24px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #fff; }}
th, td {{ padding: 10px 12px; border: 1px solid #e1e6ef; text-align: left; font-size: 13px; }}
th {{ background: #1e3a6e; color: #fff; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
.bad {{ color: #c42a1e; font-weight: 700; }}
.ok {{ color: #0d7a53; font-weight: 700; }}
</style>
</head>
<body>
<h1>Fleet Compliance Report</h1>
<p><strong>{html.escape(args.name)}</strong> · Profile {args.profile} · {aggregate['fleet_size']} host(s) · {aggregate['reachable']} reachable</p>
<p>Aggregate score: <span class="{'ok' if alls.get('score',0) >= 90 else 'bad'}">{alls.get('score',0):.1f}%</span></p>
<table>
<thead><tr><th>Host</th><th>Score</th><th>Pass</th><th>Fail</th><th>Error</th><th>Manual</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return out_path


def cmd_fleet_scan(args):
    """FLEET SCAN mode: scan multiple hosts and aggregate a fleet report."""
    hosts = _load_fleet_hosts(args)
    if not hosts:
        print("Error: no fleet hosts configured. Use --fleet-hosts or [fleet] hosts in ciscvm.toml",
              file=sys.stderr)
        sys.exit(1)

    fleet_cfg = getattr(args, "fleet", {}) or {}
    remote = getattr(args, "fleet_remote", False) or fleet_cfg.get("remote", False)

    print(f"\n╔══ CIS Benchmark — FLEET SCAN ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Hosts:   {', '.join(hosts)}")
    print(f"║ Remote:  {'SSH' if remote else 'local (tagged)'}")
    print(f"╚{'═'*26}╝\n")

    host_results = []
    for host in hosts:
        print(f"── Host: {host} ──")
        if remote:
            data = _run_remote_scan(host, args, fleet_cfg)
        else:
            # Local mode: run on this machine but tag results with the host label.
            # Useful for testing and for CI fleets that run ciscvm inside each node.
            data, _ = run_engine(args, "scan")
            if data:
                data["host"] = data.get("host", {})
                data["host"]["hostname"] = host
        host_results.append((host, data))
        if data:
            s = data.get("summary", {}).get("all", {})
            print(f"  score={s.get('score', 0):.1f}% pass={s.get('pass', 0)} fail={s.get('fail', 0)}")

    aggregate = _aggregate_fleet_results(host_results)
    out_path = _render_fleet_report(aggregate, args)
    print(f"\nFleet report saved: {out_path}")

    # Save aggregate JSON
    json_path = out_path.replace(".html", ".json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(aggregate, fh, indent=2)
    print(f"Fleet JSON saved:   {json_path}")

    return {"data": aggregate, "path": out_path}


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

    html_doc = f"""<!DOCTYPE html>
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
  <span class="meta-item">Benchmark: {html.escape(detail['benchmark'])} v{html.escape(detail['benchmark_version'])}</span>
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
            html_doc += f'<div class="section-title">{html.escape(label)}</div>\n<div class="content">{html.escape(val)}</div>\n'

    if detail.get("params"):
        html_doc += '<div class="section-title">Parameters</div>\n<table class="params-table">\n'
        for k, v in detail["params"].items():
            html_doc += f'<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>\n'
        html_doc += '</table>\n'

    html_doc += "</body></html>"

    os.makedirs(os.path.abspath(args.output), exist_ok=True)
    out_path = os.path.join(os.path.abspath(args.output),
                            f"info-{detail['id'].replace('.', '-')}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"Info HTML saved: {out_path}")
    return out_path


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
