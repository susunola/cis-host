"""scan/audit/apply/check command implementations: the core "run the
engine, print a summary table, render an HTML report" commands. apply
additionally runs a pre/post verification diff (ciscvm_diff.py) and
check runs a scan-only dry-run preview of what apply would fix.
"""

import json
import os
from datetime import datetime

import ciscvm_diff
from engine import run_engine
from display import click_style, print_summary, print_result_table
from report import render_report


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
