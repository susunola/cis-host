"""Terminal output helpers: ANSI color styling and result summary/table printers.

`click_style` respects the NO_COLOR convention (https://no-color.org/) and
auto-disables ANSI codes when stdout is not a TTY (e.g. piped to a file or
CI log), so redirected output doesn't get polluted with escape sequences.
This is a deliberate behavior change from the original cis_cli.py, which
always emitted color codes regardless of TTY/NO_COLOR — see CHANGELOG.
"""

import os
import sys


def _color_enabled():
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def click_style(text, color):
    """Return ANSI-colored text. Works in most terminals.

    No-ops (returns `text` unchanged) when NO_COLOR is set or stdout is not
    a TTY.
    """
    if not _color_enabled():
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36", "bold": "1"}
    c = codes.get(color, "0")
    return f"\033[{c}m{text}\033[0m"


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
        idx = s.get("hardening_index") or 0
        passed = s.get("pass", 0)
        failed = s.get("fail", 0)
        manual = s.get("manual", 0)
        error = s.get("error", 0)
        na = s.get("notapplicable", 0)
        waived = s.get("waived", 0)
        expired_waived = s.get("expired_waived", 0)
        print(f"  Score:           {score:.1f}%")
        print(f"  Hardening index: {idx:.1f}%")
        print(f"  Pass:            {passed}")
        print(f"  Fail:            {failed}")
        print(f"  Manual:          {manual}")
        print(f"  Error:           {error}")
        print(f"  N/A:             {na}")
        if waived:
            print(f"  Waived:          {waived}")
        if expired_waived:
            print(f"  Expired waivers: {expired_waived}")
        if total:
            print(f"  Total:           {total}")
    else:
        applied = s.get("applied", 0)
        pending = s.get("applied_pending", 0)
        already = s.get("already", 0)
        failed = s.get("failed", 0)
        skipped = s.get("skipped_disruptive", 0)
        simulated = s.get("simulated", 0)
        print(f"  Applied:         {applied}")
        print(f"  Pending reboot:  {pending}")
        print(f"  Already ok:      {already}")
        print(f"  Apply failed:    {failed}")
        print(f"  Skipped (risk):  {skipped}")
        if simulated:
            print(f"  Simulated:       {simulated}")
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

    STATUS_SYM = {"pass": "✓", "fail": "✗", "manual": "?", "error": "!", "notapplicable": "-", "waived": "W"}
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

    # Sort by priority (desc) then by ID for actionable ordering
    def _sort_key(r):
        parts = []
        for n in r.get("id", "").split("."):
            try:
                parts.append(int(n))
            except ValueError:
                parts.append(n)
        return (-int(r.get("priority", 1) or 1), parts)

    results = sorted(results, key=_sort_key)

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
        if r.get("waived"):
            title = "[waived] " + title
        if r.get("waiver_expired"):
            title = "[waiver expired] " + title
        if r.get("status_before"):
            title += f" (was {r['status_before']})"

        if status == "fail":
            line = click_style(f"[{symb}]", "red") + f" {rid:<{max_id}}  "
        elif status == "pass":
            line = click_style(f"[{symb}]", "green") + f" {rid:<{max_id}}  "
        elif status == "manual":
            line = click_style(f"[{symb}]", "yellow") + f" {rid:<{max_id}}  "
        elif status == "error":
            line = click_style(f"[{symb}]", "red") + f" {rid:<{max_id}}  "
        elif status == "waived":
            line = click_style(f"[{symb}]", "cyan") + f" {rid:<{max_id}}  "
        else:
            line = f"  [{symb}] {rid:<{max_id}}  "

        line += f"{fam:<{max_fam}}  {title}"
        print(line)

    print(sep)
    counts = {}
    for r in data.get("results", []):
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
    if counts.get("waived"):
        parts.append(click_style(f"W {counts['waived']} waived", "cyan"))
    if counts.get("notapplicable"):
        parts.append(f"- {counts['notapplicable']} n/a")
    print(f"  {'  '.join(parts)}  |  total: {len(data.get('results', []))}")
    print()
