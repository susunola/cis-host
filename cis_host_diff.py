#!/usr/bin/env python3
"""cis-host drift detection, remediation verification and waiver hygiene.

Pure logic layer — no CLI parsing, no subprocess, no I/O beyond what the
caller supplies. Consumed by cis_cli.py (CLI wiring) and exercised directly
by the unit tests in tests/test_drift.py.

Industry provenance:
  * diff / drift detection   — OpenSCAP `oscap xccdf compare`, Wazuh SCA
  * apply + verify           — dev-sec hardening (remediate + re-audit)
  * waiver expiry & audit    — Chef InSpec "exceptions as code"
  * change-only alerting     — Wazuh SCA (only surface state transitions)
"""

from __future__ import annotations

import html
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

# ─── Change categories ────────────────────────────────────────────────

NEW_FAIL = "new_fail"        # was passing, now failing          → drift
REGRESSED = "regressed"      # was compliant, broke by apply     → drift
RECOVERED = "recovered"      # was failing, now passing          → improvement
STILL_FAIL = "still_fail"    # failing before and after          → unresolved
NOW_WAIVED = "now_waived"    # newly exempted                    → exception
UNWAIVED = "unwaived"        # exception lifted                  → attention
NEW_PASS = "new_pass"        # was non-pass (manual/na), now pass
BEFORE_ONLY = "before_only"  # present only in the baseline scan
AFTER_ONLY = "after_only"    # present only in the latest scan

CATEGORIES: Tuple[str, ...] = (
    NEW_FAIL, REGRESSED, RECOVERED, STILL_FAIL,
    NOW_WAIVED, UNWAIVED, NEW_PASS, BEFORE_ONLY, AFTER_ONLY,
)

# Severity used for report badge coloring and gating decisions.
SEVERITY: Dict[str, str] = {
    NEW_FAIL: "critical",
    REGRESSED: "critical",
    STILL_FAIL: "warning",
    UNWAIVED: "warning",
    NOW_WAIVED: "info",
    RECOVERED: "info",
    NEW_PASS: "info",
    BEFORE_ONLY: "info",
    AFTER_ONLY: "info",
}

DRIFT_CATEGORIES = frozenset({NEW_FAIL, REGRESSED, STILL_FAIL})

# ─── Result document helpers ──────────────────────────────────────────


def _result_status(r: Any) -> str:
    """Effective status of a rule result dict (None-safe)."""
    if not isinstance(r, dict):
        return "?"
    return str(r.get("status", "?"))


def _is_failing(status: str) -> bool:
    return status in ("fail", "error")


def _waived(r: Any) -> bool:
    """True when a rule result is waived.

    Real engine output sets both `waived: true` and `status: "waived"`, but
    either form may appear on its own; accept both so any producer works.
    """
    if not isinstance(r, dict):
        return False
    return bool(r.get("waived")) or r.get("status") == "waived"


def _rule_title(r: Any) -> str:
    return str(r.get("title", "") or "") if isinstance(r, dict) else ""


def _rule_meta(r: Any) -> Dict[str, Any]:
    """Return metadata worth carrying into reports (family, section...)."""
    if not isinstance(r, dict):
        return {}
    out: Dict[str, Any] = {}
    for k in ("family", "section", "section_title", "action_id"):
        if r.get(k):
            out[k] = r[k]
    return out


# ─── Data model ───────────────────────────────────────────────────────


@dataclass
class RuleChange:
    """A single rule whose state changed (or stayed failing) between scans."""

    rule_id: str
    category: str
    status: str                  # status in the newer document
    previous_status: Optional[str] = None
    title: str = ""
    severity: str = field(init=False)
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = SEVERITY.get(self.category, "info")


@dataclass
class Snapshot:
    """Normalized summary of one scan result document."""

    score: float = 0.0
    hardening_index: float = 0.0
    fail: int = 0
    started_at: str = ""
    hostname: str = ""
    os: str = ""
    profile: str = ""
    benchmark: str = ""

    @classmethod
    def from_document(cls, doc: Dict[str, Any]) -> "Snapshot":
        summary = (doc.get("summary") or {}).get("all") or {}
        host = doc.get("host") or {}
        try:
            score = float(summary.get("score", 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        try:
            index = float(summary.get("hardening_index", 0.0) or 0.0)
        except (TypeError, ValueError):
            index = 0.0
        return cls(
            score=score,
            hardening_index=index,
            fail=int(summary.get("fail", 0) or 0),
            started_at=str(doc.get("started_at", "") or ""),
            hostname=str((host if isinstance(host, dict) else {}).get("hostname", "") or ""),
            os=str((host if isinstance(host, dict) else {}).get("os", "") or doc.get("os", "") or ""),
            profile=str(doc.get("profile", "") or ""),
            benchmark=str(doc.get("benchmark", "") or doc.get("name", "") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DriftReport:
    """Result of comparing two scan documents."""

    before: Snapshot
    after: Snapshot
    changes: Dict[str, List[RuleChange]]
    warnings: List[str] = field(default_factory=list)
    score_delta: float = field(init=False)

    def __post_init__(self) -> None:
        self.score_delta = round(self.after.score - self.before.score, 1)

    # ── convenience accessors ──

    def has_drift(self) -> bool:
        return any(self.changes.get(c) for c in (NEW_FAIL, REGRESSED, STILL_FAIL))

    def drift_count(self) -> int:
        return sum(len(self.changes.get(c, [])) for c in (NEW_FAIL, REGRESSED, STILL_FAIL))

    def total_changed(self) -> int:
        return sum(len(v) for v in self.changes.values())

    def counts(self) -> Dict[str, int]:
        return {cat: len(self.changes.get(cat, [])) for cat in CATEGORIES}

    # ── serialization ──

    def to_dict(self) -> Dict[str, Any]:
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "score_delta": self.score_delta,
            "has_drift": self.has_drift(),
            "drift_count": self.drift_count(),
            "warnings": self.warnings,
            "changes": {cat: [asdict(c) for c in self.changes.get(cat, [])]
                        for cat in CATEGORIES},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


# ─── Diff engine ──────────────────────────────────────────────────────


def _index_results(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index a result document by rule id, keeping insertion order."""
    index: Dict[str, Dict[str, Any]] = {}
    for r in doc.get("results", []):
        if isinstance(r, dict) and r.get("id") is not None:
            index[str(r["id"])] = r
    return index


def _sort_changes(items: Iterable[RuleChange]) -> List[RuleChange]:
    """Deterministic ordering by numeric rule id (1.1.1.1 < 2.1.1 < 10.1.1),
    falling back to the raw string for non-numeric ids."""
    def key(c: RuleChange) -> Tuple[Tuple[int, ...], str]:
        numeric: List[int] = []
        for p in c.rule_id.replace("-", ".").split("."):
            try:
                numeric.append(int(p))
            except ValueError:
                numeric.append(0)
        return (tuple(numeric), c.rule_id)
    return sorted(items, key=key)


def compatibility_warnings(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """Warn when the two documents do not describe the same target/profile.

    Comparing results from different operating systems or profiles would
    produce a misleading drift report; we surface that loudly instead of
    silently mixing rule spaces.
    """
    warnings: List[str] = []

    def _os(doc: Dict[str, Any]) -> str:
        host = doc.get("host") or {}
        return str((host if isinstance(host, dict) else {}).get("os", "") or doc.get("os", "") or "")

    def _profile(doc: Dict[str, Any]) -> str:
        return str(doc.get("profile", "") or "")

    b_os, a_os = _os(before), _os(after)
    if b_os and a_os and b_os != a_os:
        warnings.append(f"different OS: baseline '{b_os}' vs latest '{a_os}'")

    b_prof, a_prof = _profile(before), _profile(after)
    if b_prof and a_prof and b_prof != a_prof:
        warnings.append(f"different profile: baseline '{b_prof}' vs latest '{a_prof}'")

    return warnings


def diff_results(before: Dict[str, Any], after: Dict[str, Any]) -> DriftReport:
    """Classify per-rule changes between two scan result documents.

    Rules are matched by id. Waiving a rule is reported separately from its
    status, so an exception is not double-counted as drift.
    """
    b_map, a_map = _index_results(before), _index_results(after)

    changes: Dict[str, List[RuleChange]] = {cat: [] for cat in CATEGORIES}

    for rid in a_map:
        ar, br = a_map[rid], b_map.get(rid)
        a_stat, b_stat = _result_status(ar), _result_status(br)
        a_w, b_w = _waived(ar), _waived(br)

        if br is None:
            changes[AFTER_ONLY].append(RuleChange(
                rid, AFTER_ONLY, a_stat, None, _rule_title(ar), meta=_rule_meta(ar)))
            continue

        if a_w and not b_w:
            changes[NOW_WAIVED].append(RuleChange(
                rid, NOW_WAIVED, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))
        if b_w and not a_w:
            changes[UNWAIVED].append(RuleChange(
                rid, UNWAIVED, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))

        # Status comparison only for rules not waived on either side.
        if a_w or b_w:
            continue
        if _is_failing(a_stat) and not _is_failing(b_stat):
            changes[NEW_FAIL].append(RuleChange(
                rid, NEW_FAIL, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))
        elif _is_failing(b_stat) and not _is_failing(a_stat):
            changes[RECOVERED].append(RuleChange(
                rid, RECOVERED, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))
        elif _is_failing(a_stat) and _is_failing(b_stat):
            changes[STILL_FAIL].append(RuleChange(
                rid, STILL_FAIL, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))
        elif a_stat == "pass" and b_stat != "pass":
            changes[NEW_PASS].append(RuleChange(
                rid, NEW_PASS, a_stat, b_stat, _rule_title(ar), meta=_rule_meta(ar)))

    for rid in b_map:
        if rid not in a_map:
            br = b_map[rid]
            changes[BEFORE_ONLY].append(RuleChange(
                rid, BEFORE_ONLY, _result_status(br), None, _rule_title(br),
                meta=_rule_meta(br)))

    # Deterministic ordering in every channel (CLI, HTML and JSON alike).
    changes = {cat: _sort_changes(lst) for cat, lst in changes.items()}

    return DriftReport(
        before=Snapshot.from_document(before),
        after=Snapshot.from_document(after),
        changes=changes,
        warnings=compatibility_warnings(before, after),
    )


# ─── Apply verification ───────────────────────────────────────────────


@dataclass
class VerifyReport:
    """Post-apply verification: what remediation actually changed."""

    fixed: List[RuleChange] = field(default_factory=list)
    still_fail: List[RuleChange] = field(default_factory=list)
    regressed: List[RuleChange] = field(default_factory=list)
    waived: List[RuleChange] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.fixed or self.still_fail or self.regressed or self.waived)

    def counts(self) -> Dict[str, int]:
        return {"fixed": len(self.fixed), "still_fail": len(self.still_fail),
                "regressed": len(self.regressed), "waived": len(self.waived)}

    def to_dict(self) -> Dict[str, Any]:
        return {"fixed": [asdict(c) for c in self.fixed],
                "still_fail": [asdict(c) for c in self.still_fail],
                "regressed": [asdict(c) for c in self.regressed],
                "waived": [asdict(c) for c in self.waived]}


def verify_remediation(pre: Optional[Dict[str, Any]],
                       post: Dict[str, Any]) -> VerifyReport:
    """Compare pre- and post-apply scans.

    * fixed      — was failing, now passing (remediation worked)
    * still_fail — was failing, still failing (remediation ineffective)
    * regressed  — was passing, now failing (remediation broke something)
    * waived     — newly exempted by waiver

    A missing pre-scan (e.g. --no-prescan) yields an empty report; callers
    should surface "no baseline, cannot verify" on their own.
    """
    if pre is None:
        return VerifyReport(warnings=["no pre-scan baseline; verification skipped"])

    pre_map = _index_results(pre)
    report = VerifyReport()

    for r in post.get("results", []):
        if not isinstance(r, dict) or r.get("id") is None:
            continue
        rid = str(r["id"])
        post_stat = _result_status(r)
        if _waived(r):
            if not _waived(pre_map.get(rid, {})):
                report.waived.append(RuleChange(
                    rid, NOW_WAIVED, post_stat, _result_status(pre_map.get(rid, {})),
                    _rule_title(r), meta=_rule_meta(r)))
            continue

        pre_stat = _result_status(pre_map.get(rid, {}))
        if _is_failing(pre_stat) and post_stat == "pass":
            report.fixed.append(RuleChange(
                rid, RECOVERED, post_stat, pre_stat, _rule_title(r), meta=_rule_meta(r)))
        elif _is_failing(pre_stat) and _is_failing(post_stat):
            report.still_fail.append(RuleChange(
                rid, STILL_FAIL, post_stat, pre_stat, _rule_title(r), meta=_rule_meta(r)))
        elif not _is_failing(pre_stat) and _is_failing(post_stat):
            report.regressed.append(RuleChange(
                rid, REGRESSED, post_stat, pre_stat, _rule_title(r), meta=_rule_meta(r)))

    return report


# ─── Waiver hygiene ───────────────────────────────────────────────────


@dataclass
class WaiverEntry:
    rule_id: str
    reason: str
    approved_by: str = ""
    expires: str = ""
    status: str = "active"       # active | expired | invalid-date
    in_catalog: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_waiver_entries(waivers: Any) -> Dict[str, Dict[str, Any]]:
    """Normalize waiver input (dict or JSON string) into rule-id → metadata.

    Both legacy and structured forms are accepted:
        {"1.1.1.1": "reason string"}
        {"1.1.1.1": {"reason": "...", "approved_by": "...", "expires": "2026-12-31"}}
    Returns {} for anything unusable.
    """
    if waivers is None:
        return {}
    if isinstance(waivers, str):
        try:
            waivers = json.loads(waivers)
        except (json.JSONDecodeError, TypeError):
            return {}
    if not isinstance(waivers, dict):
        return {}
    return {str(rid): (entry if isinstance(entry, dict) else {"reason": str(entry)})
            for rid, entry in waivers.items()}


def audit_waivers(waivers: Any, catalog_ids: Optional[Set[str]] = None) -> List[WaiverEntry]:
    """Produce a structured, audit-ready view of every waiver.

    Each entry carries its reason, approver, expiry and a computed status
    (active / expired / invalid-date), plus whether the referenced rule id
    exists in the catalog — a typo'd waiver id silently disables the
    exception forever, so we surface it.
    """
    today = datetime.now().date()
    entries: List[WaiverEntry] = []
    for rid, meta in _parse_waiver_entries(waivers).items():
        expires = str(meta.get("expires", "") or "")
        status = "active"
        if expires:
            try:
                exp = datetime.strptime(expires, "%Y-%m-%d").date()
                if exp < today:
                    status = "expired"
            except ValueError:
                status = "invalid-date"
        in_catalog = True
        if catalog_ids is not None:
            in_catalog = rid in catalog_ids
        entries.append(WaiverEntry(
            rule_id=rid,
            reason=str(meta.get("reason", "") or ""),
            approved_by=str(meta.get("approved_by", "") or ""),
            expires=expires,
            status=status,
            in_catalog=in_catalog,
        ))
    return entries


def waiver_problems(waivers: Any,
                    catalog_ids: Optional[Set[str]] = None) -> List[str]:
    """Return human-readable problems for expired / invalid waivers.

    Used at scan time to warn on stderr; does not block execution (the
    engine still honours the waiver).
    """
    problems: List[str] = []
    for entry in audit_waivers(waivers, catalog_ids):
        if entry.status == "expired":
            approver = f" (approved by {entry.approved_by})" if entry.approved_by else ""
            problems.append(
                f"rule {entry.rule_id}: waiver EXPIRED on {entry.expires}{approver}")
        elif entry.status == "invalid-date":
            problems.append(
                f"rule {entry.rule_id}: invalid expires '{entry.expires}' (want YYYY-MM-DD)")
        if not entry.in_catalog:
            problems.append(
                f"rule {entry.rule_id}: waived rule not found in catalog — "
                f"exception is a no-op, check the rule id")
    return problems


# ─── CLI rendering ────────────────────────────────────────────────────

_STYLE = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
          "cyan": "\033[36m", "dim": "\033[2m", "reset": "\033[0m"}


def _c(text: str, color: Optional[str] = None) -> str:
    if not color or os.environ.get("NO_COLOR"):
        return text
    return f"{_STYLE[color]}{text}{_STYLE['reset']}"


def render_cli(report: DriftReport) -> str:
    """Human-readable drift summary for terminal output."""
    ch, before, after = report.changes, report.before, report.after
    lines: List[str] = []
    lines.append("=" * 60)
    target = after.hostname or before.hostname or "?"
    lines.append(f"  Drift: {target}")
    lines.append(f"  Before: {before.started_at or '?'}  score={before.score:.1f}%  fail={before.fail}")
    lines.append(f"  After:  {after.started_at or '?'}  score={after.score:.1f}%  fail={after.fail}")
    lines.append(f"  Score delta: {report.score_delta:+.1f}%")
    if report.warnings:
        for w in report.warnings:
            lines.append(f"  {_c('!', 'yellow')} {w}")
    lines.append("=" * 60)

    def dump(label: str, items: List[RuleChange], color: Optional[str] = None,
             limit: int = 50) -> None:
        if not items:
            return
        lines.append("")
        lines.append(f"  {_c(label, color) if color else label} ({len(items)})")
        for c in _sort_changes(items)[:limit]:
            marker = _c("✗", "red") if c.severity == "critical" else " "
            lines.append(f"    {marker} {c.rule_id}  {c.title[:70]}")
        if len(items) > limit:
            lines.append(f"    ... and {len(items) - limit} more")

    dump("NEW FAILURES (drift)", ch.get(NEW_FAIL, []), "red")
    dump("REGRESSED after apply", ch.get(REGRESSED, []), "red")
    dump("Recovered", ch.get(RECOVERED, []), "green")
    dump("Still failing", ch.get(STILL_FAIL, []))
    dump("Now waived", ch.get(NOW_WAIVED, []), "cyan")
    dump("No longer waived", ch.get(UNWAIVED, []), "yellow")
    dump("Now passing", ch.get(NEW_PASS, []), "green")
    dump("Only in baseline", ch.get(BEFORE_ONLY, []))
    dump("Only in latest", ch.get(AFTER_ONLY, []))

    lines.append("")
    lines.append(f"  Changed rules: {report.total_changed()}  |  "
                 f"drift: {report.drift_count()}")
    lines.append("=" * 60)
    return "\n".join(lines)


def render_html(report: DriftReport, *, name: str = "CIS Benchmark",
                profile: str = "", org: str = "") -> str:
    """Self-contained HTML drift report (no external assets)."""
    ch = report.changes
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    delta = report.score_delta

    def section(label: str, items: List[RuleChange]) -> str:
        if not items:
            return ""
        rows = "".join(
            f'<tr class="sev-{c.severity}">'
            f'<td><code>{html.escape(c.rule_id)}</code></td>'
            f'<td>{html.escape(c.title[:90])}</td>'
            f'<td><span class="badge b-{c.severity}">{c.severity}</span></td>'
            f'<td>{html.escape(c.previous_status or "—")} → '
            f'{html.escape(c.status)}</td></tr>'
            for c in _sort_changes(items))
        return (f'<h3>{html.escape(label)} <span class="count">({len(items)})</span></h3>'
                f'<table><thead><tr><th>ID</th><th>Rule</th><th>Severity</th>'
                f'<th>Status change</th></tr></thead><tbody>{rows}</tbody></table>')

    sections = "".join([
        section("New failures (drift)", ch.get(NEW_FAIL, [])),
        section("Regressed after apply", ch.get(REGRESSED, [])),
        section("Recovered", ch.get(RECOVERED, [])),
        section("Still failing", ch.get(STILL_FAIL, [])),
        section("Now waived", ch.get(NOW_WAIVED, [])),
        section("No longer waived", ch.get(UNWAIVED, [])),
        section("Now passing", ch.get(NEW_PASS, [])),
        section("Only in baseline", ch.get(BEFORE_ONLY, [])),
        section("Only in latest", ch.get(AFTER_ONLY, [])),
    ])

    warnings_html = ""
    if report.warnings:
        warnings_html = '<div class="warnbox">' + "".join(
            f'<p>⚠ {html.escape(w)}</p>' for w in report.warnings) + "</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Configuration Drift Report — {html.escape(name)}</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       max-width: 1100px; margin: 40px auto; padding: 0 20px;
       color: #1a2332; background: #f8f9fa; }}
h1 {{ font-size: 24px; }} h3 {{ font-size: 16px; margin: 28px 0 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; }}
th, td {{ padding: 8px 10px; border: 1px solid #e1e6ef; text-align: left; font-size: 13px; }}
th {{ background: #1e3a6e; color: #fff; }} tr:nth-child(even) {{ background: #f8f9fa; }}
code {{ background: #eef1f6; padding: 1px 5px; border-radius: 4px; }}
.badge {{ padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }}
.b-critical {{ background: #fde8e8; color: #c42a1e; }}
.b-warning {{ background: #fdf3d7; color: #9a6b00; }}
.b-info {{ background: #e4f4ec; color: #0d7a53; }}
tr.sev-critical td {{ background: #fff5f5; }}
.count {{ color: #64748b; font-weight: 400; }}
.summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #e1e6ef; border-radius: 8px;
        padding: 12px 18px; min-width: 140px; }}
.card .num {{ font-size: 22px; font-weight: 700; }}
.card .lbl {{ font-size: 12px; color: #64748b; }}
.delta-up {{ color: #0d7a53; }} .delta-down {{ color: #c42a1e; }}
.warnbox {{ background: #fdf3d7; border: 1px solid #f0d28a; border-radius: 8px;
           padding: 10px 16px; margin: 16px 0; font-size: 13px; }}
.filter {{ margin: 16px 0; }}
.filter input {{ padding: 8px 12px; width: 280px; border: 1px solid #cbd5e1;
                 border-radius: 6px; font-size: 14px; }}
</style>
</head>
<body>
<h1>Configuration Drift Report</h1>
<p><strong>{html.escape(name)}</strong> · Profile {html.escape(profile or "—")}{(" · " + html.escape(org)) if org else ""}</p>
{warnings_html}
<div class="summary">
  <div class="card"><div class="num">{report.before.score:.1f}%</div><div class="lbl">Baseline score</div></div>
  <div class="card"><div class="num {'delta-up' if delta >= 0 else 'delta-down'}">{delta:+.1f}%</div><div class="lbl">Score delta</div></div>
  <div class="card"><div class="num">{len(ch.get(NEW_FAIL, [])) + len(ch.get(REGRESSED, []))}</div><div class="lbl">Drift (new/regressed)</div></div>
  <div class="card"><div class="num">{len(ch.get(STILL_FAIL, []))}</div><div class="lbl">Still failing</div></div>
  <div class="card"><div class="num">{len(ch.get(RECOVERED, []))}</div><div class="lbl">Recovered</div></div>
</div>
<div class="filter"><input id="f" type="text" placeholder="Filter by rule id or title…"></div>
{sections}
<script>
(function () {{
  var input = document.getElementById("f");
  input.addEventListener("input", function () {{
    var q = input.value.toLowerCase();
    document.querySelectorAll("tbody tr").forEach(function (tr) {{
      tr.style.display = tr.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none";
    }});
  }});
}})();
</script>
<p style="color:#94a3b8; font-size:12px; margin-top:32px;">Generated {generated} · cis-host</p>
</body>
</html>"""


def render_verify_html(verify: VerifyReport, *, name: str = "CIS Benchmark",
                       profile: str = "", org: str = "") -> str:
    """Self-contained HTML verification report for apply mode."""
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")

    def section(label: str, items: List[RuleChange], sev: str) -> str:
        if not items:
            return ""
        rows = "".join(
            f'<tr><td><code>{html.escape(c.rule_id)}</code></td>'
            f'<td>{html.escape(c.title[:90])}</td>'
            f'<td><span class="badge b-{sev}">{sev}</span></td></tr>'
            for c in _sort_changes(items))
        return (f'<h3>{html.escape(label)} <span class="count">({len(items)})</span></h3>'
                f'<table><thead><tr><th>ID</th><th>Rule</th><th>Category</th>'
                f'</tr></thead><tbody>{rows}</tbody></table>')

    sections = "".join([
        section("Fixed by apply", verify.fixed, "info"),
        section("Still failing", verify.still_fail, "warning"),
        section("Regressed (broken by apply)", verify.regressed, "critical"),
        section("Newly waived", verify.waived, "info"),
    ])
    c = verify.counts()
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Apply Verification Report — {html.escape(name)}</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       max-width: 1100px; margin: 40px auto; padding: 0 20px;
       color: #1a2332; background: #f8f9fa; }}
h1 {{ font-size: 24px; }} h3 {{ font-size: 16px; margin: 28px 0 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; background: #fff; }}
th, td {{ padding: 8px 10px; border: 1px solid #e1e6ef; text-align: left; font-size: 13px; }}
th {{ background: #1e3a6e; color: #fff; }} tr:nth-child(even) {{ background: #f8f9fa; }}
code {{ background: #eef1f6; padding: 1px 5px; border-radius: 4px; }}
.badge {{ padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }}
.b-critical {{ background: #fde8e8; color: #c42a1e; }}
.b-warning {{ background: #fdf3d7; color: #9a6b00; }}
.b-info {{ background: #e4f4ec; color: #0d7a53; }}
.count {{ color: #64748b; font-weight: 400; }}
.summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
.card {{ background: #fff; border: 1px solid #e1e6ef; border-radius: 8px;
        padding: 12px 18px; min-width: 130px; }}
.card .num {{ font-size: 22px; font-weight: 700; }}
.card .lbl {{ font-size: 12px; color: #64748b; }}
.warnbox {{ background: #fdf3d7; border: 1px solid #f0d28a; border-radius: 8px;
           padding: 10px 16px; margin: 16px 0; font-size: 13px; }}
</style>
</head>
<body>
<h1>Apply Verification Report</h1>
<p><strong>{html.escape(name)}</strong> · Profile {html.escape(profile or "—")}{(" · " + html.escape(org)) if org else ""}</p>
{'<div class="warnbox">⚠ ' + html.escape(verify.warnings[0]) + "</div>" if verify.warnings else ""}
<div class="summary">
  <div class="card"><div class="num">{c["fixed"]}</div><div class="lbl">Fixed</div></div>
  <div class="card"><div class="num">{c["still_fail"]}</div><div class="lbl">Still failing</div></div>
  <div class="card"><div class="num">{c["regressed"]}</div><div class="lbl">Regressed</div></div>
  <div class="card"><div class="num">{c["waived"]}</div><div class="lbl">Newly waived</div></div>
</div>
{sections}
<p style="color:#94a3b8; font-size:12px; margin-top:32px;">Generated {generated} · cis-host</p>
</body>
</html>"""


# ─── Periodic watch (change-only alerting) ────────────────────────────
#
# Inspired by Wazuh SCA: an agent-style loop that scans on an interval and
# ONLY surfaces state transitions. A quiet run prints a single line; a
# drifted run emits a drift event (and optionally fires an alert command).
# The same drift rule is never re-alerted until it clears — otherwise a
# persistent failure would page the on-call every interval.

WatchScan = Callable[[], Dict[str, Any]]


class WatchSession:
    """Periodic scanner with de-duplicated, change-only drift alerting.

    Events (dicts) are delivered to `on_event`; the default renderer prints
    one JSON line per event when `json_events` is set, otherwise compact
    human text. Drift alerting is edge-triggered: a rule is alerted when it
    enters the drifting set and reported as cleared when it leaves.
    """

    def __init__(
        self,
        scan: WatchScan,
        *,
        interval: int = 3600,
        max_runs: int = 0,
        baseline: Optional[Dict[str, Any]] = None,
        alert: Optional[Callable[[Dict[str, Any]], None]] = None,
        json_events: bool = False,
        output_dir: str = "",
        name: str = "CIS Benchmark",
        profile: str = "L1",
        org: str = "",
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.scan = scan
        self.interval = max(int(interval), 1)
        self.max_runs = max(int(max_runs), 0)
        self.baseline = baseline
        self.alert = alert
        self.json_events = json_events
        self.output_dir = output_dir
        self.name = name
        self.profile = profile
        self.org = org
        self.on_event = on_event or self._default_emit
        self._alerted: Set[str] = set()
        self._last: Optional[Dict[str, Any]] = baseline

    # ── lifecycle ──

    def run(self) -> int:
        """Run the watch loop until max_runs or interrupted.

        Returns the number of completed scans. Raises nothing: scan errors
        become 'error' events and the loop continues.
        """
        runs = 0
        self._emit({"type": "start", "interval": self.interval,
                    "max_runs": self.max_runs, "profile": self.profile})
        try:
            while self.max_runs == 0 or runs < self.max_runs:
                runs += 1
                self._emit({"type": "scan-start", "run": runs})
                try:
                    data = self.scan()
                except Exception as exc:  # noqa: BLE001 — watch must survive
                    self._emit({"type": "error", "run": runs,
                                "message": str(exc)})
                    self._fire_alert({"type": "error", "run": runs,
                                      "message": str(exc)})
                    if self.max_runs > 0 and runs >= self.max_runs:
                        break
                    self._sleep()
                    continue

                self._on_scan(data, runs)
                if self.max_runs > 0 and runs >= self.max_runs:
                    break
                self._sleep()
        except KeyboardInterrupt:
            self._emit({"type": "stop", "runs": runs,
                        "reason": "interrupted"})
            return runs
        self._emit({"type": "stop", "runs": runs, "reason": "completed"})
        return runs

    # ── internals ──

    def _on_scan(self, data: Dict[str, Any], runs: int) -> None:
        """Emit a scan event, diff against the previous result, alert on
        state transitions only."""
        if self._last is None:
            self._last = data
            self._emit_scan_event(data, runs, drift=False, changed=0)
            self._persist(data, runs)
            return

        report = diff_results(self._last, data)
        self._last = data
        self._persist(data, runs)

        # Edge-triggered alerting: `alerted` tracks rules currently failing
        # AND already alerted. A rule stays alerted while it keeps failing
        # (no repeat pages), and only clears once it is no longer failing.
        fresh = {c.rule_id for c in report.changes[NEW_FAIL]} | \
                {c.rule_id for c in report.changes[REGRESSED]}
        still_failing = fresh | {c.rule_id for c in report.changes[STILL_FAIL]}
        cleared = self._alerted - still_failing
        newly_alerted = fresh - self._alerted
        self._alerted = (self._alerted & still_failing) | newly_alerted

        changed = report.total_changed()
        self._emit_scan_event(data, runs, drift=bool(newly_alerted), changed=changed)

        for rid in sorted(newly_alerted):
            self._emit({"type": "drift", "run": runs, "rule_id": rid})
        for rid in sorted(cleared):
            self._emit({"type": "clear", "run": runs, "rule_id": rid})

        if newly_alerted or cleared or report.drift_count():
            self._emit({"type": "summary", "run": runs,
                        "drift": report.drift_count(),
                        "new_fail": len(report.changes[NEW_FAIL]),
                        "regressed": len(report.changes[REGRESSED]),
                        "still_fail": len(report.changes[STILL_FAIL]),
                        "recovered": len(report.changes[RECOVERED]),
                        "score": round(report.after.score, 1),
                        "score_delta": report.score_delta})

        if newly_alerted:
            self._fire_alert({"type": "drift", "run": runs,
                              "rule_ids": sorted(newly_alerted),
                              "drift_count": report.drift_count(),
                              "score": round(report.after.score, 1)})

    def _emit_scan_event(self, data: Dict[str, Any], runs: int, *,
                         drift: bool, changed: int) -> None:
        snap = Snapshot.from_document(data)
        self._emit({"type": "scan", "run": runs, "score": round(snap.score, 1),
                    "fail": snap.fail, "drift": drift, "changed": changed,
                    "started_at": snap.started_at})

    def _emit(self, event: Dict[str, Any]) -> None:
        self.on_event(event)

    def _fire_alert(self, event: Dict[str, Any]) -> None:
        if self.alert is not None:
            try:
                self.alert(event)
            except Exception as exc:  # never let alerting kill the loop
                self._emit({"type": "error", "message": f"alert failed: {exc}"})

    def _sleep(self) -> None:
        if self.interval > 0:
            time.sleep(self.interval)

    def _persist(self, data: Dict[str, Any], runs: int) -> None:
        if not self.output_dir:
            return
        os.makedirs(self.output_dir, exist_ok=True)
        path = os.path.join(self.output_dir, f"watch-run-{runs:04d}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    def _default_emit(self, event: Dict[str, Any]) -> None:
        if self.json_events:
            print(json.dumps(event, ensure_ascii=False))
            return
        etype = event.get("type")
        if etype == "start":
            print(f"watch: interval={event['interval']}s max_runs={event['max_runs']}")
        elif etype == "scan-start":
            print(f"  scan #{event['run']} ...", end="", flush=True)
        elif etype == "scan":
            tag = "DRIFT" if event.get("drift") else "ok"
            print(f" score={event['score']:.1f}% fail={event['fail']} "
                  f"changed={event['changed']} [{tag}]")
        elif etype == "drift":
            print(f"  ⚠ drift: {event.get('rule_id', event.get('rule_ids'))}")
        elif etype == "clear":
            print(f"  ✓ cleared: {event['rule_id']}")
        elif etype == "summary":
            print(f"  summary: drift={event['drift']} new={event['new_fail']} "
                  f"regressed={event['regressed']} still={event['still_fail']} "
                  f"recovered={event['recovered']} score={event['score']:.1f}% "
                  f"({event['score_delta']:+.1f}%)")
        elif etype == "error":
            print(f"  ✗ error: {event.get('message', '?')}")
        elif etype == "stop":
            print(f"watch: stopped after {event['runs']} runs ({event['reason']})")
