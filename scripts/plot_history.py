#!/usr/bin/env python3
"""Render a trend dashboard from a CIS history JSONL file.

Usage:
    python3 scripts/plot_history.py history.jsonl [output.html]

The output is a self-contained HTML page with SVG line charts — no external
dependencies, CDN, or images.  Filter with --host, --profile, or --mode.
"""

import argparse
import html
import json
import os
import sys
from datetime import datetime, timezone


def parse_iso(ts):
    """Parse an ISO-8601 timestamp string into a datetime."""
    if not ts:
        return None
    try:
        # Python 3.11+ handles most ISO strings directly; fall back for older versions.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_history(path):
    """Load JSONL history and return a list of row dicts."""
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def filter_rows(rows, host=None, profile=None, mode=None):
    out = []
    for r in rows:
        if host and r.get("host") != host:
            continue
        if profile and r.get("profile") != profile:
            continue
        if mode and r.get("mode") != mode:
            continue
        out.append(r)
    return out


def _svg_line(points, width, height, padding):
    """Return SVG path `d` attribute for a series of (x_norm, y_norm) points."""
    if not points:
        return ""
    coords = []
    for xn, yn in points:
        x = padding + xn * (width - 2 * padding)
        y = height - padding - yn * (height - 2 * padding)
        coords.append(f"{x:.1f},{y:.1f}")
    return "M" + " L".join(coords)


def _svg_axes(width, height, padding, x_labels, y_ticks):
    """Return SVG group containing axes and labels."""
    parts = []
    # bottom and left axes
    parts.append(f'<line x1="{padding}" y1="{height - padding}" x2="{width - padding}" y2="{height - padding}" stroke="#cbd5e1" stroke-width="1"/>')
    parts.append(f'<line x1="{padding}" y1="{padding}" x2="{padding}" y2="{height - padding}" stroke="#cbd5e1" stroke-width="1"/>')

    # X labels (max 6)
    if x_labels:
        step = max(1, len(x_labels) // 6)
        for i in range(0, len(x_labels), step):
            xn = i / max(1, len(x_labels) - 1)
            x = padding + xn * (width - 2 * padding)
            label = html.escape(str(x_labels[i]))
            parts.append(f'<text x="{x:.1f}" y="{height - padding + 18}" font-size="10" fill="#64748b" text-anchor="middle">{label}</text>')

    # Y ticks
    for val, frac in y_ticks:
        y = height - padding - frac * (height - 2 * padding)
        parts.append(f'<text x="{padding - 8}" y="{y + 3}" font-size="10" fill="#64748b" text-anchor="end">{html.escape(str(val))}</text>')
        parts.append(f'<line x1="{padding}" y1="{y:.1f}" x2="{width - padding}" y2="{y:.1f}" stroke="#e2e8f0" stroke-width="1" stroke-dasharray="2,2"/>')

    return "\n".join(parts)


def _chart(title, rows, value_key, color, width=500, height=220, padding=36):
    """Render a single SVG line chart from history rows."""
    values = [r.get(value_key, 0) for r in rows]
    labels = [r.get("timestamp", "")[:10] for r in rows]
    if not values:
        return f'<div class="chart"><h3>{html.escape(title)}</h3><p class="empty">No data</p></div>'

    vmin, vmax = min(values), max(values)
    if vmin == vmax:
        vmin, vmax = vmin - 1, vmax + 1
        if vmin < 0:
            vmin = 0

    points = []
    n = len(values)
    for i, v in enumerate(values):
        xn = i / max(1, n - 1)
        yn = (v - vmin) / max(1, vmax - vmin)
        points.append((xn, yn))

    # Y ticks: 5 evenly spaced values
    y_ticks = []
    for i in range(5):
        frac = i / 4.0
        val = vmin + frac * (vmax - vmin)
        if isinstance(val, float):
            val = round(val, 1)
        y_ticks.append((val, frac))

    path_d = _svg_line(points, width, height, padding)
    axes = _svg_axes(width, height, padding, labels, y_ticks)

    # Area fill under the line
    area_d = path_d
    if area_d:
        last = points[-1]
        first = points[0]
        area_d += f" L{padding + last[0] * (width - 2 * padding):.1f},{height - padding:.1f}"
        area_d += f" L{padding + first[0] * (width - 2 * padding):.1f},{height - padding:.1f} Z"

    latest = values[-1]
    if isinstance(latest, float):
        latest = round(latest, 1)

    return f"""<div class="chart">
  <h3>{html.escape(title)} <span class="latest" style="color:{color}">{html.escape(str(latest))}</span></h3>
  <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">
    {axes}
    {f'<path d="{area_d}" fill="{color}" opacity="0.08"/>' if area_d else ''}
    {f'<path d="{path_d}" fill="none" stroke="{color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' if path_d else ''}
    {''.join(f'<circle cx="{padding + xn * (width - 2 * padding):.1f}" cy="{height - padding - yn * (height - 2 * padding):.1f}" r="3" fill="{color}"/>' for xn, yn in points)}
  </svg>
</div>"""


def render_dashboard(rows, outfile):
    """Render the full HTML dashboard."""
    score_chart = _chart("Compliance Score (%)", rows, "score", "#0d7a53")
    fail_chart = _chart("Failed Rules", rows, "fail", "#c42a1e")
    pass_chart = _chart("Passed Rules", rows, "pass", "#1a50ba")
    err_chart = _chart("Errors", rows, "error", "#8b3dd4")

    rows_html = ""
    for r in reversed(rows[-50:]):
        rows_html += (
            f"<tr><td>{html.escape(str(r.get('timestamp', ''))[:19])}</td>"
            f"<td>{html.escape(str(r.get('host', '')))}</td>"
            f"<td>{html.escape(str(r.get('mode', '')))}</td>"
            f"<td>{html.escape(str(r.get('profile', '')))}</td>"
            f"<td>{r.get('score', 0):.1f}%</td>"
            f"<td>{r.get('pass', 0)}</td><td>{r.get('fail', 0)}</td>"
            f"<td>{r.get('error', 0)}</td></tr>\n"
        )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Compliance Trend Dashboard</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       max-width: 1200px; margin: 0 auto; padding: 28px; color: #1a2332; background: #f8f9fa; }}
h1 {{ font-size: 24px; margin-bottom: 8px; }}
h3 {{ font-size: 14px; font-weight: 700; margin: 0 0 12px; color: #334155; display: flex; justify-content: space-between; }}
.sub {{ color: #64748b; font-size: 13px; margin-bottom: 24px; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }}
@media(max-width: 820px) {{ .grid {{ grid-template-columns: 1fr; }} }}
.chart {{ background: #fff; border: 1px solid #e1e6ef; border-radius: 12px; padding: 18px; box-shadow: 0 1px 3px rgba(15,23,42,.04); }}
.latest {{ font-weight: 800; }}
.empty {{ color: #64748b; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e1e6ef; border-radius: 12px; overflow: hidden; font-size: 12.5px; }}
th, td {{ padding: 10px 12px; border-bottom: 1px solid #e2e8f0; text-align: left; }}
th {{ background: #1e3a6e; color: #fff; font-weight: 600; }}
tr:last-child td {{ border-bottom: none; }}
</style>
</head>
<body>
<h1>CIS Compliance Trend Dashboard</h1>
<p class="sub">{len(rows)} scan(s) · generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="grid">
  {score_chart}
  {fail_chart}
  {pass_chart}
  {err_chart}
</div>
<table>
<thead><tr><th>Timestamp</th><th>Host</th><th>Mode</th><th>Profile</th><th>Score</th><th>Pass</th><th>Fail</th><th>Error</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</body>
</html>"""

    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"Trend dashboard written to {outfile} ({len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser(description="Render CIS compliance trend dashboard")
    ap.add_argument("history", help="Path to history JSONL file")
    ap.add_argument("output", nargs="?", help="Output HTML path (default: history.html)")
    ap.add_argument("--host", help="Filter by host")
    ap.add_argument("--profile", help="Filter by profile (L1/L2)")
    ap.add_argument("--mode", help="Filter by mode (scan/apply/audit)")
    args = ap.parse_args()

    if not os.path.exists(args.history):
        print(f"History file not found: {args.history}", file=sys.stderr)
        sys.exit(1)

    rows = load_history(args.history)
    rows = filter_rows(rows, host=args.host, profile=args.profile, mode=args.mode)
    rows.sort(key=lambda r: r.get("timestamp", ""))

    if len(rows) < 2:
        print("Need at least 2 history rows to render a trend.", file=sys.stderr)
        sys.exit(1)

    outfile = args.output or args.history.replace(".jsonl", ".html")
    if outfile == args.history:
        outfile += ".html"
    render_dashboard(rows, outfile)


if __name__ == "__main__":
    main()
