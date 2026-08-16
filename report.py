"""HTML report rendering: turns an engine result JSON into a self-contained
report.html.j2-based report on disk, using the Ansible-mirrored template
context (cis_result, cis_guidance, cis_sections, ohbs_host, ...).
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone

from engine import collect_host


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
        "ohbs_host": host,
        "cis_run_human": now.strftime("%Y-%m-%d %H:%M:%S"),
        "cis_run_stamp": now.strftime("%Y%m%d-%H%M%S"),
        "cis_fleet_size": 1,
        "cis_backup_dir": os.path.abspath(args.backup_dir) if args.backup_dir else "",
        "cis_allow_disruptive": args.allow_disruptive,
        "cis_lang": "en",
        "cis_report_embed_remediation": True,
    }

    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    # The report templates use `| bool` (as they would under Ansible's
    # Jinja2, where it is a built-in filter). Standalone ohbs-host renders
    # with plain Jinja2, which has no `bool` filter -- register one so
    # `ohbs-host scan/apply/audit --format html` does not crash on every
    # report render. (Found by the L4 e2e test.)
    env.filters.setdefault("bool", bool)
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
        shutil.copy2(scan_result_file, json_path)
        print(f"  JSON saved: {json_path}")

    return out_path
