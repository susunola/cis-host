"""Rule info: show single-rule detail from the catalog, either as
formatted CLI text or a standalone HTML page rendered from
templates/rule_info.html.j2.
"""

import os
import sys

from catalog import get_rule_detail
from display import click_style

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATE_PATH = os.path.join(_SCRIPT_DIR, "templates", "rule_info.html.j2")


def render_info_html(detail, args):
    """Generate a single-rule detail HTML page from rule_info.html.j2."""
    from jinja2 import Environment, FileSystemLoader

    detail_with_display = dict(detail)
    detail_with_display["levels_display"] = ", ".join(f"L{x}" for x in detail["levels"])
    ctx = {"detail": detail_with_display}

    template_dir = os.path.dirname(_TEMPLATE_PATH)
    template_name = os.path.basename(_TEMPLATE_PATH)
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template(template_name)
    html_doc = template.render(**ctx)

    os.makedirs(os.path.abspath(args.output), exist_ok=True)
    out_path = os.path.join(os.path.abspath(args.output),
                            f"info-{detail['id'].replace('.', '-')}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"Info HTML saved: {out_path}")
    return out_path


def cmd_info(args):
    """INFO mode: show rule detail by ID, CLI or HTML."""
    rule_id = args.id.strip()
    detail = get_rule_detail(args, rule_id)
    if detail is None:
        print(f"Rule '{rule_id}' not found in catalog.", file=sys.stderr)
        sys.exit(1)

    if args.format == "html":
        return render_info_html(detail, args)

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
