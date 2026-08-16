#!/usr/bin/env python3
"""Convert an XCCDF 1.2 tailoring file into a ohbs-host.toml skeleton.

Usage:
    python3 scripts/import_tailoring.py tailoring.xml [ohbs-host.toml]

The output is a starter ohbs-host.toml containing [profile], [rules], [variables],
and [waivers] sections inferred from the tailoring content.
"""

import argparse
import json
import os
import re
import sys
from xml.etree.ElementTree import parse

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"


def _strip_ns(tag):
    """Remove XML namespace from a tag."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _rule_id(idref):
    """Extract the CIS-style rule ID from an XCCDF idref."""
    prefix = "xccdf_ohbs-host_rule_"
    if idref.startswith(prefix):
        return idref[len(prefix):]
    return idref


def _value_id(idref):
    """Extract the variable name from an XCCDF value idref."""
    prefix = "xccdf_ohbs-host_value_"
    if idref.startswith(prefix):
        return idref[len(prefix):]
    return idref


def import_tailoring(path):
    tree = parse(path)
    root = tree.getroot()

    cfg = {"profile": {}, "rules": {}, "variables": {}, "waivers": {}}

    profile = root.find("{%s}Profile" % XCCDF_NS)
    if profile is None:
        return cfg

    title = profile.find("{%s}title" % XCCDF_NS)
    if title is not None and title.text:
        cfg["profile"]["name"] = title.text

    include_ids = []
    exclude_ids = []

    for child in profile:
        tag = _strip_ns(child.tag)
        if tag == "refined-value":
            idref = child.get("idref", "")
            selector = child.get("selector", "")
            if idref.endswith("_waiver"):
                rid = idref[len("xccdf_ohbs-host_rule_"):-len("_waiver")]
                cfg["waivers"][rid] = selector
                continue
            var_name = _value_id(idref)
            if var_name and selector:
                # Try to keep numbers as numbers
                try:
                    cfg["variables"][var_name] = int(selector)
                except ValueError:
                    try:
                        cfg["variables"][var_name] = float(selector)
                    except ValueError:
                        cfg["variables"][var_name] = selector
        elif tag == "select":
            rid = _rule_id(child.get("idref", ""))
            selected = child.get("selected", "true").lower()
            if selected == "true":
                include_ids.append(rid)
            else:
                exclude_ids.append(rid)

    if include_ids:
        cfg["rules"]["include"] = include_ids
    if exclude_ids:
        cfg["rules"]["exclude"] = exclude_ids

    return cfg


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value))


def render_toml(cfg):
    lines = ["# Generated from XCCDF tailoring file", ""]
    if cfg.get("profile"):
        lines.append("[profile]")
        for k, v in cfg["profile"].items():
            lines.append(f'{k} = {_toml_value(v)}')
        lines.append("")
    if cfg.get("rules"):
        lines.append("[rules]")
        for k, v in cfg["rules"].items():
            if isinstance(v, list):
                items = ", ".join(json.dumps(str(x)) for x in v)
                lines.append(f'{k} = [{items}]')
            else:
                lines.append(f'{k} = {_toml_value(v)}')
        lines.append("")
    if cfg.get("variables"):
        lines.append("[variables]")
        for k, v in cfg["variables"].items():
            lines.append(f'{k} = {_toml_value(v)}')
        lines.append("")
    if cfg.get("waivers"):
        lines.append("[waivers]")
        for k, v in cfg["waivers"].items():
            val = _toml_value(v)
            # Quoted keys for dotted rule IDs
            lines.append(f'"{k}" = {val}')
        lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Import XCCDF tailoring file as ohbs-host.toml")
    ap.add_argument("tailoring", help="Path to XCCDF tailoring XML")
    ap.add_argument("output", nargs="?", help="Output TOML path (default: ohbs-host-tailoring.toml)")
    args = ap.parse_args()

    if not os.path.exists(args.tailoring):
        print(f"Tailoring file not found: {args.tailoring}", file=sys.stderr)
        sys.exit(1)

    cfg = import_tailoring(args.tailoring)
    out = args.output or args.tailoring.replace(".xml", ".toml")
    if out == args.tailoring:
        out += ".toml"

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(render_toml(cfg))
    print(f"Tailoring imported to {out}")


if __name__ == "__main__":
    main()
