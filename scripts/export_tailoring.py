#!/usr/bin/env python3
"""Convert a ohbs-host.toml into an XCCDF 1.2 tailoring file.

Usage:
    python3 scripts/export_tailoring.py ohbs-host.toml [tailoring.xml]

The generated tailoring file can be consumed by OpenSCAP-compatible tools and
records which rules are selected/deselected and which variable values override
the benchmark defaults.
"""

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, tostring

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"


def _import_tomllib():
    try:
        import tomllib
        return tomllib
    except ImportError:
        try:
            import tomli as tomllib
            return tomllib
        except ImportError:
            return None


def _clean_id(text):
    """Turn an arbitrary string into a valid XML id token."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", str(text))


def export_tailoring(cfg, benchmark_uri="ohbs-host-benchmark", profile_id="xccdf_ohbs-host_profile_custom"):
    root = Element("{%s}Tailoring" % XCCDF_NS)
    root.set("id", "xccdf_ohbs-host_tailoring_custom")
    root.set("version", "1.0")

    status = SubElement(root, "{%s}status" % XCCDF_NS)
    status.set("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    status.text = "draft"

    benchmark = SubElement(root, "{%s}benchmark" % XCCDF_NS)
    benchmark.set("href", benchmark_uri)

    profile_cfg = cfg.get("profile", {})
    profile = SubElement(root, "{%s}Profile" % XCCDF_NS)
    profile.set("id", profile_id)
    title = SubElement(profile, "{%s}title" % XCCDF_NS)
    title.text = profile_cfg.get("name", "Custom CIS profile")
    desc = SubElement(profile, "{%s}description" % XCCDF_NS)
    desc.text = "Tailored profile generated from ohbs-host.toml"

    # Variables
    variables = cfg.get("variables", {})
    for key, value in variables.items():
        rv = SubElement(profile, "{%s}refined-value" % XCCDF_NS)
        rv.set("idref", "xccdf_ohbs-host_value_%s" % _clean_id(key))
        rv.set("selector", str(value))

    # Rule selection / deselection
    rules = cfg.get("rules", {})
    include = _split(rules.get("include"))
    exclude = _split(rules.get("exclude"))

    for rid in include:
        sel = SubElement(profile, "{%s}select" % XCCDF_NS)
        sel.set("idref", "xccdf_ohbs-host_rule_%s" % _clean_id(rid))
        sel.set("selected", "true")

    for rid in exclude:
        sel = SubElement(profile, "{%s}select" % XCCDF_NS)
        sel.set("idref", "xccdf_ohbs-host_rule_%s" % _clean_id(rid))
        sel.set("selected", "false")

    # Waivers as remarks on deselected rules
    waivers = cfg.get("waivers", {})
    if isinstance(waivers, dict) and "rules" in waivers:
        waivers = waivers["rules"]
    for rid, waiver in waivers.items():
        mr = SubElement(profile, "{%s}refined-value" % XCCDF_NS)
        mr.set("idref", "xccdf_ohbs-host_rule_%s_waiver" % _clean_id(rid))
        mr.set("selector", str(waiver))

    return root


def _split(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _pretty_xml(elem):
    """Return a pretty-printed XML string with declaration."""
    raw = tostring(elem, encoding="unicode")
    try:
        from xml.dom.minidom import parseString
        dom = parseString(raw.encode("utf-8"))
        return dom.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
    except Exception:
        return '<?xml version="1.0" encoding="utf-8"?>\n' + raw


def main():
    ap = argparse.ArgumentParser(description="Export ohbs-host.toml as XCCDF tailoring file")
    ap.add_argument("toml", help="Path to ohbs-host.toml")
    ap.add_argument("output", nargs="?", help="Output XML path (default: ohbs-host-tailoring.xml)")
    ap.add_argument("--benchmark-uri", default="ohbs-host-benchmark", help="Benchmark URI/href")
    ap.add_argument("--profile-id", default="xccdf_ohbs-host_profile_custom", help="Tailoring profile ID")
    args = ap.parse_args()

    tomllib = _import_tomllib()
    if tomllib is None:
        print("Python 3.11+ or `pip install tomli` is required", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.toml):
        print(f"Config file not found: {args.toml}", file=sys.stderr)
        sys.exit(1)

    with open(args.toml, "rb") as fh:
        cfg = tomllib.load(fh)

    root = export_tailoring(cfg, benchmark_uri=args.benchmark_uri, profile_id=args.profile_id)
    out = args.output or args.toml.replace(".toml", "-tailoring.xml")
    if out == args.toml:
        out += "-tailoring.xml"

    with open(out, "w", encoding="utf-8") as fh:
        fh.write(_pretty_xml(root))
    print(f"Tailoring file written to {out}")


if __name__ == "__main__":
    main()
