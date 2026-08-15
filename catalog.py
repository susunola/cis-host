"""Rule catalog lookup helpers: rules.json, guidance.json, sections.json."""

import json
import os


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
