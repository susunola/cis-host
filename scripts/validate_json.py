#!/usr/bin/env python3
"""Validate CIS JSON catalogs against schemas and cross-check integrity."""

import json
import os
import sys

try:
    import jsonschema
except ImportError:  # pragma: no cover
    print("jsonschema is required: pip install jsonschema", file=sys.stderr)
    sys.exit(1)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def discover_suites():
    suites = []
    for name in sorted(os.listdir(ROOT)):
        if not (name.startswith("cis-") and name.endswith("-ansible")):
            continue
        path = os.path.join(ROOT, name)
        if not os.path.isdir(path):
            continue
        role_dir = os.path.join(path, "roles")
        if not os.path.isdir(role_dir):
            continue
        roles = [d for d in sorted(os.listdir(role_dir))
                 if os.path.isdir(os.path.join(role_dir, d))]
        for role in roles:
            files_dir = os.path.join(role_dir, role, "files")
            if os.path.isdir(files_dir) and os.path.exists(os.path.join(files_dir, "rules.json")):
                suites.append(os.path.join(name, "roles", role, "files"))
    return suites


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_file(path, schema):
    data = load_json(path)
    jsonschema.validate(instance=data, schema=schema)
    return data


def check_rule_integrity(rules):
    """Lightweight consistency checks beyond schema validation."""
    errors = []
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        seen = set()
        dups = {x for x in ids if x in seen or seen.add(x)}
        errors.append("duplicate rule IDs: " + ", ".join(sorted(dups)))

    for r in rules:
        if not r["id"].startswith(r["section"]):
            errors.append(f"{r['id']}: section {r['section']} is not a prefix of id")
        if r["assessment"] == "Manual" and r["risk"] == "safe":
            errors.append(f"{r['id']}: Manual assessment with safe risk is suspicious")
        if r["family"] in ("manual", "info_only", "bootloader_password", "partition",
                           "root_access", "sshd_access") and r["risk"] not in ("manual", "none", "info_only"):
            errors.append(f"{r['id']}: family {r['family']} should not be auto-remediated")
    return errors


def main():
    failed = False
    schemas = {
        name: load_json(os.path.join(ROOT, "schemas", f"{name}.json"))
        for name in ("rules", "guidance", "sections")
    }

    suites = discover_suites()
    if not suites:
        print("No CIS suites found.")
        return 0

    for suite in suites:
        base = os.path.join(ROOT, suite)
        print(f"Checking {suite} ...")
        rules_path = os.path.join(base, "rules.json")
        guidance_path = os.path.join(base, "guidance.json")
        sections_path = os.path.join(base, "sections.json")

        for path, schema_name in [(rules_path, "rules"),
                                   (guidance_path, "guidance"),
                                   (sections_path, "sections")]:
            if not os.path.exists(path):
                print(f"  SKIP {os.path.basename(path)} (missing)")
                continue
            try:
                data = validate_file(path, schemas[schema_name])
                print(f"  OK   {os.path.basename(path)}")
                if schema_name == "rules":
                    errs = check_rule_integrity(data)
                    for e in errs:
                        print(f"  WARN {e}")
            except (json.JSONDecodeError, jsonschema.ValidationError) as exc:
                print(f"  FAIL {os.path.basename(path)}: {exc}")
                failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
