# CIS TencentOS Linux 4 Benchmark v1.0.0 — Ansible Playbooks

**English** | [简体中文](README.en.md)

Ansible playbooks that implement the **CIS TencentOS Linux 4 Benchmark v1.0.0** for
compliance scanning and remediation.

## How a run works

```
  controller                     target host                       disk
  ──────────                     ──────────                        ────

  ansible-playbook
       │
       │  preflight: vars, python3 ≥ 3.6, root
       │  push 4 files  ────────────────▶  /tmp/cis-scan/
       │                                    ohbs_engine.py
       │                                    rules.json
       │                                    guidance.json
       │                                    sections.json
       │
       │  python3 ohbs_engine.py
       │    --mode scan | apply
       │    --profile L1 | L2
       ├──────────────────────────────▶   275 rules
       │                                    scan : read only
       │                                    apply: patch + re-verify,
       │                                          backup → /var/backups/cis-tencentos4/
       │                                         │
       │                                         ▼
       │                                    result.json
       ◀────────────────────────────────
       │
       │  render Jinja2  ────────────▶  reports/HOST-L1-scan.html
       │  (report.html.j2)                 reports/HOST-L1-apply.html
       │                                   reports/index.html  (N>1)
       ▼
  open reports/*-L1-scan.html
```

See the [root README](../#how-a-run-works) for the full lifecycle and the engine's
internals.

## Quick Start

```bash
# 1) Edit the inventory with your target hosts
vim inventory/hosts.ini

# 2) L1 scan (read-only, no changes)
ansible-playbook -i inventory/hosts.ini scan.yml

# 3) Open the report
open reports/*-L1-scan.html

# 4) L1 apply (review the report first)
ansible-playbook -i inventory/hosts.ini apply.yml

# 5) L2 full scan + apply (incl. disruptive)
ansible-playbook -i inventory/hosts.ini scan.yml -e cis_profile=L2
ansible-playbook -i inventory/hosts.ini apply.yml -e cis_profile=L2 \
    -e cis_allow_disruptive=true
```

## Features

| Feature | Description |
|------|------|
| **scan** | Read-only assessment; never modifies the target |
| **apply** | Auto-remediates failing rules, then re-verifies |
| **L1 / L2** | `cis_profile=L1` (baseline) or `cis_profile=L2` (defense-in-depth) |
| **HTML report** | Self-contained file: hostname / IP / MAC, score, chapters, searchable table |
| **CSV export** | Flattened findings for SIEM / BI import |
| **Fleet overview** | Auto index page summarising all hosts |
| **Risk tiers** | Disruptive fixes skipped unless explicitly allowed |
| **Fine-grained filters** | `--include`, `--exclude`, `--sections`, `--families` |

## Report contents

At the top of the report:

- **Hostname, IP address, MAC address**
- OS / kernel / arch / virtualization
- Network interfaces (expandable)

Below, two cards — **Level 1** and **Level 2** — each show:

- Rules **fixed** (apply) or **to fix** (scan)
- A compliance bar (green=pass red=fail blue=manual purple=error)
- fixed / pending / failed / skipped-disruptive / unsupported / already-compliant

The toolbar filters by **result status, risk tier (low / high / N/A), level, chapter** and
keyword; click any row to expand the evidence and the CIS remediation text.

## Key variables

| Variable | Default | Description |
|------|--------|------|
| `cis_mode` | `scan` | `scan` or `apply` |
| `cis_profile` | `L1` | `L1` or `L2` |
| `cis_platform` | `server` | `server` / `workstation` / `all` |
| `cis_allow_disruptive` | `false` | Allow reboot / remount etc. |
| `cis_include` | `[]` | Run only matching rule-id prefixes |
| `cis_exclude` | `[]` | Exclude given rules |
| `cis_sections` | `[]` | Run only rules whose ID starts with one of these |
| `cis_families` | `[]` | Run only rules in these remediation families |
| `cis_fail_on_findings` | `false` | Fail the play on findings |
| `cis_min_score` | `0` | Fail below this score |

## Directory layout

```
cis-tencentos4-ansible/
├── ansible.cfg                    # Ansible config
├── site.yml                       # main entry
├── scan.yml                       # scan shortcut
├── apply.yml                      # apply shortcut
├── inventory/
│   └── hosts.ini                  # target hosts
├── group_vars/
│   └── all.yml                    # global overrides
├── reports/                       # HTML/JSON/CSV output
└── roles/cis-tencentos4/
    ├── defaults/main.yml          # role defaults
    ├── vars/main.yml              # internal vars
    ├── meta/main.yml              # metadata
    ├── files/
    │   ├── ohbs_engine.py          # assessment engine (Python 3)
    │   ├── rules.json             # rule catalog
    │   ├── guidance.json          # remediation text
    │   └── sections.json          # chapter titles
    ├── tasks/
    │   ├── main.yml               # entry: preflight → run → report → gate
    │   ├── preflight.yml          # validation + python probe + perms
    │   ├── run.yml                # deploy → run → collect
    │   ├── report.yml             # render HTML/JSON/CSV + index
    │   └── gate.yml               # compliance gate (optional)
    └── templates/
        ├── report.html.j2         # host report
        ├── index.html.j2          # fleet overview
        └── findings.csv.j2        # CSV export
```

## Engine notes

The assessment engine (`ohbs_engine.py`) is a pure-Python 3 script (no third-party deps)
run as root on the target. It implements **check + remediation families** for
approximately **88%** of the benchmark's automatable rules.

The engine emits a JSON document with:

- Host info (hostname / IP / MAC / OS / kernel)
- L1/L2 grouped summary stats (pass / fail / manual / error / applied …)
- Per-rule detail (status, evidence, fix, time)

## Notes

1. Target needs **Python 3.6+** and **root**
2. `apply` edits configs (backups in `/var/backups/cis-tencentos4/`)
3. Reboot fixes skipped by default; add the flag in a change window
4. Run `scan` in staging and review before `apply` in prod
5. This automation does not replace a manual security audit
