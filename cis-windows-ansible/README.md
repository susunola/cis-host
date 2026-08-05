# CIS Windows Server 2025 Benchmark v2.1.0 — Ansible Playbooks

**English** | [简体中文](README.en.md)

Ansible playbooks that implement the **CIS Microsoft Windows Server 2025 Benchmark
v2.1.0** for automated compliance scanning and remediation. Part of [CIS-OS](../).

## How a run works

```
  controller                     Windows host                        disk
  ──────────                     ───────────                         ────

  ansible-playbook
       │
       │  preflight: vars, PowerShell ≥ 5.1, Administrator
       │  push 4 files  ────────────────▶  C:\Windows\Temp\cis-scan\
       │                                    cis_engine.ps1
       │                                    rules.json
       │                                    guidance.json
       │                                    sections.json
       │
       │  powershell.exe -File cis_engine.ps1
       │    -Mode scan | apply
       │    -Profile L1 | L2
       ├──────────────────────────────▶   154 rules
       │                                    scan : read only
       │                                    apply: patch + re-verify,
       │                                          backup → C:\cis-backups\
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
| **HTML report** | Self-contained file: hostname / IP / OS, score, chapters, searchable table |
| **CSV export** | Flattened findings for SIEM / BI import |
| **Fleet overview** | Auto index page summarising all hosts |
| **Risk tiers** | Disruptive fixes skipped unless explicitly allowed |
| **Fine-grained filters** | `-Include`, `-Exclude`, `-Sections`, `-Families` |

## Key variables

| Variable | Default | Description |
|------|--------|------|
| `cis_mode` | `scan` | `scan` or `apply` |
| `cis_profile` | `L1` | `L1` or `L2` |
| `cis_platform` | `server` | `server` / `workstation` / `all` |
| `cis_allow_disruptive` | `false` | Allow reboot / service restart etc. |
| `cis_include` | `[]` | Run only matching rule-id prefixes |
| `cis_exclude` | `[]` | Exclude given rules |
| `cis_sections` | `[]` | Run only rules whose ID starts with one of these |
| `cis_families` | `[]` | Run only rules in these remediation families |
| `cis_fail_on_findings` | `false` | Fail the play on findings |
| `cis_min_score` | `0` | Fail below this score |

## Directory layout

```
cis-windows-ansible/
├── scan.yml                       # scan shortcut
├── apply.yml                      # apply shortcut
├── inventory/
│   └── hosts.ini                  # target hosts
├── group_vars/
│   └── all.yml                    # global overrides
├── reports/                       # HTML/JSON/CSV output
└── roles/cis_windows/
    ├── defaults/main.yml          # role defaults
    ├── vars/main.yml              # internal vars
    ├── meta/main.yml              # metadata
    ├── files/
    │   ├── cis_engine.ps1         # assessment engine (PowerShell)
    │   ├── rules.json             # rule catalog
    │   ├── guidance.json          # remediation text
    │   └── sections.json          # chapter titles
    ├── tasks/
    │   ├── main.yml               # entry: preflight → run → report → gate
    │   ├── preflight.yml          # validation + PowerShell probe + perms
    │   ├── run.yml                # deploy → run → collect
    │   ├── report.yml             # render HTML/JSON/CSV + index
    │   └── gate.yml               # compliance gate (optional)
    └── templates/
        ├── report.html.j2         # host report
        ├── index.html.j2          # fleet overview
        └── findings.csv.j2        # CSV export
```

## Engine notes

The assessment engine (`cis_engine.ps1`) is a single-file PowerShell script with no
third-party dependencies. It runs as Administrator on the target via WinRM.

The engine emits a JSON document with:

- Host info (hostname / IP / OS)
- L1/L2 grouped summary stats (pass / fail / manual / error / applied …)
- Per-rule detail (status, evidence, fix, time)

## Notes

1. Target needs **PowerShell 5.1+** and **Administrator** (WinRM configured)
2. `apply` edits registry / GPO / local policy; originals are backed up to `C:\cis-backups\`
3. Reboot / service-restart fixes skipped by default; add `-e cis_allow_disruptive=true`
4. Run `scan` in staging and review before `apply` in prod
5. This automation does not replace a manual security audit
