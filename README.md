# SecX Automation Suite

**Compliance Baseline as Code | Hardening & Drift Automation**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-14%20OS%20targets-34d058?logo=linux&logoColor=white)](https://github.com/susunola/cis-os#suites)
[![Python](https://img.shields.io/badge/python-3.6%2B-3670A0?logo=python&logoColor=ffdd54)](https://www.python.org/)
[![PowerShell](https://img.shields.io/badge/powershell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)

**English** | [简体中文](README.zh.md) | [日本語](README.ja.md) | [ภาษาไทย](README.th.md)

Ansible playbooks and a local CLI that run the **CIS** security benchmarks against 10 Linux distributions and 4 Windows Server versions. Each suite operates in two modes — `scan` (read-only) and `apply` (remediate) — and produces per-host interactive HTML reports with structured audit logs.

**Supported platforms:** RHEL 8/9/10 · TencentOS 3/4 · SLES 15/16 · Ubuntu 20.04/22.04/24.04 LTS · Windows Server 2016/2019/2022/2025

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="SecX Automation Suite Architecture" width="800">
</p>

Engines are single-file scripts with zero third-party dependencies (Python 3 on Linux, PowerShell on Windows). Ansible handles file transfer, command execution, and report rendering only. Each engine produces both a structured `result.json` and an optional `audit.log` (JSON-lines) suitable for compliance review and SIEM ingestion.

## Workflow

### scan (read-only)

1. `preflight` — Ansible validates variables, probes the target for Python 3.6+ (PowerShell 5.1+ on Windows), and confirms root / Administrator.
2. `push` — Copies `cis_engine.py`, `rules.json`, `guidance.json`, and `sections.json` to `/tmp/cis-scan/` on the target (`C:\Windows\Temp\cis-scan` on Windows).
3. `run` — Engine starts in `--mode scan`, iterates through the catalog checking each rule, collects evidence, and writes `result.json`. Nothing on the target is modified.
4. `fetch` — Ansible pulls `result.json` (and `audit.log` if enabled) back to the control machine.
5. `report` — Jinja2 templates (`report.html.j2`) combine `result.json` with host facts (hostname, IP, MAC, OS, kernel) to render an interactive HTML report.

### apply (remediate)

Steps 1, 2, 4, 5 are identical to scan. Step 3 differs:

3. Engine starts in `--mode apply`. For each failing rule in a known remediable family, the engine backs up the original file to `/var/backups/cis-<os>/`, modifies the configuration, then re-checks the rule to confirm the new state. Rules that require a reboot or service restart are skipped by default unless `cis_allow_disruptive=true` is explicitly set. Every action is recorded in the audit log when enabled.

Reports show **before** (from a previous scan) and **after** status with deltas. If an apply introduces new failures on re-scan, the report surfaces them in a "regressions" block.

## Suites

| Suite | Benchmark | Engine | Rules |
|-------|-----------|--------|-------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 v1.0.0 | Python 3 | 322 |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 v1.0.0 | Python 3 | 275 |
| `cis-rhel8-ansible/` | CIS Red Hat Enterprise Linux 8 v4.0.0 | Python 3 | 322 |
| `cis-rhel9-ansible/` | CIS Red Hat Enterprise Linux 9 v2.0.0 | Python 3 | 297 |
| `cis-rhel10-ansible/` | CIS Red Hat Enterprise Linux 10 v1.0.1 | Python 3 | 328 |
| `cis-sles15-ansible/` | CIS SLES 15 v2.0.1 | Python 3 | 286 |
| `cis-sles16-ansible/` | CIS SLES 16 v1.0.0 | Python 3 | 336 |
| `cis-ubuntu2004-ansible/` | CIS Ubuntu 20.04 LTS v3.0.0 | Python 3 | 312 |
| `cis-ubuntu2204-ansible/` | CIS Ubuntu 22.04 LTS v3.0.0 | Python 3 | 306 |
| `cis-ubuntu2404-ansible/` | CIS Ubuntu 24.04 LTS v2.0.0 | Python 3 | 332 |
| `cis-win2016-ansible/` | CIS Microsoft Windows Server 2016 v3.0.0 | PowerShell | 337 |
| `cis-win2019-ansible/` | CIS Microsoft Windows Server 2019 v3.0.0 | PowerShell | 338 |
| `cis-win2022-ansible/` | CIS Microsoft Windows Server 2022 v3.0.0 | PowerShell | 342 |
| `cis-win2025-ansible/` | CIS Microsoft Windows Server 2025 v2.1.0 | PowerShell | 360 |

Each suite is a self-contained Ansible project with its own inventory, group_vars, `scan.yml`, `apply.yml`, role tree, and templates.

## Audit logging

When `--audit-log` is set, the engine writes one JSON line per rule execution to the specified file, producing a structured, append-safe audit trail. Each entry includes:

| Field | Description |
|-------|-------------|
| `ts` | ISO-8601 UTC timestamp with millisecond precision |
| `host` | Target hostname |
| `version` | Engine version |
| `mode` | `scan` or `apply` |
| `profile` | `L1` or `L2` |
| `rule` | CIS rule ID (e.g. `1.1.1.1`) |
| `title` | Human-readable rule title |
| `status` | `pass`, `fail`, `manual`, `error`, `notapplicable` |
| `apply_status` | `applied`, `already`, `skipped_disruptive`, `failed`, `n/a` |
| `detail` | Evidence or remediation summary (truncated to 200 chars) |
| `duration_ms` | Execution time in milliseconds |

**Via CLI:**

```bash
python3 cis_cli.py scan --os rhel9 --audit-log output/audit-$(hostname).log
```

**Via Ansible:** add `-e cis_audit_log=/var/log/cis-audit.log` to your playbook invocation.

The audit log format is newline-delimited JSON, compatible with log aggregators, SIEM platforms, and compliance auditors.

## Quick start

### Local CLI (recommended)

```bash
# L1 scan (read-only)
python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

# L1 apply (remediate)
python3 cis_cli.py apply --os ubuntu2204 --profile L1 --output output/

# L2 full scan + allow disruptive rules + audit log
python3 cis_cli.py apply --os tencentos4 --profile L2 --allow-disruptive \
  --audit-log output/audit.log --output output/

# Scan only specific rules
python3 cis_cli.py scan --os sles15 --include "1.1.1,1.1.2,5.2" --output output/
```

`--os` values: `tencentos3` `tencentos4` · `rhel8` `rhel9` `rhel10` · `sles15` `sles16` · `ubuntu2004` `ubuntu2204` `ubuntu2404` · `win2016` `win2019` `win2022` `win2025`

### Via Ansible

```bash
ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/scan.yml

ansible-playbook -i cis-rhel9-ansible/inventory/hosts.ini \
                 cis-rhel9-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

## Fine-grained execution

Both the engine and wrapper share the same filters:

| Parameter | Purpose |
|-----------|---------|
| `--mode scan` / `--mode apply` | Read-only check / remediate |
| `--profile L1` / `--profile L2` | Baseline / defense-in-depth |
| `--include 1.1.1,1.1.2,5.2` | Run only these rules |
| `--exclude 1.5,1.6` | Skip these rules |
| `--sections 1,5` | Run only rules whose IDs start with these prefixes |
| `--families sysctl,kmod` | Run only rules from these remediable families |
| `--audit-log audit.log` | Write structured audit trail |

When using Ansible, the corresponding variables are documented in each suite's README under "Key Variables."

## Privilege modes

SecX runs under three privilege levels. `apply` always requires **root** (Linux) or **Administrator** (Windows).

### scan — what works at each level (Linux)

| Check family | Root | Non-root + caps¹ | Plain user |
|-------------|------|-------------------|------------|
| Packages, services, processes | ✅ | ✅ | ✅ |
| File perms (non-root files) | ✅ | ✅ | ✅ |
| Kernel params (`/proc/sys/`) | ✅ | ✅² | ❌ |
| File perms (root-only files) | ✅ | ✅³ | ❌ |
| SSH config (`sshd -T`) | ✅ | ✅⁴ | ❌ |
| Audit rules (`auditctl -l`) | ✅ | ✅⁴ | ❌ |
| Sudoers, shadow, logs | ✅ | ✅³ | ❌ |

¹ "Non-root + caps" = regular user granted specific privileges via capability or sudo.
² Needs `cap_sys_ptrace`. ³ Needs `cap_dac_read_search`. ⁴ Needs sudo for the specific command.

### Setting up a non-root scan user (Linux)

**Option A — capability-based bypass** (persistent; add to systemd unit or `/etc/security/capability.conf`):

```bash
sudo setcap cap_sys_ptrace,cap_dac_read_search+ep $(which python3)
```

**Option B — sudo rules** for specific commands:

```
# /etc/sudoers.d/cis-scan
cis-scanner ALL=(ALL) NOPASSWD: /usr/sbin/sshd -T *
cis-scanner ALL=(ALL) NOPASSWD: /usr/sbin/auditctl -l
```

With both capabilities and the two sudo commands, a non-root scan hits ~95% rule coverage. Gaps are limited to apply-only behaviors (chown, chmod, module loading, partition resizing).

### Windows

Scan works as non-Admin with PowerShell execution policy `RemoteSigned` or lower. Apply requires Administrator — use `-RunAsAdministrator` or Ansible `become: true`.

## Directory structure

```
secx/
├── README.md
├── README.zh.md
├── README.ja.md
├── README.th.md
├── cis_cli.py                      # Local CLI (--os switches targets)
├── docs/architecture.svg           # Architecture diagram
├── cis-tencentos3-ansible/         # TencentOS 3
├── cis-tencentos4-ansible/         # TencentOS 4
├── cis-rhel8-ansible/              # RHEL 8
├── cis-rhel9-ansible/              # RHEL 9
├── cis-rhel10-ansible/             # RHEL 10
├── cis-sles15-ansible/             # SLES 15
├── cis-sles16-ansible/             # SLES 16
├── cis-ubuntu2004-ansible/         # Ubuntu 20.04 LTS
├── cis-ubuntu2204-ansible/         # Ubuntu 22.04 LTS
├── cis-ubuntu2404-ansible/         # Ubuntu 24.04 LTS
├── cis-win2016-ansible/            # Windows Server 2016
├── cis-win2019-ansible/            # Windows Server 2019
├── cis-win2022-ansible/            # Windows Server 2022
└── cis-win2025-ansible/            # Windows Server 2025
    ├── ansible.cfg
    ├── scan.yml | apply.yml | site.yml
    ├── inventory/  group_vars/
    ├── reports/                    # HTML / JSON / CSV / audit output
    └── roles/cis_<os>/
        ├── files/   engine, rules.json, guidance.json, sections.json
        ├── tasks/   preflight, run, report, gate
        └── templates/  report.html.j2, index.html.j2, findings.csv.j2
```

## Reports

Two distinct HTML reports are produced from every run. Both are static, self-contained, print-ready, and themeable (light / dark). They share the same Jinja2 + vanilla JS stack and load zero third-party assets, so they work fully offline.

| Report | Template | Output filename | When rendered |
|--------|----------|-----------------|---------------|
| **Per-host** | `templates/report.html.j2` | `HOST-PROFILE-mode-TIMESTAMP.html` | Every run (scan or apply) |
| **Fleet index** | `templates/index.html.j2` | `index-TIMESTAMP.html` | Multi-host inventory, or `cis_report_index=true` |

A `findings.csv.j2` template is also available for Excel/Sheets consumption — enable with `cis_report_csv=true`.

### Per-host report

A single host's complete compliance posture. The default deliverable for any scan or apply.

- **Score banner** — overall pass percentage with traffic-light coloring (green ≥ 90, amber ≥ 70, red otherwise)
- **System facts** — hostname, IPv4, MAC, OS, kernel, architecture, virtualization, uptime
- **Findings table** — every rule with status, family, level, evidence, remediation hint, and benchmark page reference
- **Filters** — by status (pass / fail / manual / error / n/a), family, level, section; persistent in `localStorage`
- **Before/after diff** — in `apply` mode, pre-scan vs post-scan deltas with a regression block highlighting rules that passed before but failed after

### Fleet index

A multi-host compliance dashboard for cluster operators.

- **Fleet score** — aggregate pass percentage across all hosts in the play
- **Six stat cards** — to-fix, L1 fixed, L2 fixed, manual review, fix failed, host count
- **Host table** — each host with its score bar, pass/fail pills, applied counts (with pending-reboot warnings), and a deep link to its per-host report
- **Drill-down** — every host row links to the per-host report for that exact run

The fleet index is only useful when you have more than one target. Enable it explicitly with `-e cis_report_index=true` to force-render it on a single-host run.

## Multi-host

A single play runs against every host in the inventory. Each host gets its own `reports/HOST-L1-scan.html`. When the inventory contains more than one host, the role also renders `reports/index.html` — a cluster overview with each node's compliance score, pass/fail counts, and links to per-host reports.

## Notes

- `apply` modifies configuration files in place. Originals are backed up to `/var/backups/cis-<os>/`.
- Rules marked `disruptive` (reboot, remount, service restart) are skipped by default. Pass `-e cis_allow_disruptive=true` to opt in. Run during a maintenance window.
- Six families are intentionally never auto-remediated — they require human judgment or are environment-specific: `bootloader_password`, `info_only`, `manual`, `partition`, `root_access`, `sshd_access`. The engine reports these items but does not modify them.
- Linux engines require `rpm`/`dpkg`, `systemctl`, `sshd -T`, `auditctl`, and `/proc`, covering RHEL, Debian, and SUSE families. Windows engine targets Server 2016 / 2019 / 2022 / 2025.
- Before running `apply` in production, run `scan` in a test environment, review the report, then proceed.

## License

Automation scripts in this repository are licensed under the [MIT License](LICENSE). CIS Benchmark content is copyright &copy; Center for Internet Security, Inc. and used under their terms of use.
