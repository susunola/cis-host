# CIS-OS

**English** | [简体中文](README.zh.md)

Ansible playbooks and a local CLI that run the **CIS** security benchmarks against 11 Linux distributions and Windows Server. Each suite operates in two modes — `scan` (read-only) and `apply` (remediate) — and produces per-host interactive HTML reports.

Supports: TencentOS 3/4 · RHEL 8/9/10 · SLES 15/16 · Ubuntu 20.04/22.04/24.04 LTS · Windows Server 2025

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="CIS-OS architecture" width="960">
</p>

Engines are single-file scripts with zero third-party dependencies (Python 3 on Linux, PowerShell on Windows). Ansible handles file transfer, command execution, and report rendering only.

## Workflow

### scan (read-only)

1. `preflight` — Ansible validates variables, probes the target for Python 3.6+ (PowerShell 5.1+ on Windows), and confirms root / Administrator.
2. `push` — Copies `cis_engine.py`, `rules.json`, `guidance.json`, and `sections.json` to `/tmp/cis-scan/` on the target (`C:\Windows\Temp\cis-scan` on Windows).
3. `run` — Engine starts in `--mode scan`, iterates through the catalog checking each rule, collects evidence, and writes `result.json`. Nothing on the target is modified.
4. `fetch` — Ansible pulls `result.json` back to the control machine.
5. `report` — Jinja2 templates (`report.html.j2`) combine `result.json` with host facts (hostname, IP, MAC, OS, kernel) to render an HTML report.

### apply (remediate)

Steps 1, 2, 4, 5 are identical to scan. Step 3 differs:

3. Engine starts in `--mode apply`. For each failing rule in a known remediable family, the engine backs up the original file to `/var/backups/cis-<os>/`, modifies the configuration, then re-checks the rule to confirm the new state. Rules that require a reboot or service restart are skipped by default unless `cis_allow_disruptive=true` is explicitly set.

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
| `cis-windows-ansible/` | CIS Windows Server 2025 v2.1.0 | PowerShell | 154 |

Each suite is a self-contained Ansible project with its own inventory, group_vars, `scan.yml`, `apply.yml`, role tree, and templates.

## Quick start

### Local CLI (recommended)

```bash
# L1 scan (read-only)
python3 cis_cli.py scan --os rhel9 --profile L1 --output output/

# L1 apply (remediate)
python3 cis_cli.py apply --os ubuntu2204 --profile L1 --output output/

# L2 full scan + allow disruptive rules
python3 cis_cli.py apply --os tencentos4 --profile L2 --allow-disruptive --output output/

# Scan only specific rules
python3 cis_cli.py scan --os sles15 --include "1.1.1,1.1.2,5.2" --output output/
```

`--os` values: `tencentos3` `tencentos4` · `rhel8` `rhel9` `rhel10` · `sles15` `sles16` · `ubuntu2004` `ubuntu2204` `ubuntu2404` · `windows`

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

When using Ansible, the corresponding variables are documented in each suite's README under "Key Variables."

## Directory structure

```
CIS-OS/
├── README.md
├── README.zh.md
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
└── cis-windows-ansible/            # Windows Server 2025
    ├── ansible.cfg
    ├── scan.yml | apply.yml | site.yml
    ├── inventory/  group_vars/
    ├── reports/                    # HTML / JSON / CSV output
    └── roles/cis_<os>/
        ├── files/   engine, rules.json, guidance.json, sections.json
        ├── tasks/   preflight, run, report, gate
        └── templates/  report.html.j2, index.html.j2, findings.csv.j2
```

## Multi-host

A single play runs against every host in the inventory. Each host gets its own `reports/HOST-L1-scan.html`. When the inventory contains more than one host, the role also renders `reports/index.html` — a cluster overview with each node's compliance score, pass/fail counts, and links to per-host reports.

## Notes

- `apply` modifies configuration files in place. Originals are backed up to `/var/backups/cis-<os>/`.
- Rules marked `disruptive` (reboot, remount, service restart) are skipped by default. Pass `-e cis_allow_disruptive=true` to opt in. Run during a maintenance window.
- Six families are intentionally never auto-remediated — they require human judgment or are environment-specific: `bootloader_password`, `info_only`, `manual`, `partition`, `root_access`, `sshd_access`. The engine reports these items but does not modify them.
- Linux engines require `rpm`/`dpkg`, `systemctl`, `sshd -T`, `auditctl`, and `/proc`, covering RHEL, Debian, and SUSE families. Windows engine targets Server 2019 / 2022 / 2025.
- Before running `apply` in production, run `scan` in a test environment, review the report, then proceed.

## License

Benchmark content copyright Center for Internet Security. Automation scripts in this repository are provided as-is for operational use.
