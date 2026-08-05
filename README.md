# CIS-OS

**English** | [简体中文](README.en.md)

Ansible playbooks that run the **CIS** security benchmarks against TencentOS Linux 3,
TencentOS Linux 4, and Windows Server. Each suite has two modes — `scan` (read-only)
and `apply` (remediate) — and produces a self-contained HTML report per host.

## Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="CIS-OS Architecture" width="960">
</p>

The engine is a single-file script (Python 3 for Linux, PowerShell for Windows) with
no third-party dependencies. Ansible only handles file copy, command execution, and
report rendering.

## How a run works

### scan (read-only)

1. `preflight` — Ansible validates the variables, probes the target for Python 3.6+
   (PowerShell 5.1+ on Windows), and confirms root / Administrator.
2. `push` — copies `cis_engine.py`, `rules.json`, `guidance.json`, and `sections.json`
   to `/tmp/cis-scan/` (or `C:\Windows\Temp\cis-scan` on Windows).
3. `run` — invokes the engine with `--mode scan`. The engine walks the rule catalog,
   runs each check against the live system, captures evidence, and writes
   `result.json`. Nothing on the target is modified.
4. `fetch` — Ansible pulls `result.json` back to the controller.
5. `report` — the Jinja2 template (`report.html.j2`) is rendered with the result
   document plus host facts (hostname / IP / MAC / OS / kernel).

### apply (remediate)

Steps 1, 2, 4, 5 are identical. The only difference is step 3:

3. The engine runs with `--mode apply`. For every failing rule whose family has a
   known fix, the engine edits the configuration (writes a backup under
   `/var/backups/cis-<os>/` first), then re-runs the check to confirm the new state.
   Rules that would require a reboot or service restart are skipped unless
   `cis_allow_disruptive=true` is set.

The HTML report shows the **before** state (from a pre-apply scan if you ran one),
the **after** state, and a delta. If a follow-up `scan` finds new failures introduced
by the apply, those are listed in the report under a "regressions" section.

## Suites

| Suite | Benchmark | Engine | Rules |
|-------|-----------|--------|-------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 v1.0.0 | Python 3 | 322 |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 v1.0.0 | Python 3 | 275 |
| `cis-windows-ansible/`    | CIS Windows Server 2022 v1.0.0 | PowerShell | 30 |

Each suite is a self-contained Ansible project with its own inventory, group_vars,
`scan.yml`, `apply.yml`, role tree, and templates.

## Quick start

```bash
# 1. point the inventory at your hosts
vim cis-tencentos3-ansible/inventory/hosts.ini

# 2. L1 scan (read-only)
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/scan.yml

# 3. open the report
open cis-tencentos3-ansible/reports/*-L1-scan.html

# 4. L1 apply (review the report first)
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml

# 5. L2 full + allow disruptive remediations
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

For TencentOS Linux 4 or Windows, swap the directory.

## Fine-grained execution

The engine and the wrapper support the same filter set:

| Flag | What it does |
|------|--------------|
| `--mode scan` / `--mode apply` | read-only check vs. remediate |
| `--profile L1` / `--profile L2` | baseline vs. defense-in-depth |
| `--include 1.1.1,1.1.2,5.2` | run only these rule IDs |
| `--exclude 1.5,1.6` | skip these rule IDs |
| `--sections 1,5` | run only rules whose ID starts with one of these |
| `--families sysctl,kmod` | run only rules in these remediation families |

Through Ansible, the same filters are exposed as variables — see `Key variables` in
each suite's README.

## Repo layout

```
CIS-OS/
├── README.md                       # this file (English)
├── README.en.md                    # Chinese
├── cis-tencentos3-ansible/         # TOS 3 suite
│   ├── ansible.cfg
│   ├── scan.yml | apply.yml | site.yml
│   ├── inventory/  group_vars/
│   ├── reports/                    # HTML / JSON / CSV output
│   └── roles/cis_tencentos3/
│       ├── files/   cis_engine.py, rules.json, guidance.json, sections.json
│       ├── tasks/   preflight, run, report, gate
│       └── templates/  report.html.j2, index.html.j2, findings.csv.j2
├── cis-tencentos4-ansible/         # TOS 4 suite (same layout)
└── cis-windows-ansible/            # Windows suite (PowerShell engine)
```

## Multiple hosts

A single play assesses every host in the inventory. Each host gets its own
`reports/HOST-L1-scan.html`. When more than one host is in the run, the role also
renders `reports/index.html` — a fleet overview that lists every node with its
score, pass/fail counts, and a link back to the per-host report.

## Caveats

- `apply` edits configs in place. Originals are backed up to `/var/backups/cis-<os>/`.
- Rules tagged `disruptive` (reboot, remount, service restart) are skipped unless
  you pass `-e cis_allow_disruptive=true`. Run those in a maintenance window.
- 6 families are intentionally fix-less — they require human judgement or are
  site-specific: `bootloader_password`, `info_only`, `manual`, `partition`,
  `root_access`, `sshd_access`. The engine reports them; nothing else changes.
- The Linux engine uses `rpm`, `dnf`, `systemctl`, `sshd -T`, `auditctl`, `/proc`.
  It targets TencentOS Linux 3 / 4. The Windows engine targets Server 2019 / 2022.
- Always run `scan` in staging first, review the report, then `apply` in production.

## License

Benchmark content © Center for Internet Security. The automation in this repository
is provided as-is for operational use.
