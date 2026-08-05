# CIS-OS

A collection of Ansible playbooks that implement **CIS security benchmarks** for multiple
Linux distributions, with `scan` and `apply` modes and a generated, professional HTML report.

Currently ships two independent, self-contained playbook suites (more OS families — e.g.
RHEL — to be added later under the same layout):

| Suite | Benchmark | Rules | Automated |
|-------|-----------|-------|-----------|
| `cis-tencentos3-ansible/` | CIS TencentOS Linux 3 Benchmark v1.0.0 | 322 | ~95% |
| `cis-tencentos4-ansible/` | CIS TencentOS Linux 4 Benchmark v1.0.0 | 275 | ~88% |

Each suite is a standalone Ansible project (its own `inventory/`, `group_vars/`,
`ansible.cfg`, `scan.yml`, `apply.yml`, `site.yml`, and a full `roles/` tree).

## What it does

- **Scan** (`scan.yml`) — read-only assessment of every selected rule; produces a
  compliance report with a per-host score.
- **Apply** (`apply.yml`) — remediates failing rules automatically, then re-verifies
  and reports the new score.
- **Profile selection** — run against the **L1** or **L2** CIS profile
  (`-e cis_profile=L1|L2`).
- **Disruptive guard** — risky remediations (reboot / service restart) are skipped
  unless `-e cis_allow_disruptive=true`.
- **HTML report** — after each run, an HTML report is rendered per host showing:
  - Host **name / IP / MAC** at the top
  - **L1** and **L2** cards showing how many rules were applied (applied / pending /
    failed / skipped) plus a compliance score
  - A filterable per-rule findings table with CIS rationale and remediation text
  - A multi-host cluster overview index page

## Quick start

```bash
# 1. Edit the inventory to point at your TencentOS hosts
vim cis-tencentos3-ansible/inventory/hosts.ini

# 2. L1 scan
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/scan.yml

# 3. L1 apply
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml

# 4. L2 full + allow disruptive remediations
ansible-playbook -i cis-tencentos3-ansible/inventory/hosts.ini \
                 cis-tencentos3-ansible/apply.yml \
                 -e cis_profile=L2 -e cis_allow_disruptive=true
```

Same commands apply under `cis-tencentos4-ansible/` for TencentOS Linux 4.

## How it works

Each suite ships a small, dependency-free Python assessment engine
(`roles/cis_tencentos{3,4}/files/cis_engine.py`) that is copied to the managed node and
run as a `script:` task. The engine reads a rule catalog (`rules.json`) plus a guidance
bundle (`guidance.json`) and emits a single JSON result document. Ansible then gathers
host facts (hostname / IP / MAC) and renders the Jinja2 HTML report.

The engine classifies each rule into a remediation *family* (kmod, sysctl, file_perm,
svc_disabled, sshd_param, audit_rule, pam_arg, selinux, …) and assigns a risk level:

- `safe` — idempotent config change, applied by default
- `disruptive` — needs reboot / service restart, only with `cis_allow_disruptive=true`
- `none` — scan-only / manual (e.g. partition layout, bootloader password)

## Notes / caveats

- Remediations are applied **in place** on the target host. Review `scan.yml` output
  and use `--check` (the role auto-downgrades `apply` to `scan` under `--check`) before
  running `apply` on production systems.
- 6 rule families are intentionally fix-less (require human judgement or are
  reboot/site-specific): `bootloader_password`, `info_only`, `manual`, `partition`,
  `root_access`, `sshd_access`.
- The engine is Linux-targeted (uses `rpm`, `dnf`, `systemctl`, `sshd -T`, `auditctl`,
  `/proc`, …). Run it on a TencentOS Linux 3/4 host.

## License

Benchmark content © Center for Internet Security. Automation in this repository is
provided as-is for operational use.
