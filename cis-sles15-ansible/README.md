# CIS SUSE Linux Enterprise 15 Ansible Playbook

Automated CIS Benchmark assessment for SUSE Linux Enterprise 15.

## Quick Start

```bash
# Scan (read-only)
ansible-playbook -i inventory/hosts.ini scan.yml

# Apply remediations
ansible-playbook -i inventory/hosts.ini apply.yml -e cis_allow_disruptive=true

# Custom scan
ansible-playbook -i inventory/hosts.ini site.yml \
  -e cis_profile=L2 \
  -e cis_sections='["1","5"]' \
  -e cis_exclude='["1.1.1.1"]'
```

## Files

- `site.yml` — Main playbook
- `scan.yml` — Read-only scan
- `apply.yml` — Apply remediations
- `inventory/hosts.ini` — Target hosts
- `group_vars/all.yml` — Default settings
- `roles/cis_sles15/` — Role with engine + rules

## Engine

Powered by the shared `cis_engine.py` which runs on any Linux distribution.
The catalog (`rules.json`) contains CIS SUSE Linux Enterprise 15 Benchmark v2.0.1 rules.
