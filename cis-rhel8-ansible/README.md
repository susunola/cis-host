# CIS Red Hat Enterprise Linux 8 Ansible Playbook

Automated CIS Benchmark assessment for Red Hat Enterprise Linux 8.

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
- `roles/cis_rhel8/` — Role with engine + rules

## Engine

Powered by the shared Python 3 CIS engine.
The catalog (`rules.json`) contains CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0 rules.
