# CIS Ubuntu Linux 20.04 LTS Ansible Playbook

Automated CIS Benchmark assessment for Ubuntu Linux 20.04 LTS.

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
- `roles/cis_ubuntu2004/` — Role with engine + rules

## Engine

Powered by the shared Python 3 CIS engine.
The catalog (`rules.json`) contains CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 rules.
