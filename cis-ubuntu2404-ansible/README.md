# CIS Ubuntu Linux 24.04 LTS Ansible Playbook

Automated CIS Benchmark assessment for Ubuntu Linux 24.04 LTS.

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
- `roles/cis_ubuntu2404/` — Role with engine + rules

## Engine

Powered by a Python 3 engine tailored for this distribution.
The catalog (`rules.json`) contains CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 rules.
