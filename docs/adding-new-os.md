# Adding a new OS suite to CIS-OS

This repository keeps each OS suite self-contained rather than sharing a single base
role. This makes it easy to fork or vendor just the suite you need, but it also means
adding a new OS means copying the layout and tailoring the engine + rules.

## Quick checklist

1. Create `cis-<os>-ansible/` with the standard files:
   - `ansible.cfg`
   - `inventory/hosts.ini`
   - `group_vars/all.yml`
   - `scan.yml`, `apply.yml`
   - `roles/cis_<os>/`
2. Implement the engine:
   - Linux: `roles/cis_<os>/files/cis_engine.py`
   - Windows: `roles/cis_<os>/files/cis_engine.ps1`
3. Add the catalog files:
   - `roles/cis_<os>/files/rules.json`
   - `roles/cis_<os>/files/guidance.json`
   - `roles/cis_<os>/files/sections.json`
4. Add the report templates:
   - `roles/cis_<os>/templates/report.html.j2`
   - `roles/cis_<os>/templates/index.html.j2`
   - `roles/cis_<os>/templates/findings.csv.j2`
5. Add role metadata and task files:
   - `roles/cis_<os>/meta/main.yml`
   - `roles/cis_<os>/defaults/main.yml`
   - `roles/cis_<os>/vars/main.yml`
   - `roles/cis_<os>/tasks/{main,preflight,run,report,gate}.yml`
6. Validate:
   - `python scripts/validate_json.py`
   - `pytest -v`
   - `ansible-playbook --syntax-check cis-<os>-ansible/scan.yml`
   - `ansible-playbook --syntax-check cis-<os>-ansible/apply.yml`

## Rule catalog format

`rules.json` is an array of objects with these required fields:

```json
{
  "id": "1.1.1.1",
  "title": "Ensure cramfs kernel module is not available",
  "section": "1.1.1",
  "levels": [1],
  "platforms": ["Server", "Workstation"],
  "assessment": "Automated",
  "family": "kmod",
  "risk": "safe",
  "params": {"module": "cramfs"},
  "page": 24
}
```

`risk` must be one of:

- `safe` — can be remediated automatically without maintenance-window risk.
- `disruptive` — may disconnect sessions, reboot, or restart services; only applied
  when `cis_allow_disruptive=true`.
- `manual` / `info_only` / `partition` / `root_access` / `sshd_access` /
  `bootloader_password` — no automated fix; reported only.

## Keeping rules complete

Do not merge multiple benchmark controls into a single rule to "save space". Each
CIS control should map to one rule entry. If the engine does not yet automate a
control, use `"family": "manual"` and `"risk": "manual"` so the rule appears in
reports and scoring instead of being silently omitted.

## Engine safety requirements

Before any fix function writes configuration:

1. Back up the original file to `cis_backup_dir`.
2. Enforce `cis_backup_dir` permissions are `0700` and backup files `0600`.
3. Validate rule parameters against allow-lists before using them in commands.
4. Prefer `argv` lists over shell strings; never pass raw rule values to
   `subprocess.run(..., shell=True)`.
5. For changes that can lock the operator out (SSH, PAM, sudo, firewall, crypto
   policy, SELinux enforcing, mount options), tag the rule as `disruptive` and
   require `cis_allow_disruptive=true`.

## Testing

Add engine-level unit tests under `tests/` and include the new suite in
`.github/workflows/ci.yml` so `ansible-playbook --syntax-check` runs on every push.
