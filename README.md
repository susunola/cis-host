> ⚠️ **Not affiliated with, endorsed by, or sponsored by the Center for Internet
> Security (CIS).** See [DISCLAIMER.md](./DISCLAIMER.md). `ohbs-host`
> implements hardening *aligned with* the CIS Benchmarks™; it references CIS as
> a standard only.

# oh baseline host

> **Repository / CLI / package:** `ohbs-host`
> Full name: **oh baseline host** — part of the **oh baseline** (ohbs) family,
> **Open Source Hardened Baseline**.

Ansible playbooks and a local CLI that run hardening baselines against
**10 Linux distributions and 4 Windows Server versions**.

- Two modes: `scan` (read-only assessment) and `apply` (remediate)
- Per-host HTML reports with structured audit logs
- **4,400+ rules, zero third-party dependencies**
- Each suite ships a single-file engine (Python 3 on Linux, PowerShell on Windows)

## Install (from source — only supported method)

```bash
git clone https://github.com/susunola/ohbs-host.git
cd ohbs-host
pip install -e .
```

> Not published to PyPI. Ansible role dirs resolve relative to the source
> checkout at runtime, so an editable install (`-e .`) is mandatory.

Windows engine uses PowerShell 5.1+; Linux uses Python 3.6+. Configuration is
TOML (`ohbs-host.toml`); the legacy `ciscvm.toml` auto-falls back with a
deprecation warning.

## Commands

| Command | Purpose |
|---------|---------|
| `ohbs-host list` | list supported OS presets |
| `ohbs-host scan` | read-only assessment |
| `ohbs-host apply` | remediate (requires root / Admin) |
| `ohbs-host audit` | strict CI gate (exit non-zero on findings) |
| `ohbs-host fleet scan` | scan multiple hosts, aggregate |
| `ohbs-host diff` | compare two scan results (drift) |
| `ohbs-host watch` | periodic scan loop with alerting |
| `ohbs-host remediate` | fix only rules that failed in a previous scan |
| `ohbs-host info` | rule info |

Key flags: `--os`, `--profile L1|L2`, `--output`, `--config` / `$OHBS_HOST_CONFIG`,
`--evidence-dir`, `--webhook`, `--result`, `--fail-on-expired-waiver`,
`--simulate`, `--include`, `--exclude`, `--sections`, `--families`,
`--audit-log`, `--allow-disruptive`, `--variables`, `--waivers`, `--fleet-hosts`,
`--fleet-remote`, `--interval`, `--alert-cmd`, `--json`, `--exit-code`.

## Usage

```bash
ohbs-host list

# L1 scan (read-only)
ohbs-host scan --os rhel9 --profile L1 --output output/

# L1 apply (remediate)
ohbs-host apply --os ubuntu2204 --profile L1 --output output/

# audit / gate mode
ohbs-host audit --os rhel9 --profile L1 --output output/

# fleet scan
ohbs-host fleet scan --os rhel9 --fleet-hosts web1,web2,db1 --output output/

# tailor inputs and waive exceptions
ohbs-host scan --os rhel9 --variables '{"min_len": 14}' \
  --waivers '{"1.1.1.1": "legacy app exception"}'

# dry-run remediation
ohbs-host apply --os rhel9 --simulate

# drift detection
ohbs-host diff output/result-before.json output/result-after.json --exit-code

# periodic watch
ohbs-host watch --os rhel9 --interval 21600 --alert-cmd "curl -fsS https://hooks.example.com/alert"

# remediate from previous scan
ohbs-host remediate --os rhel9 --result output/result-scan-*.json
```

Via Ansible:

```bash
ansible-playbook -i ohbs-rhel9-ansible/inventory/hosts.ini ohbs-rhel9-ansible/scan.yml
ansible-playbook -i ohbs-rhel9-ansible/inventory/hosts.ini ohbs-rhel9-ansible/apply.yml \
  -e ohbs_profile=L2 -e ohbs_allow_disruptive=true
```

Exporters (`python3 scripts/export_*.py`): SARIF, XCCDF, JUnit, Prometheus,
PDF (`pip install -e .[pdf]` for WeasyPrint), history, tailoring.

## Supported targets (suites)

Linux: tencentos3/4, rhel8/9/10, sles15/16, ubuntu2004/2204/2404.
Windows: win2016/2019/2022/2025.

## License

MIT — see [LICENSE](./LICENSE).
