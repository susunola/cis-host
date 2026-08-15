#!/usr/bin/env python3
"""
CIS Benchmark CLI — scan, apply, audit, fleet scan, with HTML + CLI output.

Installable as the `cis-host` command after `pip install cis-host`.

Usage:
  # Scan only (check compliance)
  cis-host scan --os rhel9 --profile L1 --output output/

  # Apply then re-scan (combined)
  cis-host apply --os rhel9 --profile L1 --output output/

  # Audit / gate mode (exit non-zero on findings)
  cis-host audit --os rhel9 --profile L1 --output output/

  # Fleet scan across multiple hosts
  cis-host fleet scan --os rhel9 --fleet-hosts web1,web2 --output output/

  # Fine-grained: run specific rules by ID
  cis-host scan --os rhel9 --include "1.1.1.1,1.1.1.2,5.1.1" --output output/

  # Tailor rule inputs and waive exceptions
  cis-host scan --os rhel9 --variables '{"min_len": 14}' --waivers '{"1.1.1.1": "legacy app"}'

  # Dry-run remediation
  cis-host apply --os rhel9 --simulate

  # Use a config file (cis-host.toml)
  cis-host scan --config cis-host.toml

  # View rule detail (CLI)
  cis-host info --os rhel9 --id 1.1.1.1

Supported --os values:
  tencentos3, tencentos4
  rhel8, rhel9, rhel10
  sles15, sles16
  ubuntu2004, ubuntu2204, ubuntu2404
  win2016, win2019, win2022, win2025
"""

import dispatch


def main():
    dispatch.run()


if __name__ == "__main__":
    main()
