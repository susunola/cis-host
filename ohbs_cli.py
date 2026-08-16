#!/usr/bin/env python3
"""
ohbs-host CLI — CIS Benchmark scan, apply, audit, fleet scan, with HTML + CLI output.

Installable as the `ohbs-host` command after `pip install ohbs-host`.

Usage:
  # Scan only (check compliance)
  ohbs-host scan --os rhel9 --profile L1 --output output/

  # Apply then re-scan (combined)
  ohbs-host apply --os rhel9 --profile L1 --output output/

  # Audit / gate mode (exit non-zero on findings)
  ohbs-host audit --os rhel9 --profile L1 --output output/

  # Fleet scan across multiple hosts
  ohbs-host fleet scan --os rhel9 --fleet-hosts web1,web2 --output output/

  # Fine-grained: run specific rules by ID
  ohbs-host scan --os rhel9 --include "1.1.1.1,1.1.1.2,5.1.1" --output output/

  # Tailor rule inputs and waive exceptions
  ohbs-host scan --os rhel9 --variables '{"min_len": 14}' --waivers '{"1.1.1.1": "legacy app"}'

  # Dry-run remediation
  ohbs-host apply --os rhel9 --simulate

  # Use a config file (ohbs-host.toml)
  ohbs-host scan --config ohbs-host.toml

  # View rule detail (CLI)
  ohbs-host info --os rhel9 --id 1.1.1.1

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
