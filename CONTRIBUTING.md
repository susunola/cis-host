# Contributing to cis-host

Thanks for your interest in contributing.

## Scope

This project automates CIS Benchmark compliance checks and remediations. Contributions are welcome in these areas:

- **New OS support** — adding a new Linux distribution or Windows Server version
- **Rule fixes** — correcting check logic, false positives, or remediation issues
- **CLI improvements** — enhancements to `cis_cli.py` and its supporting modules (`args.py`, `dispatch.py`, `commands_scan.py`, `commands_watch.py`, `fleet.py`, `info.py`, `report.py`, `display.py`, `engine.py`, `presets.py`, `catalog.py`, `defaults.py`)
- **Report templates** — improving the HTML/CSV report experience
- **Documentation** — fixing errors or improving clarity across the 4 README languages

## Pull request workflow

1. Fork the repository and create a feature branch from `main`.
2. If adding a new OS suite, copy the closest existing suite as a starting point.
3. Run at least one `scan` against a real or test target before opening the PR.
4. Open a PR with a description of the change and any relevant test output.

## Report guidelines

- Bug reports should include the OS version, CIS profile (L1/L2), mode (scan/apply), and the relevant rule ID.
- Feature requests are welcome but please check existing issues first.

## Code conventions

- Engine code is Python 3.6+ (Linux) or PowerShell 5.1+ (Windows). Keep zero third-party dependencies.
- Template logic uses Jinja2. Keep reports self-contained (no CDN assets, fully offline).
- Ansible playbooks target a single OS per role. Cross-OS logic lives in the engine, not in Ansible.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
