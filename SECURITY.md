# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | ✅ |
| Tagged releases | ✅ |
| Historical commits | ❌ |

## Reporting a vulnerability

If you discover a security vulnerability in cis-host (e.g., a rule that introduces a misconfiguration, an insecure default, or a privilege escalation path), please report it responsibly.

**Do not open a public issue.** Instead, email the maintainers directly.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation within 14 days.

## Scope

The following are in scope:

- Automation logic that would weaken the target system's security posture
- Hard-coded credentials or secrets in source code
- Insecure defaults in the engine or wrapper scripts
- Template-level XSS in the HTML reports

The following are out of scope:

- CIS Benchmark content errors (report to CIS directly)
- Ansible itself or third-party Ansible modules
- Target OS vulnerabilities that are not introduced by the automation

## Remediation policy

After a fix is merged, we will tag a release and update the advisory. Users running from `main` will receive the fix immediately; tagged-release users should upgrade to the patched version.
