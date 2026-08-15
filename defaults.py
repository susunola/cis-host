"""Hard-coded default values for CLI args not set via CLI flags or config."""


def apply_defaults(args):
    """Apply hard-coded defaults for args that were not set via CLI or config."""
    defaults = {
        "profile": "L1",
        "platform": "server",
        "name": "CIS Benchmark",
        "version": "v1.0.0",
        "org": "",
        "include": "",
        "exclude": "",
        "sections_filter": "",
        "families": "",
        "output": "./output",
        "format": "both",
        "copy_json": False,
        "strict": False,
        "timeout": 600,
        "allow_disruptive": False,
        "backup_dir": "",
        "audit_log": "",
        "evidence_dir": "",
        "webhook": "",
        "variables": None,
        "waivers": None,
        "simulate": False,
        "fail_on_expired_waiver": False,
        "fleet": {},
        "fleet_hosts": "",
        "fleet_remote": False,
    }
    for key, value in defaults.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)
    return args
