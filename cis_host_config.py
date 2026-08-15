#!/usr/bin/env python3
"""Load and merge cis-host.toml configuration with CLI arguments."""

import os
import sys


def _import_tomllib():
    """Return a tomllib-compatible module (stdlib 3.11+ or tomli fallback)."""
    try:
        import tomllib
        return tomllib
    except ImportError:
        try:
            import tomli as tomllib
            return tomllib
        except ImportError:
            return None


def load(path):
    """Load a cis-host.toml file and return a normalized dict.

    Returns None if the file does not exist. Raises RuntimeError on parse
    failure when tomllib/tomli is unavailable.
    """
    if not path or not os.path.isfile(path):
        return None
    tomllib = _import_tomllib()
    if tomllib is None:
        raise RuntimeError(
            "cis-host.toml requires Python 3.11+ or `pip install tomli`"
        )
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _get(cfg, *keys, default=None):
    """Safely descend into nested dicts."""
    node = cfg
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node


def _normalize_list(value):
    """Accept str, list, or None and return a comma-separated string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def _normalize_bool(value):
    """Return bool or the original value if not bool-like."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return bool(value)


def _set_if_none(args, attr, value):
    """Set args.attr = value only if the attribute is currently None."""
    if getattr(args, attr, None) is None:
        setattr(args, attr, value)


def merge(args, config_path=None):
    """Merge cis-host.toml defaults into argparse args object.

    CLI arguments always take precedence over config-file values. Only keys
    that are not set (None) on args are filled from the config.
    """
    if config_path is None:
        config_path = os.environ.get("CIS_HOST_CONFIG") or os.environ.get("CISCVM_CONFIG") or "cis-host.toml"
        # Legacy config fallback: keep reading ciscvm.toml when the default
        # cis-host.toml is absent, so existing pipelines are not broken.
        if config_path == "cis-host.toml" and not os.path.exists(config_path) and os.path.exists("ciscvm.toml"):
            print("cis-host: legacy ciscvm.toml found — please rename it to cis-host.toml "
                  "(ciscvm.toml support will be removed in a future release).", file=sys.stderr)
            config_path = "ciscvm.toml"

    cfg = load(config_path)
    if not cfg:
        return args

    profile_cfg = _get(cfg, "profile", default={})
    if profile_cfg:
        _set_if_none(args, "os", profile_cfg.get("os", ""))
        _set_if_none(args, "profile", profile_cfg.get("profile"))
        _set_if_none(args, "platform", profile_cfg.get("platform"))
        _set_if_none(args, "name", profile_cfg.get("name"))
        _set_if_none(args, "version", profile_cfg.get("version"))
        _set_if_none(args, "org", profile_cfg.get("org", ""))

    rules_cfg = _get(cfg, "rules", default={})
    if rules_cfg:
        _set_if_none(args, "include", _normalize_list(rules_cfg.get("include", "")))
        _set_if_none(args, "exclude", _normalize_list(rules_cfg.get("exclude", "")))
        _set_if_none(args, "sections_filter", _normalize_list(rules_cfg.get("sections", "")))
        _set_if_none(args, "families", _normalize_list(rules_cfg.get("families", "")))

    output_cfg = _get(cfg, "output", default={})
    if output_cfg:
        _set_if_none(args, "output", output_cfg.get("directory"))
        _set_if_none(args, "format", output_cfg.get("format"))
        _set_if_none(args, "copy_json", _normalize_bool(output_cfg.get("copy_json")) if "copy_json" in output_cfg else None)
        _set_if_none(args, "strict", _normalize_bool(output_cfg.get("strict")) if "strict" in output_cfg else None)

    engine_cfg = _get(cfg, "engine", default={})
    if engine_cfg:
        _set_if_none(args, "timeout", engine_cfg.get("timeout"))
        _set_if_none(args, "allow_disruptive", _normalize_bool(engine_cfg.get("allow_disruptive")) if "allow_disruptive" in engine_cfg else None)
        _set_if_none(args, "backup_dir", engine_cfg.get("backup_dir", ""))
        _set_if_none(args, "audit_log", engine_cfg.get("audit_log", ""))

    # Tailoring: rule input variables and waivers/exception tracking.
    variables_cfg = _get(cfg, "variables", default={})
    if variables_cfg:
        _set_if_none(args, "variables", variables_cfg)

    waivers_cfg = _get(cfg, "waivers", default={})
    if waivers_cfg:
        # Support both:
        #   [waivers]
        #   "1.1.1.1" = "legacy app"
        # and:
        #   [waivers.rules]
        #   "1.1.1.1" = { reason = "legacy app", approved_by = "..." }
        if "rules" in waivers_cfg and isinstance(waivers_cfg["rules"], dict):
            _set_if_none(args, "waivers", waivers_cfg["rules"])
        else:
            _set_if_none(args, "waivers", waivers_cfg)

    # Audit gate configuration (mostly for documentation/defaults).
    audit_cfg = _get(cfg, "audit", default={})
    if audit_cfg:
        if "strict" in audit_cfg:
            _set_if_none(args, "strict", _normalize_bool(audit_cfg.get("strict")))

    # Fleet scan configuration.
    fleet_cfg = _get(cfg, "fleet", default={})
    if fleet_cfg:
        _set_if_none(args, "fleet", fleet_cfg)

    return args
