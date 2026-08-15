"""Engine invocation: run cis_engine.py (Linux) / cis_engine.ps1 (Windows),
plus small helpers for tailoring-argument materialization and host facts
collection used when rendering reports.
"""

import json
import os
import random
import subprocess
import sys
import time

import ciscvm_diff


# ─── Platform detection helpers ───────────────────────────────────────

def is_windows():
    return sys.platform == "win32"

def default_shell():
    return "powershell" if is_windows() else "/bin/bash"


# ─── Engine runner ────────────────────────────────────────────────────

def _engine_is_windows(args):
    """Determine whether the selected engine is the Windows PowerShell variant.

    The engine type follows the --os preset or the explicit --engine path, not
    the platform the CLI happens to be running on.
    """
    if args.os and args.os.startswith("win"):
        return True
    if args.engine and args.engine.lower().endswith(".ps1"):
        return True
    return False


def _materialize_json_arg(value, label, output_dir):
    """Return a path to a JSON file containing `value`.

    `value` may already be a filesystem path, an inline JSON string, or a
    Python dict (from a config file).  The engine accepts both files and
    inline JSON; normalising to a file keeps long payloads out of the command
    line and avoids shell-quoting mistakes.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, dict):
        data = value
    elif isinstance(value, str):
        v = value.strip()
        if os.path.isfile(v):
            return os.path.abspath(v)
        try:
            data = json.loads(v)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} is not a valid JSON string or file: {exc}")
    else:
        raise ValueError(f"{label} must be a JSON string, file path, or dict")

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{label}-{int(time.time())}-{random.randint(0, 9999):04d}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def _waiver_catalog_ids(args):
    """Known rule ids for the target catalog, so a typo'd waiver id (a
    silent no-op exception) can be flagged. Returns None when unknown."""
    catalog_path = getattr(args, "catalog", None)
    if not catalog_path or not os.path.isfile(catalog_path):
        return None
    try:
        with open(catalog_path, "r", encoding="utf-8") as fh:
            catalog = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    rules = catalog if isinstance(catalog, list) else catalog.get("rules", [])
    ids = {str(r["id"]) for r in rules if isinstance(r, dict) and r.get("id")}
    return ids or None


def run_engine(args, mode):
    """Run cis_engine (Python or PowerShell) and return parsed JSON result."""
    engine = os.path.abspath(args.engine)
    catalog = os.path.abspath(args.catalog)
    engine_dir = os.path.dirname(os.path.abspath(args.engine))
    output_dir = os.path.abspath(args.output)

    result_file = os.path.join(
        output_dir,
        f"result-{mode}-{int(time.time())}-{random.randint(0, 9999):04d}.json"
    )
    os.makedirs(os.path.dirname(result_file), exist_ok=True)

    # Normalise tailoring arguments to JSON files so the engine can load them
    # reliably.  We do this even for scan mode so shared helpers stay simple.
    variables_path = ""
    waivers_path = ""
    if getattr(args, "variables", None):
        try:
            variables_path = _materialize_json_arg(args.variables, "variables", output_dir)
        except ValueError as exc:
            print(f"[{mode.upper()}] {exc}", file=sys.stderr)
            sys.exit(1)
    if getattr(args, "waivers", None):
        try:
            waivers_path = _materialize_json_arg(args.waivers, "waivers", output_dir)
        except ValueError as exc:
            print(f"[{mode.upper()}] {exc}", file=sys.stderr)
            sys.exit(1)

    # Waiver hygiene: warn on expired / malformed waiver metadata, and on
    # waiver ids that do not exist in the catalog (a typo'd id is a silent
    # no-op exception). Expired exceptions should not linger silently.
    if waivers_path:
        try:
            with open(waivers_path, "r", encoding="utf-8") as fh:
                waivers_doc = json.load(fh)
        except (OSError, json.JSONDecodeError):
            waivers_doc = None
        if waivers_doc is not None:
            for problem in ciscvm_diff.waiver_problems(
                    waivers_doc, _waiver_catalog_ids(args)):
                print(f"  [waivers] {problem}", file=sys.stderr)

    if not _engine_is_windows(args):
        # Linux: run cis_engine.py with python3
        cmd = [
            "sudo", "python3", engine,
            "--catalog", catalog,
            "--mode", mode,
            "--profile", args.profile,
            "--platform", args.platform,
            "--benchmark", args.name,
            "--out", result_file,
        ]
        if args.include:
            cmd += ["--include", args.include]
        if args.exclude:
            cmd += ["--exclude", args.exclude]
        if args.sections_filter:
            cmd += ["--sections", args.sections_filter]
        if args.families:
            cmd += ["--families", args.families]
        if args.allow_disruptive:
            cmd.append("--allow-disruptive")
        if args.backup_dir:
            cmd += ["--backup-dir", os.path.abspath(args.backup_dir)]
        if args.audit_log:
            cmd += ["--audit-log", os.path.abspath(args.audit_log)]
        if variables_path:
            cmd += ["--variables", variables_path]
        if waivers_path:
            cmd += ["--waivers", waivers_path]
        if getattr(args, "simulate", False):
            cmd.append("--simulate")
    else:
        # Windows: run cis_engine.ps1 with powershell
        cmd = [
            "powershell", "-ExecutionPolicy", "Bypass", "-File", engine,
            "-Catalog", catalog,
            "-Mode", mode,
            "-Profile", args.profile,
            "-Platform", args.platform,
            "-Benchmark", args.name,
            "-Out", result_file,
        ]
        if args.include:
            cmd += ["-Include", args.include]
        if args.exclude:
            cmd += ["-Exclude", args.exclude]
        if args.sections_filter:
            cmd += ["-Sections", args.sections_filter]
        if args.families:
            cmd += ["-Families", args.families]
        if args.allow_disruptive:
            cmd.append("-AllowDisruptive")
        if args.backup_dir:
            cmd += ["-BackupDir", os.path.abspath(args.backup_dir)]
        if args.audit_log:
            cmd += ["-AuditLog", os.path.abspath(args.audit_log)]
        # Note: Windows PowerShell engine does not yet support variables/waivers/simulate.

    print(f"[{mode.upper()}] Running: {' '.join(cmd)}")
    started = time.time()

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=args.timeout,
            stdin=subprocess.DEVNULL, cwd=engine_dir
        )
        elapsed = time.time() - started
        print(f"[{mode.upper()}] Exit: {proc.returncode}  Duration: {elapsed:.1f}s")
    except subprocess.TimeoutExpired:
        print(f"[{mode.upper()}] TIMEOUT after {args.timeout}s", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"[{mode.upper()}] Engine not found: {e}", file=sys.stderr)
        sys.exit(1)

    if proc.returncode != 0:
        print(f"[{mode.upper()}] Engine stderr:\n{proc.stderr[:1000]}", file=sys.stderr)
        if len(proc.stderr) > 1000:
            print(f"[{mode.upper()}] ... (truncated, {len(proc.stderr)} chars total)", file=sys.stderr)
        # For scan mode, engine errors are usually pre-checks (e.g. not root)
        # — still try to read the JSON if it was written.
        if mode == "scan" and not os.path.exists(result_file):
            sys.exit(proc.returncode)

    if not os.path.exists(result_file):
        print(f"[{mode.upper()}] No result JSON produced", file=sys.stderr)
        sys.exit(1)

    try:
        with open(result_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[{mode.upper()}] Result JSON corrupt: {exc}", file=sys.stderr)
        sys.exit(1)

    return data, result_file


# ─── Host facts collector ─────────────────────────────────────────────

def collect_host():
    """Collect host information — mirrors what cis_engine records."""
    import platform
    import socket

    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": "",
        "kernel": platform.release(),
        "arch": platform.machine(),
        "virtualization": "",
        "ipv4": [],
        "ipv6": [],
        "mac": [],
        "interfaces": {},
        "uptime_seconds": 0,
        "ssh_address": socket.gethostname(),
    }

    # OS name
    if sys.platform.startswith("linux"):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["os"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except (OSError, UnicodeDecodeError):
            pass
    elif sys.platform == "darwin":
        info["os"] = f"macOS {platform.mac_ver()[0]}"
    elif sys.platform == "win32":
        info["os"] = platform.platform()

    # IPs — set a socket timeout so DNS misconfiguration doesn't hang
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(10)
    try:
        info["ipv4"] = [addr[4][0] for addr in
                        socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
                        if not addr[4][0].startswith("127.")]
    except (OSError, socket.gaierror, socket.timeout):
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)

    # Uptime (Linux)
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/uptime") as f:
                info["uptime_seconds"] = int(float(f.read().split()[0]))
        except (OSError, ValueError):
            pass

    return info
