"""Fleet scan: run scan across multiple hosts (local-tagged or remote SSH)
and aggregate per-host results into a single fleet report (HTML + JSON).
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from engine import run_engine

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_TEMPLATE_PATH = os.path.join(_SCRIPT_DIR, "templates", "fleet_report.html.j2")


def _normalize_list(value):
    """Accept str, list, or None and return a comma-separated string."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def load_fleet_hosts(args):
    """Return a list of host identifiers from CLI or config."""
    hosts = []
    if getattr(args, "fleet_hosts", None):
        hosts = [h.strip() for h in args.fleet_hosts.split(",") if h.strip()]
    fleet_cfg = getattr(args, "fleet", {}) or {}
    if not hosts and fleet_cfg.get("hosts"):
        hosts = _normalize_list(fleet_cfg.get("hosts"))
        hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    return hosts


def run_remote_scan(host, args, fleet_cfg):
    """SSH to a host and run the engine remotely.  Returns parsed JSON or None."""
    user = fleet_cfg.get("user", "root")
    key = fleet_cfg.get("key", "")
    remote_engine = fleet_cfg.get("remote_engine", "/opt/ohbs-host/ohbs_engine.py")
    remote_catalog = fleet_cfg.get("remote_catalog", "/opt/ohbs-host/rules.json")
    remote_guidance = fleet_cfg.get("remote_guidance", "")
    remote_sections = fleet_cfg.get("remote_sections", "")
    remote_template = fleet_cfg.get("remote_template", "")
    ssh_opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        ssh_opts += ["-i", os.path.expanduser(key)]
    target = f"{user}@{host}"

    cmd = ["ssh"] + ssh_opts + [target, "sudo", "python3", remote_engine,
           "--catalog", remote_catalog,
           "--mode", "scan",
           "--profile", args.profile,
           "--platform", args.platform,
           "--benchmark", args.name,
           "--out", "-"]
    if args.include:
        cmd += ["--include", args.include]
    if args.exclude:
        cmd += ["--exclude", args.exclude]
    if args.sections_filter:
        cmd += ["--sections", args.sections_filter]
    if args.families:
        cmd += ["--families", args.families]

    print(f"[FLEET] ssh {target}: {' '.join(cmd[3 + len(ssh_opts):])}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout,
                              stdin=subprocess.DEVNULL)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"[FLEET] {host}: connection failed: {exc}", file=sys.stderr)
        return None

    if proc.returncode != 0:
        print(f"[FLEET] {host}: engine error: {proc.stderr[:500]}", file=sys.stderr)
        return None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        print(f"[FLEET] {host}: result JSON corrupt: {exc}", file=sys.stderr)
        return None

    # Ensure host identity reflects the fleet target
    data["host"] = data.get("host", {})
    data["host"]["hostname"] = host
    return data


def aggregate_fleet_results(host_results):
    """Combine per-host result dicts into a fleet summary."""
    fleet_results = []
    summaries = []
    for host, data in host_results:
        if not data:
            continue
        for r in data.get("results", []):
            r["_fleet_host"] = host
            fleet_results.append(r)
        s = data.get("summary", {}).get("all", {})
        s["_host"] = host
        summaries.append(s)

    # Roll up counts
    blank = {"total": 0, "pass": 0, "fail": 0, "manual": 0, "error": 0,
             "notapplicable": 0, "waived": 0}
    for s in summaries:
        for k in blank:
            blank[k] += s.get(k, 0)
    scored = blank["pass"] + blank["fail"]
    blank["score"] = round(100.0 * blank["pass"] / scored, 1) if scored else 0.0

    return {
        "mode": "fleet_scan",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "fleet_size": len(host_results),
        "reachable": len(summaries),
        "summaries": summaries,
        "summary": {"all": blank},
        "results": fleet_results,
    }


def render_fleet_report(aggregate, args):
    """Render the fleet HTML summary from templates/fleet_report.html.j2."""
    from jinja2 import Environment, FileSystemLoader

    now = datetime.now(timezone.utc).astimezone()
    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"fleet-report-{args.profile}-{now.strftime('%Y%m%d-%H%M%S')}.html")

    alls = aggregate.get("summary", {}).get("all", {})
    ctx = {
        "cis_benchmark_name": args.name,
        "cis_profile": args.profile,
        "cis_fleet_size": aggregate["fleet_size"],
        "cis_reachable": aggregate["reachable"],
        "cis_score": alls.get("score", 0),
        "cis_summaries": aggregate.get("summaries", []),
    }

    template_dir = os.path.dirname(_TEMPLATE_PATH)
    template_name = os.path.basename(_TEMPLATE_PATH)
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template(template_name)
    html_doc = template.render(**ctx)

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return out_path


def cmd_fleet_scan(args):
    """FLEET SCAN mode: scan multiple hosts and aggregate a fleet report."""
    hosts = load_fleet_hosts(args)
    if not hosts:
        print("Error: no fleet hosts configured. Use --fleet-hosts or [fleet] hosts in ohbs-host.toml",
              file=sys.stderr)
        sys.exit(1)

    fleet_cfg = getattr(args, "fleet", {}) or {}
    remote = getattr(args, "fleet_remote", False) or fleet_cfg.get("remote", False)

    print(f"\n╔══ CIS Benchmark — FLEET SCAN ══╗")
    print(f"║ Target:  {args.name}")
    print(f"║ Profile: {args.profile}")
    print(f"║ Hosts:   {', '.join(hosts)}")
    print(f"║ Remote:  {'SSH' if remote else 'local (tagged)'}")
    print(f"╚{'═'*26}╝\n")

    host_results = []
    for host in hosts:
        print(f"── Host: {host} ──")
        if remote:
            data = run_remote_scan(host, args, fleet_cfg)
        else:
            # Local mode: run on this machine but tag results with the host label.
            # Useful for testing and for CI fleets that run ohbs-host inside each node.
            data, _ = run_engine(args, "scan")
            if data:
                data["host"] = data.get("host", {})
                data["host"]["hostname"] = host
        host_results.append((host, data))
        if data:
            s = data.get("summary", {}).get("all", {})
            print(f"  score={s.get('score', 0):.1f}% pass={s.get('pass', 0)} fail={s.get('fail', 0)}")

    aggregate = aggregate_fleet_results(host_results)
    out_path = render_fleet_report(aggregate, args)
    print(f"\nFleet report saved: {out_path}")

    # Save aggregate JSON
    json_path = out_path.replace(".html", ".json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(aggregate, fh, indent=2)
    print(f"Fleet JSON saved:   {json_path}")

    return {"data": aggregate, "path": out_path}
