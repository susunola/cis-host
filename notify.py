"""Evidence snapshot and webhook notification helpers.

`collect_evidence` packs a run's engine result JSON, effective config,
host facts, and per-rule detail into a <host>-<timestamp>-evidence.tar.gz.
`send_webhook` POSTs a compact JSON run summary to a configured URL; it is
strictly fire-and-warn so notification never blocks or fails a run.
"""

import io
import json
import os
import sys
import tarfile
import time
import urllib.request
from datetime import datetime, timezone

from engine import collect_host


def _tar_add_text(tar, arcname, text):
    """Add an in-memory text payload to an open tarfile."""
    payload = text.encode("utf-8")
    info = tarfile.TarInfo(arcname)
    info.size = len(payload)
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(payload))


def collect_evidence(args, result_data, result_file, mode):
    """Pack scan evidence into <hostname>-<timestamp>-evidence.tar.gz.

    The archive contains the engine result JSON, the effective cis-host.toml
    (if one was used), host facts, and one text file per rule holding its
    detail plus the extra per-rule fields recorded by the engine.
    Returns the archive path, or None when evidence collection is disabled.
    """
    evidence_dir = getattr(args, "evidence_dir", "") or ""
    if not evidence_dir:
        return None
    evidence_dir = os.path.abspath(evidence_dir)
    os.makedirs(evidence_dir, exist_ok=True)

    host = result_data.get("host", {}).get("hostname", "localhost")
    slug = "".join(c if c.isalnum() or c in "._-" else "_" for c in host)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tar_path = os.path.join(evidence_dir, f"{slug}-{stamp}-evidence.tar.gz")

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(result_file, arcname="result.json")

        # Effective config file, when one was loaded
        cfg_path = getattr(args, "config", "") or os.environ.get("CIS_HOST_CONFIG", "cis-host.toml")
        if cfg_path and os.path.isfile(cfg_path):
            tar.add(cfg_path, arcname="cis-host.toml")

        # Host facts (engine record wins over locally collected values)
        host_info = collect_host()
        host_info.update(result_data.get("host", {}))
        _tar_add_text(tar, "host.json", json.dumps(host_info, indent=2))

        # Per-rule evidence: metadata header + full detail text
        for r in result_data.get("results", []):
            rid = r.get("id", "unknown")
            lines = [
                f"rule:          {rid}",
                f"title:         {r.get('title', '')}",
                f"section:       {r.get('section', '')}",
                f"status:        {r.get('status', '')}",
                f"family:        {r.get('family', '')}",
                f"risk:          {r.get('risk', '')}",
                f"duration_ms:   {r.get('duration_ms', 0)}",
            ]
            if r.get("status_before"):
                lines.append(f"status_before: {r['status_before']}")
            if r.get("apply_status") and r.get("apply_status") != "n/a":
                lines.append(f"apply_status:  {r['apply_status']}")
            if r.get("apply_detail"):
                lines.append(f"apply_detail:  {r['apply_detail']}")
            if r.get("waived"):
                lines.append(f"waived:        {r['waived']}")
                lines.append(f"waiver:        {json.dumps(r.get('waiver'))}")
            lines.append("")
            lines.append("detail:")
            lines.append(str(r.get("detail", "")))
            _tar_add_text(tar, f"rules/rule-{rid}.txt", "\n".join(lines) + "\n")

    print(f"Evidence saved: {tar_path}")
    return tar_path


def send_webhook(args, mode, data, report_path):
    """POST a JSON summary to the configured webhook URL.

    Delivery failures only produce a warning — notification must never
    block or fail a scan/apply run.
    """
    url = getattr(args, "webhook", "") or ""
    if not url:
        return False

    s = data.get("summary", {}).get("all", {})
    payload = {
        "hostname": data.get("host", {}).get("hostname", "unknown"),
        "mode": mode,
        "score": s.get("score", 0),
        "pass": s.get("pass", 0),
        "fail": s.get("fail", 0),
        "error": s.get("error", 0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report": report_path or "",
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"Webhook delivered: {url} (HTTP {resp.status})")
        return True
    except Exception as exc:
        print(f"Warning: webhook delivery failed ({url}): {exc}", file=sys.stderr)
        return False
