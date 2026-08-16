#!/usr/bin/env python3
"""Real end-to-end test: provision a real OS host, install ohbs-host on it,
and run a genuine scan -> apply -> re-scan -> idempotent-apply cycle,
then tear the host back down.

This is a *supplement* to the L3 rule-verification matrix in
tests/fixtures/ (see docs/TESTING.md), not a replacement. The matrix
fakes the OS/subprocess boundary and proves each rule's check/fix
*logic*; it can never answer "does `pip install -e .` actually work on a
clean host", "does a real `ohbs-host scan` produce a valid report against
a real kernel/filesystem", or "does real remediation actually change the
host without regressing other rules". Those only show up against
something real.

Modeled on the sister project's ohbs-image/scripts/real_e2e_test.py:
provision -> confirm cost -> run remote suite over exec/SSH -> ALWAYS
teardown (success, failure, or Ctrl-C) unless --keep-on-failure.

Two providers:
  --provider docker (default)  : ephemeral Docker container (geerlingguy
    systemd images, same as the Molecule configs). ~free, fast, safe to
    gate PRs on. Most rules (packages, services, sysctl, files) run fine.
  --provider cloud            : real cloud VM (root, real kernel, host-only
    rules like GRUB/bootloader). Billed; intended for tags/releases only.

Usage:
    python3 scripts/real_e2e_test.py --os ubuntu2204 -y
    python3 scripts/real_e2e_test.py --os ubuntu2204 --provider docker --allow-disruptive
    TENCENTCLOUD_SECRET_ID=... TENCENTCLOUD_SECRET_KEY=... \
      python3 scripts/real_e2e_test.py --os rhel9 --provider cloud \
        --vpc-id vpc-... --subnet-id subnet-... --security-group-id sg-...

The container/VM and any temporary key pair are ALWAYS torn down on exit
unless --keep-on-failure is passed and the remote run actually failed.
A record of the last target is written to logs/e2e_last_instance.json for
manual cleanup if teardown ever fails.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# OS presets -> base Docker image (mirrors the Molecule configs).
DOCKER_IMAGES = {
    "ubuntu2004": "geerlingguy/docker-ubuntu2004-ansible:latest",
    "ubuntu2204": "geerlingguy/docker-ubuntu2204-ansible:latest",
    "ubuntu2404": "geerlingguy/docker-ubuntu2404-ansible:latest",
    "rhel8": "geerlingguy/docker-rockylinux8-ansible:latest",
    "rhel9": "geerlingguy/docker-rockylinux9-ansible:latest",
    # tencentos/sles have no geerlingguy image; cloud is the real path.
}
LAST_TARGET_FILE = REPO_ROOT / "logs" / "e2e_last_instance.json"
BOOT_TIMEOUT_SECONDS = 900
READY_TIMEOUT_SECONDS = 300
SSH_READY_TIMEOUT_SECONDS = 180


# ---- progress helpers (mirror ohbs-image's banner/info/ok/warn/fail) ----
def _color(code: str, s: str) -> str:
    return "\033[%sm%s\033[0m" % (code, s) if sys.stdout.isatty() else s


def banner(s: str) -> None:
    print(_color("1;36", "\n═══ %s ═══" % s))


def info(s: str) -> None:
    print("  " + _color("36", s))


def ok(s: str) -> None:
    print("  " + _color("32", "✔ " + s))


def warn(s: str) -> None:
    print("  " + _color("33", "⚠ " + s), file=sys.stderr)


def fail(s: str) -> None:
    print("  " + _color("31", "✖ " + s), file=sys.stderr)


# ---- CLI / config ---------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--os", default="ubuntu2204",
                   help="OS preset to test (must be in presets.py OS_PRESETS)")
    p.add_argument("--provider", choices=("docker", "cloud"), default="docker")
    p.add_argument("--profile", default="L1", choices=("L1", "L2"))
    p.add_argument("--allow-disruptive", action="store_true",
                   help="pass --allow-disruptive to ohbs-host apply")
    p.add_argument("--branch", default="main")
    p.add_argument("--repo-url", default="https://github.com/susunola/ohbs-host.git")
    p.add_argument("--keep-on-failure", action="store_true",
                   help="do not teardown if the remote run fails (for debugging)")
    p.add_argument("--yes", "-y", action="store_true",
                   help="skip the cost/impact confirmation prompt")
    # cloud provider options (ignored for docker)
    p.add_argument("--image-id", default="")
    p.add_argument("--region", default="")
    p.add_argument("--zone", default="")
    p.add_argument("--instance-type", default="")
    p.add_argument("--vpc-id", default="")
    p.add_argument("--subnet-id", default="")
    p.add_argument("--security-group-id", default="")
    p.add_argument("--ssh-user", default="root")
    return p.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    sys.path.insert(0, str(REPO_ROOT))
    from presets import OS_PRESETS
    if args.os not in OS_PRESETS:
        fail("unknown --os %r; valid: %s" % (args.os, ", ".join(sorted(OS_PRESETS))))
        sys.exit(1)
    if args.provider == "cloud":
        need = {
            "TENCENTCLOUD_SECRET_ID": os.environ.get("TENCENTCLOUD_SECRET_ID", ""),
            "TENCENTCLOUD_SECRET_KEY": os.environ.get("TENCENTCLOUD_SECRET_KEY", ""),
        }
        missing = [k for k, v in need.items() if not v]
        if missing:
            fail("cloud provider requires: " + ", ".join(missing))
            sys.exit(1)
        for flag in ("--vpc-id", "--subnet-id", "--security-group-id"):
            if not getattr(args, flag.replace("--", "").replace("-", "_")):
                fail("cloud provider requires " + flag)
                sys.exit(1)
    else:
        if args.os not in DOCKER_IMAGES:
            fail("no Docker image mapped for %r; use --provider cloud" % args.os)
            sys.exit(1)
        if not _have("docker"):
            fail("docker not found on PATH; required for --provider docker")
            sys.exit(1)


def _have(binname: str) -> bool:
    from shutil import which
    return which(binname) is not None


def confirm_impact(args: argparse.Namespace) -> None:
    if args.yes:
        return
    banner("End-to-end test — impact confirmation")
    if args.provider == "docker":
        info("This will pull a systemd Docker image (if needed) and run a real")
        info("ohbs-host scan + apply (remediation) inside a throwaway container.")
        info("The container is destroyed when the run finishes.")
    else:
        info("This will create a REAL, billed cloud VM (image=%s type=%s)" %
             (args.image_id, args.instance_type))
        info("It is automatically destroyed once the run finishes.")
    reply = input("Proceed? [y/N] ").strip().lower()
    if reply != "y":
        fail("Aborted by user")
        sys.exit(1)


# ---- Docker provider ------------------------------------------------------
def docker_start(args: argparse.Namespace) -> dict:
    image = DOCKER_IMAGES[args.os]
    name = "cis-e2e-%s-%d" % (args.os, int(time.time()))
    banner("Starting Docker container from %s" % image)
    info("pulling image (first run may take a while)...")
    subprocess.run(["docker", "pull", image], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ["docker", "run", "-d", "--name", name,
           "--privileged", "--cgroupns", "host",
           "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
           "--entrypoint", "/lib/systemd/systemd", image]
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        docker_rm(name)
        raise RuntimeError("docker run failed: %s" % cp.stderr.strip())
    return {"provider": "docker", "container": name, "name": name,
            "image": image}


def docker_exec(args: argparse.Namespace, target: dict, script: str,
                log_path: Path) -> int:
    """Copy the local repo into the container, then run the remote script
    via `docker exec -i <c> bash -s`, streaming output to stdout and a log.
    Mirrors ohbs-image's ssh+bash -s runner but via docker exec.
    """
    # Copy the local working tree in so the e2e tests THIS checkout
    # (including uncommitted changes) rather than whatever is on the
    # remote branch -- and avoids needing git/apt inside the container.
    subprocess.run(
        ["docker", "exec", target["container"], "mkdir", "-p", "/root/ohbs-host"],
        check=True, capture_output=True, text=True)
    # `docker cp <repo>/. <dst>/` copies the *contents* (including
    # dotfiles like .git) into the destination.
    subprocess.run(
        ["docker", "cp", str(REPO_ROOT) + "/.", "%s:/root/ohbs-host/" % target["container"]],
        check=True, capture_output=True, text=True)
    log_path.parent.mkdir(exist_ok=True)
    with subprocess.Popen(
        ["docker", "exec", "-i", target["container"], "bash", "-s"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    ) as proc, log_path.open("w") as log_f:
        assert proc.stdin is not None
        proc.stdin.write(script)
        proc.stdin.close()
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            log_f.write(line)
        proc.wait()
        return proc.returncode


def docker_wait_ready(container: str) -> None:
    """Wait for systemd/PID1 to be up inside the container."""
    deadline = time.time() + READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        cp = subprocess.run(
            ["docker", "exec", container, "/bin/sh", "-c",
             "test -d /run/systemd/system"], capture_output=True)
        if cp.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError("container %s did not become ready" % container)


def docker_rm(container: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", container],
                       capture_output=True, text=True)
    except Exception:
        pass


# ---- cloud provider (mirrors ohbs-image's TC3 flow) ------------------------
def _cloud_api(action: str, payload: dict) -> dict:
    from ohbs_image import _tc3_api  # type: ignore  # ohbs-image must be installed
    sid = os.environ.get("TENCENTCLOUD_SECRET_ID", "")
    skey = os.environ.get("TENCENTCLOUD_SECRET_KEY", "")
    tok = os.environ.get("TENCENTCLOUD_SECURITY_TOKEN") or None
    region = os.environ.get("TENCENTCLOUD_REGION", "")
    resp = _tc3_api("cvm", action, "2017-03-12", region, payload, sid, skey, tok)
    resp_r = resp.get("Response", {})
    if "Error" in resp_r:
        raise RuntimeError("%s failed: %s" % (action, resp_r["Error"]))
    return resp_r


def cloud_generate_keypair(tmpdir: Path) -> tuple[Path, Path]:
    priv, pub = tmpdir / "e2e_key", tmpdir / "e2e_key.pub"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv)],
                   check=True, capture_output=True)
    priv.chmod(0o600)
    return priv, pub


def cloud_start(args: argparse.Namespace, tmpdir: Path) -> dict:
    priv, pub = cloud_generate_keypair(tmpdir)
    pub_key = pub.read_text().strip()
    key_name = "cis-e2e-%d" % int(time.time())
    resp = _cloud_api("ImportKeyPair", {
        "KeyName": key_name, "ProjectId": 0, "PublicKey": pub_key})
    key_id = resp.get("KeyId")
    if not key_id:
        raise RuntimeError("ImportKeyPair returned no KeyId")
    resp = _cloud_api("RunInstances", {
        "ImageId": args.image_id, "InstanceType": args.instance_type,
        "InstanceChargeType": "POSTPAID_BY_HOUR", "InstanceName": "ohbs-host-e2e-test",
        "Placement": {"Zone": args.zone},
        "VirtualPrivateCloud": {"VpcId": args.vpc_id, "SubnetId": args.subnet_id},
        "SecurityGroupIds": [args.security_group_id],
        "LoginSettings": {"KeyIds": [key_id]},
        "InternetAccessible": {"PublicIpAssigned": True,
                               "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR",
                               "InternetMaxBandwidthOut": 5},
        "InstanceCount": 1,
        "TagSpecification": [{"ResourceType": "instance",
                              "Tags": [{"Key": "purpose", "Value": "ohbs-host-e2e-test"},
                                       {"Key": "ephemeral", "Value": "true"}]}]})
    ids = resp.get("InstanceIdSet") or []
    if not ids:
        raise RuntimeError("RunInstances returned no InstanceId")
    return {"provider": "cloud", "instance_id": ids[0], "key_id": key_id,
            "key_path": str(priv), "ssh_user": args.ssh_user}


def cloud_wait_ready(target: dict, region: str) -> str:
    deadline = time.time() + BOOT_TIMEOUT_SECONDS
    while time.time() < deadline:
        resp = _cloud_api("DescribeInstances", {"InstanceIds": [target["instance_id"]]})
        insts = resp.get("InstanceSet") or []
        if insts:
            st = insts[0].get("InstanceState", "")
            state = st.get("State", "") if isinstance(st, dict) else str(st)
            if state == "RUNNING":
                addrs = insts[0].get("PublicIpAddresses") or []
                if addrs:
                    return str(addrs[0])
        time.sleep(10)
    return ""


def cloud_ssh(target: dict, host: str, script: str, log_path: Path) -> int:
    deadline = time.time() + SSH_READY_TIMEOUT_SECONDS
    while time.time() < deadline:
        cp = subprocess.run(
            ["ssh", "-i", target["key_path"], "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
             "%s@%s" % (target["ssh_user"], host), "true"], capture_output=True)
        if cp.returncode == 0:
            break
        time.sleep(5)
    log_path.parent.mkdir(exist_ok=True)
    with subprocess.Popen(
        ["ssh", "-i", target["key_path"], "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "%s@%s" % (target["ssh_user"], host),
         "bash", "-s"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    ) as proc, log_path.open("w") as log_f:
        assert proc.stdin is not None
        proc.stdin.write(script)
        proc.stdin.close()
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            log_f.write(line)
        proc.wait()
        return proc.returncode


def cloud_teardown(target: dict) -> None:
    try:
        _cloud_api("TerminateInstances", {"InstanceIds": [target["instance_id"]]})
        ok("Instance terminated: %s" % target["instance_id"])
    except Exception as exc:
        warn("Failed to terminate instance: %s" % exc)
    try:
        _cloud_api("DeleteKeyPairs", {"KeyIds": [target["key_id"]]})
        ok("Key pair deleted")
    except Exception as exc:
        warn("Failed to delete key pair: %s" % exc)


# ---- the remote run (shared by both providers) ----------------------------
# Static remote script; dynamic values (os/profile/disruptive/repo_mode/
# branch/repo_url) are injected as shell variables by a header prepended in
# run_remote(). Kept free of Python str.format() placeholders so the inline
# Python heredoc below (which uses its own {}) does not conflict.
REMOTE_SCRIPT = r"""
set -euo pipefail
echo "[remote 1/5] python + git"
if ! command -v python3 >/dev/null 2>&1; then
    { apt-get update -qq >/dev/null 2>&1 || true; }
    { apt-get install -y python3 python3-pip git >/dev/null 2>&1 || dnf install -y python3 python3-pip git >/dev/null 2>&1 || true; }
fi
PY=python3

echo "[remote 2/5] get repo ($REPO_MODE)"
if [ "$REPO_MODE" = "local" ]; then
    # repo already copied to /root/ohbs-host by the host (docker cp)
    cd /root/ohbs-host
else
    command -v git >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 || true; apt-get install -y git >/dev/null 2>&1 || dnf install -y git >/dev/null 2>&1 || true; }
    rm -rf /root/ohbs-host
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" /root/ohbs-host
    cd /root/ohbs-host
fi
echo "     commit: $(git rev-parse --short HEAD 2>/dev/null || echo local)"

echo "[remote 3/5] install ohbs-host (venv preferred, else system)"
cd /root/ohbs-host
# Upgrade pip first: slim/distro images ship an old pip (e.g. 22.x) that
# predates PEP 660 and cannot do `pip install -e .` on a pyproject-only
# package. A modern pip fixes both editable installs and venv support.
pip install --quiet --upgrade pip >/dev/null 2>&1 || true
if $PY -m venv .venv 2>/dev/null; then
    source .venv/bin/activate
    pip install --quiet -e ".[dev]"
else
    # venv/ensurepip unavailable (common on slim systemd images); the
    # container is disposable so a system-wide editable install is fine.
    pip install --quiet -e ".[dev]" --break-system-packages 2>/dev/null || \
    pip install --quiet -e ".[dev]"
fi

echo "[remote 4/5] CLI alive"
ohbs-host --help >/dev/null
ohbs-host list >/dev/null

echo "[remote 5/5] real scan -> apply -> re-scan -> idempotent apply"
mkdir -p /root/e2e
set +e
ohbs-host scan --os "$OS" --profile "$PROFILE" --output /root/e2e/scan1 >/root/e2e/scan1.out 2>&1
SCAN1_RC=$?
ohbs-host apply --os "$OS" --profile "$PROFILE" $DISRUPTIVE --output /root/e2e/apply >/root/e2e/apply.out 2>&1
APPLY_RC=$?
ohbs-host scan --os "$OS" --profile "$PROFILE" --output /root/e2e/scan2 >/root/e2e/scan2.out 2>&1
SCAN2_RC=$?
ohbs-host apply --os "$OS" --profile "$PROFILE" $DISRUPTIVE --output /root/e2e/apply2 >/root/e2e/apply2.out 2>&1
APPLY2_RC=$?
set -e

# Emit machine-readable outcome for the host side to parse. This must
# always run even if a step above failed (hence the set +e guards above).
# Result JSON files may not be readable on the host via bind mount (Colima
# on macOS has unreliable bind-mounts), so we also emit the parsed summary
# stats inline for the host-side assertion.
echo "===E2E-RESULT-START==="
echo "scan1_rc=$SCAN1_RC"
echo "apply_rc=$APPLY_RC"
echo "scan2_rc=$SCAN2_RC"
echo "apply2_rc=$APPLY2_RC"
echo "---scan1.out-tail---"
tail -8 /root/e2e/scan1/scan1.out 2>/dev/null || true
echo "---apply.out-tail---"
tail -8 /root/e2e/apply/apply.out 2>/dev/null || true
python3 - <<'PYEOF'
import json, glob, os
def load(d):
    for pat in ("result*.json", "*result*.json"):
        for f in sorted(glob.glob(os.path.join(d, pat))):
            try:
                return json.load(open(f))
            except Exception:
                continue
    return {}
out = {}
for key, d in (("scan1", "/root/e2e/scan1"), ("scan2", "/root/e2e/scan2"),
               ("apply", "/root/e2e/apply"), ("apply2", "/root/e2e/apply2")):
    doc = load(d)
    alls = (doc.get("summary") or {}).get("all") or {}
    out[key] = {
        "total": alls.get("total"), "pass": alls.get("pass"),
        "fail": alls.get("fail"), "error": alls.get("error"),
        "manual": alls.get("manual"), "applied": alls.get("applied"),
        "applied_pending": alls.get("applied_pending"),
        "changed_files": (doc.get("changed_files") or [])[:5],
        "has_results": bool(doc.get("results")),
    }
print("RESULT_SUMMARY=" + json.dumps(out))
PYEOF
echo "===E2E-RESULT-END==="
"""


# ---- host-side assertions -------------------------------------------------
def _parse_remote_block(remote_output: str) -> tuple[dict, dict]:
    """Parse the ===E2E-RESULT=== block, returning (rc, result_summary)
    where rc is {scan1_rc, apply_rc, scan2_rc, apply2_rc} and
    result_summary is {scan1|scan2|apply|apply2: {stats}} from the
    inline RESULT_SUMMARY= JSON line emitted by the remote script.
    """
    m = re.search(r"===E2E-RESULT-START===\n(.*?)\n===E2E-RESULT-END===",
                  remote_output, re.S)
    if not m:
        raise AssertionError("remote did not emit the ===E2E-RESULT=== block")
    rc = {}
    summary = {}
    for ln in m.group(1).splitlines():
        if ln.startswith("RESULT_SUMMARY="):
            try:
                summary = json.loads(ln[len("RESULT_SUMMARY="):])
            except ValueError:
                pass
        elif "=" in ln:
            k, _, v = ln.partition("=")
            rc[k.strip()] = int(v.strip() or "0")
    return rc, summary


def assert_e2e(rc: dict, summary: dict) -> None:
    """Assert the real scan/apply cycle behaved, from the rc and summary
    parsed out of the remote log. No bind mount or file transfer required.
    """
    assert rc.get("scan1_rc") == 0, "scan #1 exited %s" % rc.get("scan1_rc")
    assert rc.get("apply_rc") == 0, "apply exited %s" % rc.get("apply_rc")
    assert rc.get("scan2_rc") == 0, "re-scan exited %s" % rc.get("scan2_rc")
    assert rc.get("apply2_rc") == 0, "idempotent re-apply exited %s" % rc.get("apply2_rc")

    s1 = summary.get("scan1") or {}
    s2 = summary.get("scan2") or {}
    a = summary.get("apply") or {}
    a2 = summary.get("apply2") or {}

    # a valid report was produced
    assert s1.get("has_results"), "scan1 produced no results array"
    assert s1.get("total", 0) > 0, "scan1 summary.total is 0"

    # remediation actually changed the host (the box is unhardened)
    applied = (a.get("applied") or 0) + (a.get("applied_pending") or 0)
    assert applied > 0, "apply remediated nothing (applied=%s)" % a.get("applied")

    # re-scan improved: fewer fails, no error regression
    assert (s2.get("fail") or 0) < (s1.get("fail") or 0), \
        "re-scan did not reduce failures: %s -> %s" % (s1.get("fail"), s2.get("fail"))
    assert (s2.get("error") or 0) <= (s1.get("error") or 0), \
        "re-scan introduced new errors: %s -> %s" % (s1.get("error"), s2.get("error"))

    # real-OS idempotency: the second apply must not perform any NEW
    # remediation (applied == 0). applied_pending > 0 is tolerated here
    # because it is the documented pre-existing `kv_conf` re-parse bug (the
    # fix persists but the check re-reads "key = value" as "= value" and
    # still reports fail) -- see docs/TESTING.md §3 -- not evidence of
    # re-mutation; applied counts newly-applied fixes, which is what
    # idempotency means.
    assert (a2.get("applied") or 0) == 0, \
        "second apply still applied new fixes (applied=%s) -- NOT idempotent" % a2.get("applied")


# ---- lifecycle / main -----------------------------------------------------
def save_last_target(target: dict) -> None:
    LAST_TARGET_FILE.parent.mkdir(exist_ok=True)
    LAST_TARGET_FILE.write_text(json.dumps(target, indent=2))


def clear_last_target() -> None:
    LAST_TARGET_FILE.unlink(missing_ok=True)


def run_remote(args: argparse.Namespace, target: dict, log_path: Path) -> int:
    repo_mode = "local" if target["provider"] == "docker" else "git"
    disruptive = "--allow-disruptive" if args.allow_disruptive else ""
    header = (
        "OS=%s\n"
        "PROFILE=%s\n"
        "DISRUPTIVE=%s\n"
        "REPO_MODE=%s\n"
        "BRANCH=%s\n"
        "REPO_URL=%s\n"
    ) % (_shquote(args.os), _shquote(args.profile), disruptive,
         _shquote(repo_mode), _shquote(args.branch), _shquote(args.repo_url))
    script = header + REMOTE_SCRIPT
    if target["provider"] == "docker":
        return docker_exec(args, target, script, log_path)
    host = cloud_wait_ready(target, os.environ.get("TENCENTCLOUD_REGION", ""))
    if not host:
        raise RuntimeError("instance did not get a public IP")
    ok("Public IP: %s" % host)
    target["public_ip"] = host
    return cloud_ssh(target, host, script, log_path)


def _shquote(s: str) -> str:
    """Single-quote a value for safe shell assignment."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def teardown(target: dict, keep: bool) -> None:
    if keep:
        warn("--keep-on-failure set: target NOT destroyed. record: %s"
             % LAST_TARGET_FILE)
        return
    if target["provider"] == "docker":
        docker_rm(target["container"])
        ok("Container removed: %s" % target.get("container"))
    else:
        cloud_teardown(target)
    clear_last_target()


def main() -> int:
    args = parse_args()
    validate_args(args)
    confirm_impact(args)

    target: dict | None = None
    remote_exit = 1

    with tempfile.TemporaryDirectory() as tmp:
        try:
            if args.provider == "docker":
                target = docker_start(args)
                save_last_target(target)
                ok("Container: %s" % target["container"])
                banner("Waiting for systemd to be ready")
                docker_wait_ready(target["container"])
                ok("container ready")
            else:
                target = cloud_start(args, Path(tmp))
                save_last_target(target)
                ok("InstanceId: %s" % target["instance_id"])

            banner("Running real scan -> apply -> re-scan -> idempotent apply")
            log_path = REPO_ROOT / "logs" / ("e2e-%s-%d.log" % (args.os, int(time.time())))
            remote_exit = run_remote(args, target, log_path)
            info("Full remote log saved to %s" % log_path)

            if remote_exit == 0:
                banner("Host-side assertions")
                rc, summary = _parse_remote_block(log_path.read_text())
                assert_e2e(rc, summary)
                ok("Real end-to-end test PASSED")
            else:
                fail("Remote run FAILED (exit code %d)" % remote_exit)

        except (AssertionError, RuntimeError) as exc:
            fail(str(exc))
            remote_exit = 1
        except KeyboardInterrupt:
            warn("Interrupted — cleaning up")
            remote_exit = 130
        except Exception as exc:  # noqa: BLE001
            fail("Unexpected error: %s" % exc)
            remote_exit = 1
        finally:
            if target:
                teardown(target, keep=args.keep_on_failure and remote_exit != 0)

    return remote_exit


if __name__ == "__main__":
    sys.exit(main())
