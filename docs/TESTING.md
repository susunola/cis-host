# ohbs-host — QA Test Plan

**Status:** Living document · applies to the merged `main` (post PR0–PR9 modularization + M0–M5 rule-verification matrix + `ohbs → ohbs-host` rename)
**Last updated:** 2026-08-15
**Baseline:** 509 passing tests across two suites (see [Test inventory](#2-test-inventory-what-exists-today)).
**L4 e2e plan:** §10 (modeled on `ohbs-image/scripts/real_e2e_test.py`) — implemented in `scripts/real_e2e_test.py`; Docker provider validated against ubuntu2204; CI step added (non-blocking).

This plan describes the full testing strategy for ohbs-host: what is tested today, the philosophy behind it, and where coverage is intentionally extended next. It is a *plan*, not an exhaustive how-to — each section names the target, the approach, the mocking boundary, and the current gap. Sections 1–9 cover the unit → rule-matrix stack; [§10](#10-end-to-end-l4-test-plan--real-host-scanapplyrescan) is the real-host end-to-end (L4) plan, modeled on the sister-project's `ohbs-image/scripts/real_e2e_test.py`.

---

## 1. Goals & philosophy

The product is a CIS Benchmark engine + CLI that (a) **assesses** and (b) **remediates** system configuration across 14 OSes (10 Linux + 4 Windows), producing HTML reports, drift/verification views, and a periodic watch mode. Three properties matter most and drive the whole strategy:

1. **Correctness of the rule engine.** A wrong `pass`/`fail` or a broken fix is the worst failure mode — it silently misleads a security assessment. Rule logic therefore gets the highest-value testing.
2. **No regressions across 14 OSes.** The engines are near-duplicated per OS (Linux engines are byte-identical; Windows engines are byte-identical), so testing one OS's engine logic validates all copies — but each OS has a *different* `rules.json` catalog, so catalog-driven behavior must be exercised per OS.
3. **Zero-trust of subprocess/OS state.** Checks and fixes shell out (`sh`/`systemctl`/`secedit`/`auditpol`) and touch the filesystem. Tests must never run real remediation against the host. The strategy is to **exercise the real check/fix logic while faking only the OS/subprocess boundary**.

**Layers** (from fastest/cheapest to slowest/heaviest):

```
L0  Static / packaging guards        (py_compile, py-modules, JSON schema, syntax)
L1  Pure-logic unit tests            (no subprocess: config, diff, presets, display)
L2  Boundary-mocked unit tests       (mock subprocess.run / cmdlets: engine, CLI, exporters)
L3  Rule-verification matrix         (real engine, faked OS boundary)  ★ release gate
L4  Behavioral integration           (real engine process, container/VM)  [gap today]
```

---

## 2. Test inventory (what exists today)

| Area | File(s) | Layer | Mocking boundary | Count |
|------|---------|-------|------------------|-------|
| CLI snapshot (byte-for-byte help) | `tests/test_cli_baseline.py` | L0/L1 | none (real subprocess `ohbs_cli.py`) | 13 |
| CLI smoke | `tests/test_cli.py` | L1 | none | 7 |
| `engine.py` subprocess wiring | `tests/test_cli_engine.py` | L2 | `mock.patch("engine.subprocess.run")` | 18 |
| `display.py` color/summary/table | `tests/test_cli_display.py` | L1 | `patch.object(sys.stdout,'isatty')`, `capsys` | 8 |
| `ohbs_host_config` load/merge | `tests/test_config.py` | L1 | `tmp_path` TOML | 7 |
| `ohbs_host_diff` logic + CLI | `tests/test_diff.py` | L1 | `tmp_path`, injected scanners | 31 |
| Linux engine boundary helpers | `tests/test_engine.py` | L1 | real engine via `importlib`, `tmp_path` | 22 |
| Exporters (xccdf/junit) | `tests/test_exporters.py` | L2 | real subprocess + XML parse | 2 |
| `fleet.py` aggregation/render | `tests/test_fleet.py` | L1 | `tmp_path` | 10 |
| `info.py` lookup/render | `tests/test_info.py` | L1 | `patch("info.get_rule_detail")`, `tmp_path` | 7 |
| Packaging (`py-modules` graph) | `tests/test_packaging.py` | L0 | static BFS | 2 |
| Presets + catalog resolution | `tests/test_presets_catalog.py` | L1 | `tmp_path` | 12 |
| `report.py` render ctx | `tests/test_report.py` | L2 | minimal Jinja2 template, `patch("report.collect_host")` | 5 |
| Windows engine static checks | `tests/test_windows.py` | L0 | static file reads | 4 |
| **Fixture matrix (M0–M5)** | `tests/fixtures/test_m*.py` | **L3** | **real engine, faked OS boundary** | **~348** |

**Fixture matrix detail** (`tests/fixtures/`):
- **Linux** — 10 OS × 10 families (`multi_os.build_matrix()` → 99 combos): loads the real per-OS `ohbs_engine.py` via `importlib` and monkeypatches its boundary (`sh/read/exists/atomic_write/conf_values/have`, `open`, `globmod`, `os.path`, `os`) to an in-memory `FakeSystem`. Drives `run_rule()` through:
  - `run_closed_loop`: scan→fail, apply→applied→pass, fresh re-scan→pass
  - `run_already_compliant`: scan→pass, apply→"already"
  - `run_idempotency_check` (M5): apply twice; second must be "already" **and** leave `files/services/kmods/sysctls/packages` byte-identical
- **Windows** — 4 OS × {reg-dword, adv-audit, firewall, user-right}: shells out to `pwsh`, dot-sourcing `win_fake_system.py` (fake `Get-ItemProperty`/`secedit`/`auditpol`/`Get-NetFirewallProfile`) before the real `ohbs_engine.ps1`. Same three runner checks.

**CI** (`.github/workflows/ci.yml`, single `lint-and-test` job): py_compile engines → `pytest -v --ignore=tests/fixtures` → **release-gate step** running `pytest tests/fixtures/` + a JUnit-skip detector (fails if any fixture test skipped) → JSON catalog validation → Ansible `--syntax-check` → `pip install -e .` + CLI smoke.

---

## 3. Known engine/catalog bugs surfaced by the matrix (documented, not yet fixed)

These were *found* by the M0–M5 work. They are real product bugs that a release gate should eventually block. Fixing them is tracked separately (out of scope for this plan), but the test plan must keep them covered so a fix can be verified:

- **Linux `kv_conf` separator re-parse bug** — `_kv_current()` tries `r"\s+"` before `r"\s*=\s*"` when a rule omits `sep`; a value persisted as `key = value` is re-read as `= value`, so the rule reports `fail` immediately after a successful fix. Affects real rules like `5.3.3.2.2` (minlen), `5.3.3.2.3` (minclass), `5.3.3.3.1` (remember). The fixture matrix *avoids* these rules (pins to safe rules with explicit `sep`) — see `multi_os._kv_conf_rule_is_safe`.
- **Windows `reg-dword` / `user-right` catalog/engine mismatch** — every real `reg-dword`/`user-right` rule in all 4 Windows `rules.json` files stores `{"key"/"privilege": "<rule id>"}` but `Invoke-Check`/`Invoke-Fix` read `path/name/value` (reg-dword) or `privilege/expected_sid` (user-right). Real scans return `"error"`. The Windows matrix therefore uses *synthetic* rules (see `families_win.synthetic_*`).
- **Windows `user-right` fix pipeline bug** — PowerShell single-element pipeline unwrap makes `$members += $expectedSid` string-concatenate when a privilege has exactly one existing member, yielding a malformed, never-matching SID list. The generator seeds 2+ members to avoid it.

**Plan intent:** add a dedicated regression test that reproduces each bug *against the real engine* in a way that fails today, so that when the fix lands, the test flips green and proves the fix. See [§7 Next: close known-bug loops](#7-prioritized-gaps--next-steps).

---

## 4. Layer-by-layer plan

### L0 — Static & packaging guards (today: partial → good)
- `py_compile` every engine + CLI module in CI. ✅
- `tests/test_packaging.py` walks the local-import graph from `ohbs_cli.py` and asserts it equals `pyproject.toml py-modules`. ✅ (already transitive since PR8)
- `scripts/validate_json.py` validates all catalogs in CI. ✅ (runs as a step)
- **Gap:** `validate_json.py` has no pytest test itself; `scripts/export_sarif.py`, `export_prometheus.py`, `append_history.py` are untested. **Action:** add L1 tests for the remaining exporters mirroring `test_exporters.py`.

### L1 — Pure-logic unit tests (today: strong)
Config merge, drift/diff logic, presets/catalog lookups, display/summary formatting, report ctx construction, packaging graph. These are fast, deterministic, and mock nothing. **No action needed beyond upkeep** as new pure functions are added (rule: any new non-I/O helper gets an L1 test alongside it).

### L2 — Boundary-mocked unit tests (today: good, one gap)
`engine.py` subprocess wiring is well-mocked (`mock.patch("engine.subprocess.run")`). Exporters covered for xccdf/junit.
- **Gap:** `fleet.run_remote_scan` (SSH) is untested; `watch`'s `--alert-cmd` subprocess path is untested.
- **Action:** add `mock.patch("fleet.subprocess.run")` tests for SSH argv assembly, JSON parse, timeout, and error paths. Add an alert-callback test in `cmd_watch`.

### L3 — Rule-verification matrix (today: the crown jewel) ★
This is the highest-value layer and the CI release gate. **Intent:** every OS × family × {closed-loop, already-compliant, idempotent} combination must pass before merge. Currently 348 tests across 99 Linux combos + 4 Windows OS × 4 families.
- **Action (coverage growth):** the matrix currently covers 10 Linux families + 4 Windows families. Extend to the full family set per OS by adding `FixtureGenerator`s — priority by rule count. On Linux the largest untested automated families are `file_perm` (17), `world_writable`, `logfile_perm`, `pam_*`, `sshd_*`, `audit_perm`; on Windows the remaining automated families are `password-policy`, `lockout-policy`, `audit-policy`, `service-state`, `uac`, `lanman-auth`, `smb-signing`, `rdp-nla`, `eventlog-size`, `ps-execution`, `ps-logging`, `wu-config`, `reg-string`, `reg-exists`. See §7.
- **Windows note:** `pwsh` is required; the gate already fails loudly if it's missing (JUnit-skip detector).

### L4 — Behavioral integration (today: none → the biggest structural gap)
The matrix proves rule *logic* with a faked OS. It does **not** prove that a real engine invocation on a real OS behaves identically (real `subprocess`, real filesystem, real privilege). The README Roadmap already lists "Molecule-based integration tests for every Linux role" and "CI pipeline for per-suite regression testing" as outstanding.
- **Full plan:** see [§10 End-to-end (L4) test plan](#10-end-to-end-l4-test-plan--real-host-scanapplyrescan) — a `scripts/real_e2e_test.py` modeled on the sister-project's `ohbs-image` e2e, provisioning a real OS (Docker first, cloud-VM optional), running a real scan → apply → re-scan → idempotent-apply cycle, and always tearing down.
- **Windows L4:** would need real Windows Server VMs (expensive). Recommend deferring; keep Windows at L3 (`pwsh` + faked cmdlets) unless/until a VM fleet is available.

---

## 5. Test data & fixtures strategy

- **Unit tests** use `tmp_path` and minimal inline JSON — self-contained, no repo fixtures needed.
- **Snapshot tests** (`tests/snapshots/cli/*.txt`) freeze CLI help text byte-for-byte. **Discipline required:** never regenerate a snapshot to "fix" a failing test unless the change is a *documented, intentional* CLI change (see the `ohbs → ohbs-host` rename already reflected there). A snapshot diff is the canary for accidental CLI drift.
- **Fixture matrix** uses the *real* per-OS `rules.json` and *real* engine code, with only the OS boundary faked. This means the matrix automatically tracks catalog/engine changes. New family generators must mirror exactly what the check function inspects (see `families/core.py` for the pattern).
- **Synthetic rules** (Windows reg-dword/user-right) exist only because the real catalog params don't match the engine — a temporary stopgap until the catalog/engine mismatch is fixed (§3). Once fixed, the synthetic rules should be deleted and the real rules used.

---

## 6. Release gate & CI

**Current gate (must pass to merge):**
1. All 508 tests (L0–L3) pass — `pytest -v --ignore=tests/fixtures` + `pytest tests/fixtures/`.
2. **Zero skipped** fixture tests (JUnit-skip detector) — prevents silent Windows-coverage loss.
3. JSON catalogs validate.
4. Ansible playbooks pass `--syntax-check`.
5. `pip install -e .` + `ohbs-host --help`/`list`/`scan --help`/`apply --help` smoke.

**Proposed additions (phased):**
- **Coverage gate (phase 1):** add `pytest --cov` reporting for the main suite; set a floor (e.g. ≥80% line on non-fixture code) as a *warning* first, then a hard gate once the number stabilizes.
- **Per-suite regression job (phase 2):** container-based L4 scan-diff job on `main` (see §4 L4).
- **Known-bug gates (phase 2):** regression tests that currently fail on the §3 bugs; once each bug is fixed, it becomes part of the gate (no known-bug can ship).
- **Release checklist (phase 3):** an explicit release document that runs L0–L4 and the per-suite regression before tagging, so a release is never cut against an unverified rule set.

---

## 7. Prioritized gaps & next steps

Ordered by value/effort.

| # | Gap | Layer | Value | Action |
|---|-----|-------|-------|--------|
| 1 | Untested exporters (`sarif`, `prometheus`, `append_history`) + `validate_json.py` | L0/L1 | Med | Add L1 tests mirroring `test_exporters.py` |
| 2 | `fleet.run_remote_scan` (SSH) & `watch --alert-cmd` subprocess paths | L2 | Med | Mock `subprocess.run`, assert argv/JSON/error handling |
| 3 | Extend Linux matrix to remaining automated families (`file_perm`, `world_writable`, `pam_*`, `sshd_*`, `audit_perm`, ...) | L3 | **High** | Add `FixtureGenerator`s per family, mirroring check logic; grows closed-loop coverage |
| 4 | Extend Windows matrix to remaining automated families (`password-policy`, `service-state`, `uac`, `reg-string`, ...) | L3 | **High** | Add fake cmdlet coverage + generators |
| 5 | Real `report.html.j2` template rendering with real data | L2 | Med | Snapshot the rendered HTML for one representative OS; assert key sections |
| 6 | `--simulate` path (`apply_status == "simulated"`) | L3 | Med | Drive `run_rule` with `ctx.simulate=True` in the matrix |
| 7 | Known-bug regression tests (§3) — `kv_conf` separator, Windows reg-dword/user-right catalog, user-right pipeline | L3 | **High** | Dedicated tests that fail today, flip green on fix |
| 8 | Molecule/container L4 for a representative Linux role | L4 | High (post-PoC) | Wire existing `ohbs-ubuntu2204` molecule config into a non-gating CI job |
| 9 | Per-suite regression (weak vs. hardened container scan-diff) | L4 | High (post-PoC) | On-tag/on-main soak job |
| 10 | Coverage floor + release checklist doc | L0/L3 | Med | Add `pytest --cov`, write `docs/RELEASE.md` |

---

## 8. Definition of done for a rule's coverage

A rule/family is considered **fully verified** when, against the *real* engine with the OS boundary faked, the following all pass (this is the M0–M5 contract, reused for every new family):

1. **Closed loop:** non-compliant seed → `scan` = `fail` → `apply` = `applied` + re-check `pass` → fresh re-`scan` = `pass`.
2. **Already-compliant:** compliant seed → `scan` = `pass` → `apply` = `already`.
3. **Idempotent (M5):** apply twice from a non-compliant seed; second apply = `already` **and** system state byte-identical.
4. **Assertion of the actual value** (not just status): the detail string carries the expected key/value so a `pass` can't be a false positive from an empty check.

---

## 9. Risk register

| Risk | Mitigation |
|------|-----------|
| Faked-boundary diverges from real OS behavior (matrix passes, real scan breaks) | L4 container soak; keep fakes *minimal* and mirror exactly the real tool output format |
| Windows engine drift undetected | L0 `test_windows.py` static guards + L3 matrix (pwsh) + gate's zero-skip detector |
| Snapshot tests hide accidental CLI drift | Strict snapshot discipline; only documented intentional changes |
| Engine/catalog bugs (known §3) silently ship | Known-bug regression tests; gate on zero known-bugs at release |
| New family added with no generator (matrix gap) | `build_matrix()` asserts coverage; add a guard that every automated family appears in some OS's matrix |
| Slow L4 flakes breaking PRs | Run L4 on `main`/tags, not PRs; PRs gated on fast L0–L3 only |

---

## 10. End-to-end (L4) test plan — real host scan/apply/re-scan

### 10.1 Why (the gap this fills)

The L3 fixture matrix (M0–M5) exercises the *real* engine logic against a **faked** OS boundary — it proves a rule's check/fix logic is correct, but it cannot answer the questions the sister-project's `ohbs-image/scripts/real_e2e_test.py` answers for that project:

- Does `pip install -e .` actually work on a **clean** OS, and does `ohbs-host scan` run a real subprocess against a real filesystem/kernel?
- Does a real `scan` → `apply` → re-`scan` cycle on a real host produce a valid report, correct exit codes, and genuine remediation (not just faked writes)?
- Did the per-OS `rules.json` / `ohbs_engine.py` drift from real-world behavior in a way only a live OS exposes (e.g. a family that shells out to a tool absent from the faked dispatch)?

These only show up against something real. This plan follows the exact shape of `ohbs-image/scripts/real_e2e_test.py` (provision → confirm cost → run remote suite → **always teardown**), adapted from a cloud-VM image-builder to a **host scanner** whose target is a real OS.

### 10.2 Provisioning target — Docker first, cloud-VM optional

ohbs-host scans real OS hosts. Two fidelity tiers:

| Tier | Target | Fidelity | Cost | Runs where |
|------|--------|----------|------|-----------|
| **Docker (default)** | `docker run` a real distro image (with systemd where possible; Molecule infra already exists for all 10 Linux roles) | Good — covers package manager, services, sysctl, files, most rules | ~free | PRs (fast, disposable), `main`, tags |
| **Cloud VM (optional)** | real CVM/EC2 instance per OS (root, real kernel, host-only rules like GRUB/bootloader, hardware paths) | **Full** — host-only rules that containers can't exercise | billed | `--provider cloud`, on tags/releases only |

The script must support both via `--provider docker|cloud`, defaulting to `docker` (cheap enough to gate PRs) and reserving `cloud` for the release gate.

### 10.3 Script: `scripts/real_e2e_test.py`

Mirrors the reference script's structure and lifecycle discipline, applied to ohbs-host.

**CLI / config** (mirrors reference + provider switch):
```
python3 scripts/real_e2e_test.py \
    --os ubuntu2204 \          # which OS image/role to test
    --provider docker|cloud \  # docker (default) or cloud VM
    --profile L1 \
    --allow-disruptive \       # so apply actually remediates
    --branch main \
    --keep-on-failure \        # don't teardown if the remote run fails
    -y                          # skip cost confirmation
```
Cloud mode adds `--image-id/--region/--zone/--instance-type/--vpc-id/--subnet-id/--security-group-id/--ssh-user` + `TENCENTCLOUD_SECRET_ID/KEY` env, exactly as the reference.

**Step flow** (each step is a `banner("...")` + `ok/info/warn/fail` like the reference):

1. **Confirm cost** — `confirm_cost()`: unless `-y`, print the billed/unbilled warning and prompt. (Cloud = billed instance; Docker = ephemeral, still confirm for the security-group/port exposure.)
2. **Provision target**
   - *Docker:* `docker run -d --privileged --name cis-e2e-<os>-<ts> <image> init` (systemd image) → wait for healthy.
   - *Cloud:* reuse reference's `generate_keypair` → `import_keypair` → `run_instance` → `wait_for_public_ip` → `wait_for_ssh`.
3. **Save last-target record** — `logs/e2e_last_instance.json` (Docker: container id; Cloud: instance/key/region) so a manual cleanup path always exists.
4. **Install ohbs-host + run real cycle over exec/SSH** — `REMOTE_SCRIPT` heredoc piped to `ssh host bash -s` (cloud) or `docker exec -i container bash -s` (docker):
   ```
   set -euo pipefail
   [1/6] install python + git
   [2/6] pip install -e .[dev]          # proves clean editable install
   [3/6] ohbs-host --help; ohbs-host list # CLI surface alive
   [4/6] ohbs-host scan --os X --profile L1 --output /root/e2e   # real subprocess scan
   [5/6] ohbs-host apply --os X --profile L1 --allow-disruptive --output /root/e2e   # real remediation
   [6/6] ohbs-host scan --os X --profile L1 --output /root/e2e/after  # post-apply re-scan
   ```
5. **Assert results** (on the *host* side, after the remote run) — this is where e2e differs from a plain "did it run":
   - scan #1 exit 0, valid result JSON (`summary.all.pass+fail+manual+error == total`), HTML report produced.
   - apply produced `changed_files`/`applied > 0` (because the box is intentionally-unhardened).
   - re-scan after apply: `fail` count strictly **decreased** vs scan #1 (remediation worked on a real host), no `error` regressions.
   - **Idempotency at the real-OS level (the L4 payoff):** run `apply` a **second** time and assert it reports `already`/`applied == 0` — mirrors the M5 gate but against real `set_kv_in_file`/`systemctl`/package changes, proving no fix re-mutates on every run.
6. **Teardown (always)** — `finally:` block: `docker rm -f <container>` / `terminate_instance` + `delete_keypair`, `clear_last_instance`. `--keep-on-failure` keeps it only when the remote run failed. Teardown errors are `warn` (manual cleanup hint), never a crash.

**Exit code** = the remote script's exit code (0 pass / non-zero fail), like the reference.

### 10.4 Assertion summary table

| Assertion | What it proves |
|-----------|----------------|
| Clean `pip install -e .[dev]` succeeds | packaging actually works on a real OS |
| `ohbs-host --help` / `list` live | CLI entrypoint + dispatch survive a real install |
| scan #1 exits 0, result JSON well-formed | real engine subprocess + catalog load work |
| HTML report generated | real `report.html.j2` renders with real data |
| `applied > 0` on apply | real remediation actually changes the host |
| re-scan `fail` count decreases, no new `error` | remediation worked without breaking other rules |
| apply #2 → `already` / `applied == 0` | **real-OS idempotency** (the L4 version of the M5 gate) |
| container/instance + key torn down | no orphaned billed resources or open SSH ports |

### 10.5 CI wiring (phased)

- **Phase 1 (PR):** run the **Docker** e2e for a representative OS (ubuntu2204) in the existing `lint-and-test` job, as a non-blocking `continue-on-error` check first, then make it blocking once stable. This is fast and free.
- **Phase 2 (`main` / on-tag):** full Docker e2e across a matrix of representative OSes (one per distro family: rhel, ubuntu, sles, tencentos) — the "per-suite regression" roadmap item.
- **Phase 3 (release/tag):** optional **cloud-VM** e2e (billed) for host-only fidelity; gated by an explicit `--provider cloud` invocation, never on a PR.

### 10.6 Relationship to the rest of the plan

```
L3 fixture matrix (faked OS)   → proves rule LOGIC is correct, fast, deterministic
L4 e2e (real OS)               → proves the full real path works (install→scan→apply→re-scan→idempotent)
```
Neither replaces the other. L3 is the release gate that runs on every PR; L4 is the periodic/integration soak that catches environment-level drift L3 structurally cannot. Together they satisfy the README Roadmap's "Molecule-based integration tests" + "CI pipeline for per-suite regression testing".
