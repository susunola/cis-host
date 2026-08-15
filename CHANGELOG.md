# Changelog

## [Unreleased] — CI rule-verification matrix (M0–M5)

Added `tests/fixtures/`: an in-memory, per-OS scan → apply → re-scan
closed-loop and idempotency regression matrix, covering all 14
supported OS engines (10 Linux + 4 Windows) without requiring real VMs
or containers. This is test-only infrastructure — no production code
changed as part of M0–M5, and it introduces no new runtime
   dependencies for `cis-host` itself (the Windows fixtures need `pwsh`
   on the *test* machine only, and are skipped automatically if it's
   absent).

### What's covered

- **Linux (10 OSes: tencentos3/4, rhel8/9/10, sles15/16, ubuntu2004/
  2204/2404):** `FakeSystem` (`tests/fixtures/fake_system.py`)
  monkeypatches each OS's real `cis_engine.py` boundary functions
  (`sh`/`read`/`exists`/`atomic_write`/`conf_values`/`have`, plus
  `open()`/`glob.glob()`/`os.path.isfile`/`isdir` for the handful of
  families that bypass those helpers) so the real check/fix business
  logic runs against in-memory state instead of the real filesystem/
  subprocess. Covers the top-10 Linux families by rule count: `kmod`,
  `sysctl`, `svc_enabled`, `svc_disabled`, `pkg_present`, `mount_opt`,
  `kv_conf`, `banner`, `partition`, `audit_immutable`.
- **Windows (4 OSes: win2016/2019/2022/2025):** since the Windows
  engine is PowerShell (`cis_engine.ps1`), a parallel harness
  (`tests/fixtures/win_harness.py`) shells out to `pwsh`, dot-sourcing
  a block of fake cmdlet definitions (`win_fake_system.py`:
  `Get-ItemProperty`/`Set-ItemProperty`/`Test-Path`/`New-Item` for the
  registry, `secedit` for security-policy/user-rights, `auditpol` for
  advanced audit policy, `Get-NetFirewallProfile`/
  `Set-NetFirewallProfile` for the firewall) *before* dot-sourcing the
  real engine, so PowerShell's function-over-cmdlet resolution routes
  every relevant call to the fake. Covers `reg-dword`, `adv-audit`,
  `firewall`, `user-right`.
- **Idempotency gate (M5):** every family with a registered `fix()` is
  applied *twice* in a row from a non-compliant seed; the second apply
  must report `apply_status == "already"` **and** leave the fake
  system's state byte-for-byte unchanged from the first apply. This
  catches fixes that "succeed" once but keep mutating state on every
  subsequent run (e.g. blindly re-appending a config line instead of
  checking whether it's already present) — a class of bug the M0–M4
  closed-loop checks (which only ever apply once per rule) could not
  detect.
- Wired into `.github/workflows/ci.yml` as its own release-gate step,
  separate from the general `pytest` run, with an explicit check that
  zero fixture tests were skipped (so a missing `pwsh` on a future CI
  image silently dropping Windows coverage would fail the build loudly
  instead of passing quietly).

### Pre-existing engine/catalog bugs found while building this (none
fixed here — all documented in the relevant fixture module/test
docstring and left for separate follow-up bugfix work, since fixing
them is out of scope for a fixture-framework milestone):

- **`kv_conf` (Linux, all 10 OSes):** `_kv_current()` tries separator
  regex `\s+` before `\s*=\s*` for any `kv_conf` rule that omits an
  explicit `"sep"` param (defaults to `"="`). A value persisted as
  `"key = value"` (exactly what `f_kv_conf()`'s default write format
  produces) gets mis-parsed back as `"= value"` on the very next
  check, so the rule reports "fail" immediately after a successful
  fix. Affects real rules like `5.3.3.2.2` (minlen), `5.3.3.2.3`
  (minclass), `5.3.3.3.1` (remember). See `tests/fixtures/
  test_m1_ubuntu2204.py`.
- **`reg-dword` / `user-right` (Windows, all 4 OSes):** the real
  catalog stores `{"key"/"privilege": "<rule id>"}` for every rule in
  both families, but `Invoke-Check`/`Invoke-Fix` read `params.path`/
  `params.name`/`params.value` (for `reg-dword`) or `params.privilege`/
  `params.expected_sid` (for `user-right`) — none of which the real
  catalog provides. Every real scan of these families returns
  `"error"`, not a meaningful pass/fail; affects `reg-dword`'s full 232
  rules on win2022 (and similar counts on the other 3 Windows OSes),
  the single largest non-manual family across all 4 Windows
  benchmarks. See `tests/fixtures/families_win.py`.
- **`user-right` fix (Windows, all 4 OSes):** `Invoke-Fix`'s
  `user-right` branch builds `$members` via a piped `-split`/
  `ForEach-Object`/`Where-Object` chain; when that pipeline yields
  exactly one element, PowerShell auto-unwraps it from an array to a
  scalar string, so the following `$members += $expectedSid.Trim()`
  string-concatenates instead of array-appending — producing a
  malformed, comma-less member list that can never match the expected
  SID on re-check. Only manifests when the privilege currently has
  exactly one existing member. See `tests/fixtures/
  test_m4_windows_multi_os.py`.
- **Catalog gap (Linux, rhel9 only):** rhel9's `rules.json` has zero
  `sysctl`-family rules — a real gap in that OS's catalog, not a
  fixture-framework issue.

## [Unreleased] — cis_cli.py modularization (PR1–PR8)

`cis_cli.py` was refactored from a single 1730-line monolithic file into
14 top-level modules (`presets.py`, `catalog.py`, `engine.py`,
`display.py`, `report.py`, `fleet.py`, `info.py`, `commands_scan.py`,
`commands_watch.py`, `args.py`, `defaults.py`, `dispatch.py`, plus the
pre-existing `cis_host_config.py`/`cis_host_diff.py`). `cis_cli.py`
itself is now a 51-line entrypoint (`def main(): dispatch.run()`).

This was a mechanical extraction — CLI flags, help text, exit codes, and
output formatting are locked in by byte-for-byte snapshot tests
(`tests/test_cli_baseline.py`, added in PR0 before the refactor started)
and pass unchanged across all 8 PRs. The items below are the only
user-visible or API-visible differences from pre-refactor `cis_cli.py`.

### Changed (user-visible)

- **Color output now respects `NO_COLOR` and TTY detection.**
  Previously, `cis_cli.py` always emitted ANSI color escape codes,
  even when output was piped/redirected (e.g. into a log file or CI
  runner). `display.click_style()` now suppresses color codes when the
  `NO_COLOR` environment variable is set, or when stdout is not a TTY.
  If you were parsing colored CLI output, or relied on ANSI codes always
  being present, this changes: piped output and CI logs are now plain
  text by default.
- **`info --format html` now escapes `section`/`family`/`risk` fields
  in the rule-detail HTML report.** The original hand-written HTML only
  called `html.escape()` on a subset of fields; the Jinja2 template
  (`templates/rule_info.html.j2`, `autoescape=True`) escapes all
  interpolated values consistently. This only affects rendering if a
  rule's catalog metadata contains HTML-special characters (`<`, `>`,
  `&`); for the shipped rule catalogs, output is visually identical.

### Fixed

- **`pip install -e .` no longer crashes with `ModuleNotFoundError`.**
  A clean editable install previously failed on `cis-host list` (or any
  command) with `ModuleNotFoundError: No module named 'cis_host_diff'`,
  because `pyproject.toml`'s `[tool.setuptools] py-modules` only listed
  `cis_cli` and `cis_host_config`. All local modules are now registered,
  and `tests/test_packaging.py` regression-tests this by walking the
  local-import graph transitively from `cis_cli.py`.

### Known limitation (documented, not fixed in this refactor)

- Building a real wheel/sdist (`python -m build`) does **not** package
  the 14 `cis-<os>-ansible/` directories or the top-level `templates/`
  directory, since they're consumed via filesystem paths relative to
  `cis_cli.py` at runtime. Installing a published wheel would install
  the CLI but `scan`/`apply`/`fleet`/`info --format html` would fail
  with "Template not found" / missing catalog errors. **Do not publish
  this package to PyPI** until this is fixed. See the comment above
  `[tool.setuptools]` in `pyproject.toml`.

### Internal / non-breaking

- Several module-private helper functions were renamed to drop their
  leading underscore as they moved to their own top-level module (they
  were never part of a public API before, so this is additive, not
  breaking, for anyone importing these modules directly):
  `_apply_defaults` → `defaults.apply_defaults`,
  `_load_fleet_hosts` → `fleet.load_fleet_hosts`,
  `_run_remote_scan` → `fleet.run_remote_scan`,
  `_aggregate_fleet_results` → `fleet.aggregate_fleet_results`,
  `_render_fleet_report` → `fleet.render_fleet_report`,
  `_render_info_html` → `info.render_info_html`,
  `_load_result_json` → `commands_watch.load_result_json`.
- Inline f-string HTML in fleet scan and rule-info reports was replaced
  with Jinja2 templates (`templates/fleet_report.html.j2`,
  `templates/rule_info.html.j2`), matching the pattern already used by
  `report.py`.
- A pre-existing `--version` display bug (`vv1.0.0`, double "v" prefix)
  was identified during the refactor but is **not** new — it predates
  PR1 and was intentionally left unfixed as out of scope for a
  mechanical refactor.

### PR breakdown

| PR | Commit | Change |
|----|---------|--------|
| PR0 | `14bca9b` | Add baseline CLI snapshot tests before refactor |
| PR1 | `e6fc583` | Extract `presets.py`, `catalog.py` |
| PR2 | `5c7b007` | Extract `engine.py`, `display.py` (NO_COLOR/TTY change) |
| PR4 | `4b2c53b` | Fix missing `py-modules` (ModuleNotFoundError) |
| PR3 | `7a77fec` | Extract `report.py` |
| PR5 | `6c8fbe7` | Extract `fleet.py`, move inline HTML to Jinja2 template |
| PR6 | `b49a30a` | Extract `info.py`, move inline HTML to Jinja2 template |
| PR7 | `bf6210e` | Extract `commands_scan.py`, `commands_watch.py` |
| PR8 | `238706e` | Split `main()` into `args.py` + `dispatch.py`, add `defaults.py` |
