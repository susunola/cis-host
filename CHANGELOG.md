# Changelog

## [Unreleased] — cis_cli.py modularization (PR1–PR8)

`cis_cli.py` was refactored from a single 1730-line monolithic file into
14 top-level modules (`presets.py`, `catalog.py`, `engine.py`,
`display.py`, `report.py`, `fleet.py`, `info.py`, `commands_scan.py`,
`commands_watch.py`, `args.py`, `defaults.py`, `dispatch.py`, plus the
pre-existing `ciscvm_config.py`/`ciscvm_diff.py`). `cis_cli.py` itself is
now a 51-line entrypoint (`def main(): dispatch.run()`).

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
  command) with `ModuleNotFoundError: No module named 'ciscvm_diff'`,
  because `pyproject.toml`'s `[tool.setuptools] py-modules` only listed
  `cis_cli` and `ciscvm_config`. All local modules are now registered,
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
