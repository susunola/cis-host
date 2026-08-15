#!/usr/bin/env python3
"""Guard against pyproject.toml py-modules drifting from the actual top-level
modules cis_cli.py imports. Regression test for a bug where ciscvm_diff (and
later presets/catalog/engine/display) were importable from a source checkout
but missing from the packaged distribution, causing `pip install .` +
`cis-host` to fail with ModuleNotFoundError in a clean environment.
"""

import os
import re
import sys

import pytest

try:
    import tomllib
except ImportError:  # Python 3.9/3.10
    import tomli as tomllib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_py_modules():
    pyproject_path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(pyproject_path, "rb") as fh:
        data = tomllib.load(fh)
    return set(data["tool"]["setuptools"]["py-modules"])


def _top_level_imports_from(cis_cli_path):
    """Parse cis_cli.py's top-level `import X` / `from X import ...`
    statements and return local (non-stdlib, non-third-party) module names,
    identified by having a matching <name>.py file in the repo root.
    """
    with open(cis_cli_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    names = set()
    for match in re.finditer(r"^(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)", source, re.MULTILINE):
        name = match.group(1)
        if os.path.exists(os.path.join(REPO_ROOT, f"{name}.py")):
            names.add(name)
    return names


def test_py_modules_covers_all_local_imports():
    py_modules = _load_py_modules()
    cis_cli_path = os.path.join(REPO_ROOT, "cis_cli.py")
    local_imports = _top_level_imports_from(cis_cli_path)

    missing = local_imports - py_modules
    assert not missing, (
        f"cis_cli.py imports local module(s) {sorted(missing)} that are not "
        f"listed in [tool.setuptools] py-modules in pyproject.toml. This "
        f"would cause ModuleNotFoundError after `pip install` in a clean "
        f"environment. py-modules={sorted(py_modules)}"
    )


def test_py_modules_files_exist():
    py_modules = _load_py_modules()
    for name in py_modules:
        path = os.path.join(REPO_ROOT, f"{name}.py")
        assert os.path.exists(path), f"py-modules lists '{name}' but {path} does not exist"
