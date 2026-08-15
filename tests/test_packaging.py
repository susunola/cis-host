#!/usr/bin/env python3
"""Guard against pyproject.toml py-modules drifting from the actual local
modules reachable (transitively) from cis_cli.py's entrypoint. Regression
test for a bug where cis_host_diff (and later presets/catalog/engine/display)
were importable from a source checkout but missing from the packaged
distribution, causing `pip install .` + `cis-host` to fail with
ModuleNotFoundError in a clean environment.

Since PR8, cis_cli.py itself only imports dispatch.py, which in turn
imports the bulk of the local modules (args, defaults, commands_scan,
commands_watch, fleet, info, ...). We therefore walk the local-import graph
transitively starting from cis_cli.py, instead of only checking cis_cli.py's
direct imports, so that modules newly required by dispatch.py (or anything
it imports) are still caught.
"""

import os
import re

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


def _direct_local_imports(module_path):
    """Parse a module's top-level `import X` / `from X import ...`
    statements and return local (non-stdlib, non-third-party) module names,
    identified by having a matching <name>.py file in the repo root.
    """
    with open(module_path, "r", encoding="utf-8") as fh:
        source = fh.read()

    names = set()
    for match in re.finditer(r"^(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)", source, re.MULTILINE):
        name = match.group(1)
        if os.path.exists(os.path.join(REPO_ROOT, f"{name}.py")):
            names.add(name)
    return names


def _transitive_local_imports(entry_path):
    """BFS over the local-import graph starting at entry_path, returning
    every local module name reachable from it (directly or indirectly).
    """
    seen = set()
    queue = [entry_path]
    while queue:
        path = queue.pop()
        for name in _direct_local_imports(path):
            if name in seen:
                continue
            seen.add(name)
            queue.append(os.path.join(REPO_ROOT, f"{name}.py"))
    return seen


def test_py_modules_covers_all_local_imports():
    py_modules = _load_py_modules()
    cis_cli_path = os.path.join(REPO_ROOT, "cis_cli.py")
    local_imports = _transitive_local_imports(cis_cli_path)

    missing = local_imports - py_modules
    assert not missing, (
        f"cis_cli.py transitively imports local module(s) {sorted(missing)} "
        f"that are not listed in [tool.setuptools] py-modules in "
        f"pyproject.toml. This would cause ModuleNotFoundError after "
        f"`pip install` in a clean environment. py-modules={sorted(py_modules)}"
    )


def test_py_modules_files_exist():
    py_modules = _load_py_modules()
    for name in py_modules:
        path = os.path.join(REPO_ROOT, f"{name}.py")
        assert os.path.exists(path), f"py-modules lists '{name}' but {path} does not exist"
