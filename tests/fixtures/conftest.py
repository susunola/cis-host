"""Adds tests/fixtures/ to sys.path so the fixture modules here can use
plain top-level imports (from base import ..., from fake_system import
...) instead of package-relative imports, matching the flat-module
convention used by the rest of the repo (see cis_cli.py's own
top-level-module layout).
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
