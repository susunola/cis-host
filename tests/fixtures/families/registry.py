"""Aggregates all per-family FixtureGenerator registries across
milestones into a single GENERATORS dict. New milestones (M1, M2, ...)
add their own families/<name>.py module with its own GENERATORS dict
and get merged in here, rather than growing one another's files --
keeps each milestone's generators independently reviewable.
"""

from families.core import GENERATORS as _M0_GENERATORS
from families.extra import GENERATORS as _M1_GENERATORS

GENERATORS = {}
GENERATORS.update(_M0_GENERATORS)
GENERATORS.update(_M1_GENERATORS)
