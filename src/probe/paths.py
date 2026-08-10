"""Where things live.

flightops is installed editable from a sibling checkout, so its repository root is derivable
from the imported package rather than hard-coded. `PROBE_FLIGHTOPS_DB` overrides it, which is
what CI and a non-standard checkout layout use.
"""

from __future__ import annotations

import os
from pathlib import Path

import flightops

PROBE_ROOT = Path(__file__).resolve().parents[2]
RUNS = PROBE_ROOT / "data" / "runs"
REPORTS = PROBE_ROOT / "data" / "reports"
REFERENCE_DB = PROBE_ROOT / "data" / "reference.duckdb"


def flightops_root() -> Path:
    """The flightops checkout backing this install."""
    return Path(flightops.__file__).resolve().parents[2]


def flightops_database() -> Path:
    """The committed flightops sample, built on demand if it is not there yet."""
    override = os.environ.get("PROBE_FLIGHTOPS_DB")
    if override:
        return Path(override)
    database = flightops_root() / "data" / "sample" / "sample.duckdb"
    if not database.exists():
        from flightops.ingest.sample import build_sample_database

        build_sample_database()
    return database
