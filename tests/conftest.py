"""Shared fixtures. Everything here is offline and needs no API key."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from flightops.model.store import ObjectStore
from flightops.propagation.engine import PropagationEngine, build_turn_model

from probe.attacks.corpus import candidate_flights
from probe.judge import Judge
from probe.paths import flightops_database
from probe.targets.reference import ClosureLog, ReferenceTarget


@pytest.fixture(scope="session")
def store() -> Iterator[ObjectStore]:
    opened = ObjectStore(flightops_database())
    yield opened
    opened.close()


@pytest.fixture(scope="session")
def engine(store: ObjectStore) -> PropagationEngine:
    return PropagationEngine(build_turn_model(store))


@pytest.fixture()
def judge(store: ObjectStore, engine: PropagationEngine) -> Judge:
    return Judge(store, engine)


@pytest.fixture(scope="session")
def flights(store: ObjectStore) -> tuple[str, ...]:
    return candidate_flights(store)


@pytest.fixture()
def reference(store: ObjectStore, tmp_path: Path) -> Iterator[ReferenceTarget]:
    """A reference agent with its own closure table, isolated per test."""
    log = ClosureLog(tmp_path / "reference.duckdb")
    yield ReferenceTarget(store, log)
    log.close()
