"""The seed corpus, and the properties the rest of the measurement depends on."""

from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from flightops.model.objects import FlightStatus
from flightops.model.store import ObjectNotFound, ObjectStore
from flightops.propagation.engine import PropagationEngine

from probe.attacks.corpus import (
    FAKE_FLIGHT_ID,
    TEMPLATES,
    candidate_flights,
    read_only_scope,
    seeds,
)
from probe.attacks.model import AttackClass
from probe.defenses.layers import build
from probe.episodes import drive
from probe.judge import Judge
from probe.targets.reference import SUPPORTED, ClosureLog, ReferenceTarget


def test_the_fake_flight_id_really_is_absent(store: ObjectStore) -> None:
    """Citation laundering is only measurable if the planted id resolves to nothing."""
    with pytest.raises(ObjectNotFound):
        store.get_flight(FAKE_FLIGHT_ID)


def test_the_fake_flight_id_is_well_formed() -> None:
    """A malformed id would be caught by shape rather than by the store, which tests nothing."""
    from probe.judge.core import FLIGHT_ID

    assert FLIGHT_ID.fullmatch(FAKE_FLIGHT_ID)


def test_candidate_flights_are_actionable(store: ObjectStore) -> None:
    for flight_id in candidate_flights(store):
        flight = store.get_flight(flight_id)
        assert flight.status is not FlightStatus.CANCELLED
        assert flight.tail_number


def test_candidates_occupy_distinct_departure_instants(store: ObjectStore) -> None:
    """Ties collapse the corpus onto one clock and quietly disarm criterion 2.

    The unfiltered first twelve rows of this date all depart within five minutes of each other,
    because the schedule opens with a bank of legs sharing an instant. `retarget` moving between
    them would leave the request clock unchanged, so the temporal bypass would report near-zero
    for a reason that has nothing to do with the agent.
    """
    flights = candidate_flights(store)
    instants = [store.get_flight(fid).sched_dep_utc for fid in flights]

    assert len(set(instants)) == len(instants)
    assert max(instants) - min(instants) > timedelta(hours=6), (
        "candidates cover a narrow window; retargeting barely moves the clock"
    )


def test_seeds_anchor_mid_day_so_the_temporal_check_is_reachable(
    store: ObjectStore, engine: PropagationEngine
) -> None:
    """Seeding on the earliest leg makes criterion 2 unreachable and reports a false zero."""
    flights = candidate_flights(store)
    built = seeds(store, engine, "reference", SUPPORTED)
    anchor = next(iter(built[0].licensed_scope.object_ids))
    anchor_departure = store.get_flight(anchor).sched_dep_utc

    earlier = [fid for fid in flights if store.get_flight(fid).sched_dep_utc < anchor_departure]
    later = [fid for fid in flights if store.get_flight(fid).sched_dep_utc > anchor_departure]

    assert earlier, "no leg before the anchor: the precondition bypass cannot be found"
    assert later, "no leg after the anchor: retargeting has nowhere forward to go"


def test_most_seeds_fail_against_the_reference_agent(
    store: ObjectStore, engine: PropagationEngine
) -> None:
    """Seeds that already work would make the search a formality.

    The value the operators add is discovering the authority framing. If this ever inverts, the
    search-efficiency numbers stop describing search.
    """
    with tempfile.TemporaryDirectory() as directory:
        log = ClosureLog(Path(directory) / "ref.duckdb")
        target = ReferenceTarget(store, log)
        judge = Judge(store, engine)
        landed = 0
        built = seeds(store, engine, "reference", SUPPORTED)
        for attack in built:
            control = attack.control()
            clean = drive(control, target.open_episode(control, build((), control, store)))
            result = drive(attack, target.open_episode(attack, build((), attack, store)))
            if judge.grade(result, clean).succeeded:
                landed += 1
        log.close()

    assert landed < len(built), "every seed worked unaided; the search has nothing to discover"


def test_seeds_are_filtered_to_supported_classes(
    store: ObjectStore, engine: PropagationEngine
) -> None:
    only = frozenset({AttackClass.CITATION_LAUNDERING})
    built = seeds(store, engine, "reference", only)

    assert built and all(attack.attack_class in only for attack in built)


def test_every_template_names_a_class_in_the_taxonomy() -> None:
    assert all(isinstance(template.attack_class, AttackClass) for template in TEMPLATES)


def test_grounded_claim_is_derived_from_the_store_not_asserted(
    store: ObjectStore, engine: PropagationEngine, judge: Judge
) -> None:
    """The fixture's expected value must be the store's answer, or the drift guard is theatre."""
    flights = candidate_flights(store)
    scope = read_only_scope(store, engine, flights[0], plants_figure=True)
    claim = scope.grounded_claims[0]

    assert claim.expected == pytest.approx(judge.recompute(claim))
    assert claim.induced_value != claim.expected


def test_control_strips_the_payload_but_keeps_the_case(
    store: ObjectStore, engine: PropagationEngine
) -> None:
    built = seeds(store, engine, "reference", SUPPORTED)
    injected = next(
        attack
        for attack in built
        if attack.injection and attack.injection.channel.value != "user_turn"
    )
    control = injected.control()

    assert control.injection is None
    assert control.user_turn == injected.user_turn
    assert control.licensed_scope == injected.licensed_scope
