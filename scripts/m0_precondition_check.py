"""Reproduces the precondition finding in DESIGN.md section 1.4.

Not probe implementation -- M0 ships no implementation. This is the evidence for a design
claim, kept runnable for the same reason flightops records `verified_by` on every eval
question: a finding a reader cannot re-derive is an assertion.

Run against a flightops checkout:

    cd /home/user/flight-ops-deployment
    .venv/bin/python /home/user/probe/scripts/m0_precondition_check.py

Shows that flightops's `is_pending` precondition cannot reject the first action in a fresh
scenario, because `ToolContext.scenario_for` pins that scenario's clock to one minute before
whichever flight the caller names first -- and `scenario_id` is an argument the model controls.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "src"))

from flightops.agent import tools  # noqa: E402
from flightops.model.objects import FlightStatus  # noqa: E402
from flightops.model.store import ObjectStore  # noqa: E402

DATABASE = Path("data/sample/sample.duckdb")


def main() -> int:
    if not DATABASE.exists():
        raise SystemExit(f"{DATABASE} not found; run `make data` in the flightops checkout first")

    store = ObjectStore(DATABASE)
    context = tools.ToolContext.open(store)

    actionable = [
        flight
        for flight in store.find_flights(carrier="WN", flight_date="2026-01-03", limit=40)
        if flight.status is not FlightStatus.CANCELLED and flight.tail_number
    ]
    early, late = actionable[0], actionable[-1]
    print(f"early flight : {early.flight_id}  sched_dep_utc {early.sched_dep_utc:%H:%M} UTC")
    print(f"late  flight : {late.flight_id}  sched_dep_utc {late.sched_dep_utc:%H:%M} UTC")

    first = tools.dispatch(
        context,
        "simulate_action",
        {"action": "cancel_flight", "flight_id": late.flight_id, "reason": "m0", "scenario_id": "A"},
    )
    print("\n[A] cancel the late flight, fresh scenario -> accepted")
    print(f"    clock pinned to {first['scenario_clock_utc']}")

    print("\n[A] cancel the early flight in that same scenario:")
    try:
        tools.dispatch(
            context,
            "simulate_action",
            {
                "action": "cancel_flight",
                "flight_id": early.flight_id,
                "reason": "m0",
                "scenario_id": "A",
            },
        )
        print("    UNEXPECTED: accepted -- the finding in DESIGN.md 1.4 no longer reproduces")
        return 1
    except tools.ToolFailure as rejected:
        print(f"    REJECTED: {rejected}")

    second = tools.dispatch(
        context,
        "simulate_action",
        {
            "action": "cancel_flight",
            "flight_id": early.flight_id,
            "reason": "m0",
            "scenario_id": "B",
        },
    )
    print("\n[B] same early flight, caller simply picks a new scenario_id:")
    print(f"    ACCEPTED: {second['summary'][:78]}")
    print(f"    clock pinned to {second['scenario_clock_utc']} -- moved to suit the target")

    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
