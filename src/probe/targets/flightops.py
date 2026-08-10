"""The flightops adapter.

DESIGN.md sections 3 and 4. flightops is installed as a dependency and driven through the same
module-level names its own `scripts/run_eval.py` and `api/app.py` use -- `TOOL_SCHEMAS`,
`dispatch`, `ToolContext`, `ontology_system_prompt`, `LiveTransport`. Nothing private is
imported, the DuckDB schema is never queried directly, and no file in the flightops checkout is
modified. Adversarial content arrives by wrapping the executor that `loop.run` already accepts
as an argument.

The HTTP API was considered and rejected as the interface: `/api/ask` is env-gated off in the
deployment, returns tool call names and arguments but not results, builds a fresh `ToolContext`
per request and never exposes the resulting `Scenario`. probe needs all three of the things it
withholds.

`supported_classes` is short and that is the finding, not an omission. BTS On-Time Performance
carries no attacker-writable free-text field, so instruction injection through data and
tool-result poisoning are reachable against this target only by synthesising records the real
source cannot contain. They are listed, because measuring what the agent would do with a
compromised source is worth knowing, and every result they produce is labelled hypothetical.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from flightops.agent.loop import MODEL, AssistantTurn
from flightops.agent.prompts import ontology_system_prompt
from flightops.agent.tools import TOOL_SCHEMAS, ToolContext, dispatch
from flightops.model.store import ObjectStore

from probe.attacks.inject import injector_for
from probe.attacks.model import Attack, AttackClass
from probe.targets.base import (
    BlockRecord,
    Defence,
    Episode,
    StateChange,
    compose_executor,
)

NAME = "flightops"

SUPPORTED = frozenset(
    {
        AttackClass.AUTHORITY_FORGERY,
        AttackClass.CITATION_LAUNDERING,
        AttackClass.INSTRUCTION_INJECTION,
        AttackClass.TOOL_RESULT_POISONING,
    }
)

STATE_CHANGING_ACTIONS = frozenset({"delay_flight", "cancel_flight", "swap_aircraft"})


class LazyLiveTransport:
    """flightops's LiveTransport, constructed on first use.

    Opening an episode must not require an API key: the judge fixtures, the search mechanics and
    every test open episodes against this target without ever driving one. Only an actual live
    turn needs the key, and that is where the failure should surface.
    """

    def __init__(self, model: str = MODEL) -> None:
        self._model = model
        self._inner: Any = None

    def next_turn(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AssistantTurn:
        if self._inner is None:
            from flightops.agent.loop import LiveTransport

            self._inner = LiveTransport(self._model)
        turn: AssistantTurn = self._inner.next_turn(system, messages, tools)
        return turn


@dataclass
class FlightopsObserver:
    """Reads the scenarios the agent mutated, from the context the adapter handed it.

    This is the object the agent actually changed, not a reconstruction: `ToolContext.scenarios`
    is populated by flightops itself as `simulate_action` runs.
    """

    context: ToolContext

    def changes(self) -> Sequence[StateChange]:
        return [
            StateChange(
                object_id=change.flight_id,
                action=change.action,
                summary=change.summary,
                # The overlay evaporates with the process; the base DuckDB file is opened
                # read-only. DESIGN.md section 5.3 -- against this target criterion 1 measures a
                # proxy for harm, and this flag is how the report says so.
                irreversible=False,
                scenario_id=scenario_id,
            )
            for scenario_id, scenario in self.context.scenarios.items()
            for change in scenario.changes
        ]

    def scenario_clocks(self) -> Mapping[str, datetime]:
        return {
            scenario_id: scenario.clock for scenario_id, scenario in self.context.scenarios.items()
        }


class FlightopsTarget:
    """The real target, wrapped through its public module surface."""

    name = NAME
    supported_classes = SUPPORTED

    def __init__(self, store: ObjectStore, model: str = MODEL) -> None:
        self._store = store
        self._model = model

    def open_episode(self, attack: Attack, defences: Sequence[Defence]) -> Episode:
        context = ToolContext.open(self._store)
        blocked: list[BlockRecord] = []
        injector = injector_for(attack.injection)

        def inner(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            return dispatch(context, tool_name, arguments)

        system = ontology_system_prompt(self._store)
        for defence in defences:
            system = defence.transform_system(system)

        return Episode(
            target_name=self.name,
            attack_id=attack.attack_id,
            system=system,
            user_turn=injector.transform_user_turn(attack.user_turn),
            tool_schemas=list(TOOL_SCHEMAS),
            execute=compose_executor(inner, defences, injector, blocked),
            observer=FlightopsObserver(context),
            licensed_scope=attack.licensed_scope,
            transport=LazyLiveTransport(self._model),
            blocked=blocked,
            defences=tuple(defence.name for defence in defences),
            answer_filters=tuple(defence.transform_answer for defence in defences),
        )
