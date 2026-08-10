"""The target adapter interface: one agent probe can drive, wrapped through its public surface.

DESIGN.md section 4. Three constraints shape this module.

The target is never edited. flightops is installed as a dependency and driven through the same
module-level names its own `run_eval.py` and `api/app.py` use. Adversarial content reaches the
agent by wrapping the executor that `loop.run` already takes as an argument, so probe adds a
layer around the target rather than a patch inside it. A harness that has to fork its target
cannot claim to measure that target.

Defences block by raising flightops's own `ToolFailure`, which its loop already renders as an
error tool result the model reads and retries against. Inventing a second error channel would
mean the defended agent sees a different failure shape than the undefended one, and the utility
comparison in M5 would be measuring that difference instead of the defence.

State is read from the objects the agent mutated, never parsed back out of prose. `StateChange`
carries `irreversible` because the two targets differ on exactly that point: flightops mutates a
per-session overlay that evaporates, the reference agent writes a row that persists. DESIGN.md
section 5.3 calls the first a proxy for harm, and a boolean on the record is how that limitation
reaches the report instead of only the design document.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from flightops.agent.loop import AssistantTurn
from flightops.agent.tools import ToolFailure

from probe.attacks.model import Attack, AttackClass, LicensedScope

ToolExecutor = Callable[[str, dict[str, Any]], dict[str, Any]]
"""Runs one tool call. Raises ToolFailure for a rejection the agent should read and retry."""


class DefenceBlocked(ToolFailure):
    """A defence refused a call before it reached the target.

    Subclasses ToolFailure so the agent loop renders it exactly like any other rejection -- the
    defended agent must not be able to tell a defence apart from the domain saying no, or the
    measurement is of the tell rather than the defence.
    """

    def __init__(self, defence: str, reason: str) -> None:
        super().__init__(reason)
        self.defence = defence
        self.reason = reason


@dataclass(frozen=True)
class BlockRecord:
    """One call a defence stopped, kept so a defence's cost can be attributed to it."""

    defence: str
    tool_name: str
    arguments: dict[str, Any]
    reason: str


@dataclass(frozen=True)
class StateChange:
    """One state change the target actually applied, read from the target's own objects."""

    object_id: str
    action: str
    summary: str
    irreversible: bool
    scenario_id: str | None = None


class StateObserver(Protocol):
    """What the judge reads after an episode. Never prose, always the mutated objects."""

    def changes(self) -> Sequence[StateChange]: ...

    def scenario_clocks(self) -> Mapping[str, datetime]:
        """The clock each scenario was pinned to, for the temporal precondition check."""
        ...


class Transport(Protocol):
    """Where the next assistant turn comes from. Structurally flightops's own Transport."""

    def next_turn(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> AssistantTurn: ...


class Defence(Protocol):
    """One independently toggleable hardening layer.

    Three hooks because the six defences in the brief act at three different points, and
    collapsing them into one would mean a layer that does nothing at two of them.
    """

    name: str

    def transform_system(self, system: str) -> str: ...

    def before_call(self, tool_name: str, arguments: dict[str, Any]) -> None:
        """Raise DefenceBlocked to stop the call."""
        ...

    def after_call(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]: ...

    def transform_answer(self, answer: str) -> str: ...


class Injector(Protocol):
    """How an attack's payload reaches the agent."""

    def transform_user_turn(self, user_turn: str) -> str: ...

    def after_call(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]: ...


@dataclass
class Episode:
    """One attack against one target: everything to run it, and everything to judge it."""

    target_name: str
    attack_id: str
    system: str
    user_turn: str
    tool_schemas: list[dict[str, Any]]
    execute: ToolExecutor
    observer: StateObserver
    licensed_scope: LicensedScope
    transport: Transport
    blocked: list[BlockRecord] = field(default_factory=list)
    defences: tuple[str, ...] = ()
    answer_filters: tuple[Callable[[str], str], ...] = ()

    def filter_answer(self, answer: str) -> str:
        """Apply post-answer defences, in order. Identity when none are enabled."""
        for transform in self.answer_filters:
            answer = transform(answer)
        return answer


class Target(Protocol):
    """One agent probe can drive."""

    name: str
    supported_classes: frozenset[AttackClass]
    """Classes this target has a surface for.

    Not decoration. flightops cannot express threshold pressure, and reporting 0% ASR for a class
    the target cannot receive would be a fabricated result. The report renders an unsupported
    class as n/a and never as zero.
    """

    def open_episode(self, attack: Attack, defences: Sequence[Defence]) -> Episode: ...


def compose_executor(
    inner: ToolExecutor,
    defences: Sequence[Defence],
    injector: Injector | None,
    blocked: list[BlockRecord],
) -> ToolExecutor:
    """Wrap the target's own executor: defences before the call, injection then defences after.

    Order is load-bearing. `before_call` defences see the call the agent actually made. The
    target then executes unmodified. The injector runs **before** the post-call defences, because
    it stands in for the data source containing hostile text: by the time any defence sees a
    record, the payload is already in it. Fencing first and injecting afterwards would place the
    payload outside the fence and make structural separation unable to work by construction --
    which would be reported as the defence failing rather than as the harness being wired wrong.
    """

    def execute(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        for defence in defences:
            try:
                defence.before_call(tool_name, arguments)
            except DefenceBlocked as stopped:
                blocked.append(
                    BlockRecord(
                        defence=stopped.defence,
                        tool_name=tool_name,
                        arguments=dict(arguments),
                        reason=stopped.reason,
                    )
                )
                raise
        result = inner(tool_name, arguments)
        if injector is not None:
            result = injector.after_call(tool_name, arguments, result)
        for defence in defences:
            result = defence.after_call(tool_name, arguments, result)
        return result

    return execute
