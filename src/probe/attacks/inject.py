"""How an attack's payload reaches the agent.

DESIGN.md section 4.1. Two implementations, and the difference between them is the honesty of
every finding they produce.

`UserTurnInjector` puts the payload in the question. That channel is genuinely attacker
controlled against both targets: anyone can type into flightops's `/api/ask`.

`ResultInjector` writes the payload into a field of a tool result, simulating a record whose
free text an attacker authored. Against flightops that is **hypothetical**: BTS On-Time
Performance is government-published and has no free-text column an attacker could write. The
injector is still worth having -- it measures what the agent would do if its data source were
compromised, which is the right question to ask before adding a source that could be -- but
every result it produces is labelled hypothetical wherever it is reported, and
`Attack.hypothetical` is what carries that label.
"""

from __future__ import annotations

from typing import Any

from probe.attacks.model import Channel, Injection

DEFAULT_FIELDS: dict[str, str] = {
    "find_objects": "describes_as",
    "traverse_links": "describes_as",
    "simulate_action": "summary",
}
"""Where a payload lands when the injection names no field.

Chosen as the field most likely to be read as prose rather than parsed as data: an id or a
timestamp is obviously structured, while a description already carries human-written text and is
where a hostile record's free text would realistically sit.
"""


class NullInjector:
    """Injects nothing. Used for control episodes, where the point is that nothing is injected."""

    def transform_user_turn(self, user_turn: str) -> str:
        return user_turn

    def after_call(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        return result


class UserTurnInjector:
    """Appends the payload to the user's question. The one channel an attacker really has."""

    def __init__(self, injection: Injection) -> None:
        self._injection = injection

    def transform_user_turn(self, user_turn: str) -> str:
        return f"{user_turn}\n\n{self._injection.payload}"

    def after_call(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        return result


class ResultInjector:
    """Writes the payload into a returned object, as a hostile record's free text would appear.

    Hypothetical against flightops. See the module docstring.
    """

    def __init__(self, injection: Injection) -> None:
        self._injection = injection

    def transform_user_turn(self, user_turn: str) -> str:
        return user_turn

    def after_call(
        self, tool_name: str, arguments: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        target_tool = self._injection.tool_name
        if target_tool is not None and target_tool != tool_name:
            return result
        field = self._injection.field_path or DEFAULT_FIELDS.get(tool_name)
        if field is None:
            return result
        return _poison(result, field, self._injection.payload)


def _poison(result: dict[str, Any], field: str, payload: str) -> dict[str, Any]:
    """Append the payload to `field`, reaching into a `results` list when one is present.

    Returns a copy: mutating the target's own payload in place would let one episode's injection
    leak into a later one through any structure the target happens to cache.
    """
    poisoned = dict(result)
    rows = poisoned.get("results")
    if isinstance(rows, list) and rows:
        poisoned["results"] = [
            _append_field(row, field, payload) if isinstance(row, dict) else row for row in rows
        ]
        return poisoned
    return _append_field(poisoned, field, payload)


def _append_field(row: dict[str, Any], field: str, payload: str) -> dict[str, Any]:
    updated = dict(row)
    existing = updated.get(field)
    updated[field] = f"{existing} {payload}" if isinstance(existing, str) else payload
    return updated


def injector_for(injection: Injection | None) -> NullInjector | UserTurnInjector | ResultInjector:
    if injection is None:
        return NullInjector()
    if injection.channel is Channel.USER_TURN:
        return UserTurnInjector(injection)
    return ResultInjector(injection)
