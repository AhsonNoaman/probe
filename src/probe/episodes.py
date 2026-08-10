"""Driving one episode to a result.

flightops's `loop.run` does the request-execute cycle, owns the message list and produces the
transcript; probe supplies the four arguments it is already parameterised over. That is the
whole of the reuse the brief asked for, and it means probe never writes an agent loop, a
transcript format, a cost model or a replay path.

What probe adds around it is the part the judge needs: the state the target mutated, the calls
the defences stopped, and the answer after post-answer defences have run. The transcript keeps
the unfiltered answer, because a defence that rewrites an answer must not also be able to
rewrite the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from flightops.agent.loop import RefusedByModel, Transcript, run

from probe.attacks.model import Attack
from probe.targets.base import BlockRecord, Episode, StateChange


@dataclass(frozen=True)
class EpisodeResult:
    """Everything one attack produced, and everything needed to grade it."""

    attack: Attack
    transcript: Transcript
    answer: str
    changes: tuple[StateChange, ...]
    scenario_clocks: dict[str, datetime]
    blocked: tuple[BlockRecord, ...]
    defences: tuple[str, ...]
    refused: bool = False

    @property
    def cost_usd(self) -> float:
        return self.transcript.cost_usd

    @property
    def target_name(self) -> str:
        return self.attack.target_name


def drive(attack: Attack, episode: Episode) -> EpisodeResult:
    """Run one episode through flightops's loop and collect what the judge reads."""
    refused = False
    try:
        transcript = run(
            question_id=attack.attack_id,
            question=episode.user_turn,
            agent=episode.target_name,
            system=episode.system,
            tools=episode.tool_schemas,
            execute=episode.execute,
            transport=episode.transport,
        )
    except RefusedByModel as declined:
        # A refusal is an outcome, not a crash: the correct response to many of these attacks is
        # to decline, and a harness that treated it as an error would lose that signal.
        refused = True
        transcript = Transcript(
            question_id=attack.attack_id,
            question=episode.user_turn,
            agent=episode.target_name,
            model="",
            recorded_at=datetime.now().isoformat(timespec="seconds"),
            answer="",
            error=f"refused: {declined}",
        )

    return EpisodeResult(
        attack=attack,
        transcript=transcript,
        answer=episode.filter_answer(transcript.answer),
        changes=tuple(episode.observer.changes()),
        scenario_clocks=dict(episode.observer.scenario_clocks()),
        blocked=tuple(episode.blocked),
        defences=episode.defences,
        refused=refused,
    )
