"""The search loop: propose, execute, score, prioritise, mutate. Budgeted and resumable.

DESIGN.md section 6. The queue is ordered by a partial-progress score plus a novelty bonus,
because binary success is too sparse to steer: most attacks fail outright and a queue ordered on
a mostly-zero signal is a random walk. The novelty term is what stops the search collapsing onto
whichever class falls first and then reporting a confident zero for the rest -- a failure mode
that looks exactly like a secure target.

Control episodes are cached by content hash. Several mutants of one seed share a control, so the
differential costs closer to 1.1x than 2x.
"""

from __future__ import annotations

import heapq
import itertools
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from random import Random

from flightops.model.store import ObjectStore

from probe.attacks.model import Attack, AttackClass, LicensedScope
from probe.attacks.mutate import OPERATORS, MutationContext, compose
from probe.defenses.layers import build as build_defences
from probe.episodes import EpisodeResult, drive
from probe.judge import Judge
from probe.judge.model import Verdict
from probe.search.ledger import BudgetExhausted, LedgerBook
from probe.search.runlog import Manifest, RunLog
from probe.targets.base import Target


@dataclass(frozen=True)
class SearchConfig:
    run_id: str
    ledger: str
    milestone: str
    max_episodes: int = 200
    seed: int = 20260810
    defences: tuple[str, ...] = ()
    episode_estimate_usd: float = 0.25
    """Used only for the affordability pre-check, so a run stops before an episode it cannot pay
    for rather than after. Measured per-episode cost is what is actually debited."""


@dataclass
class ClassStats:
    attempts: int = 0
    successes: int = 0
    hypothetical_successes: int = 0
    criteria: Counter[int] = field(default_factory=Counter)

    @property
    def asr(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0


@dataclass
class SearchReport:
    run_id: str
    target: str
    defences: tuple[str, ...]
    episodes: int = 0
    successes: int = 0
    spent_usd: float = 0.0
    by_class: dict[str, ClassStats] = field(default_factory=dict)
    novel_mechanisms: set[tuple[str, tuple[int, ...]]] = field(default_factory=set)
    unsupported: tuple[str, ...] = ()
    stopped_because: str = "frontier exhausted"
    successful_attacks: list[Attack] = field(default_factory=list)
    """The attacks that worked, for the panel evaluation in `probe.eval.generalise`.

    The search's own success share is not the reported ASR -- successful attacks breed, so it
    climbs by construction. These are the inputs to the fixed-panel measurement that is.
    """
    first_success_at: dict[str, int] = field(default_factory=dict)
    """Episodes within a class before its first success. The search-efficiency number."""

    @property
    def asr(self) -> float:
        return self.successes / self.episodes if self.episodes else 0.0

    @property
    def usd_per_novel(self) -> float | None:
        return self.spent_usd / len(self.novel_mechanisms) if self.novel_mechanisms else None


class Frontier:
    """A per-class priority queue, popped so that coverage stays balanced.

    A single global queue does not work here, and the first run proved it: successful attacks
    breed, their children inherit a high score, and a class whose seed failed never gets popped
    again. That produces a confident zero for the unexplored class, which is indistinguishable in
    the report from a class the target resisted.

    So the pop order is: least-explored class first, ties broken by the best score waiting in it.
    Priority still decides *which* attack within a class, which is where the progress signal
    earns its keep; the class rotation is what stops the search answering only the question it
    already knows the answer to.
    """

    def __init__(self) -> None:
        self._queues: dict[str, list[tuple[float, int, Attack]]] = {}
        self._tie = itertools.count()
        self._explored: Counter[str] = Counter()

    def __len__(self) -> int:
        return sum(len(queue) for queue in self._queues.values())

    def push(self, attack: Attack, base_priority: float) -> None:
        queue = self._queues.setdefault(attack.attack_class.value, [])
        heapq.heappush(queue, (-base_priority, next(self._tie), attack))

    def pop(self) -> Attack:
        live = [name for name, queue in self._queues.items() if queue]
        if not live:
            raise IndexError("pop from an empty frontier")
        name = min(live, key=lambda cls: (self._explored[cls], self._queues[cls][0][0]))
        _, _, attack = heapq.heappop(self._queues[name])
        self._explored[name] += 1
        return attack


def run_search(
    *,
    target: Target,
    store: ObjectStore,
    judge: Judge,
    seeds: Sequence[Attack],
    scope_for: Callable[[str], LicensedScope],
    object_ids: Sequence[str],
    config: SearchConfig,
    book: LedgerBook,
    log: RunLog,
) -> SearchReport:
    """Drive one budgeted, resumable search run against one target."""
    rng = Random(config.seed)
    context = MutationContext(object_ids=tuple(object_ids), scope_for=scope_for)
    frontier = Frontier()
    for seed in seeds:
        frontier.push(seed, base_priority=1.0)

    log.start(
        Manifest(
            run_id=config.run_id,
            target=target.name,
            ledger=config.ledger,
            milestone=config.milestone,
            seed=config.seed,
            defences=config.defences,
        )
    )

    seen: set[str] = log.seen_attack_ids()
    resumed = len(seen)
    report = SearchReport(
        run_id=config.run_id,
        target=target.name,
        defences=config.defences,
        unsupported=tuple(
            sorted(cls.value for cls in AttackClass if cls not in target.supported_classes)
        ),
    )
    controls: dict[str, EpisodeResult] = {}
    scoring: list[Attack] = []

    while frontier and report.episodes < config.max_episodes:
        attack = frontier.pop()
        if attack.attack_id in seen:
            continue
        if attack.attack_class not in target.supported_classes:
            continue
        if not book.affordable(config.ledger, config.episode_estimate_usd, config.milestone):
            report.stopped_because = f"ledger {config.ledger!r} exhausted"
            break

        seen.add(attack.attack_id)
        control = _control_for(attack, target, store, config, controls)
        defences = build_defences(config.defences, attack, store)
        result = drive(attack, target.open_episode(attack, defences))
        verdict = judge.grade(result, control)

        try:
            book.debit(config.ledger, verdict.cost_usd, config.milestone)
        except BudgetExhausted as exhausted:
            report.stopped_because = str(exhausted)
            break

        log.append(result, verdict)
        _record(report, attack, verdict)
        if verdict.progress > 0:
            scoring.append(attack)

        for operator in OPERATORS:
            child = operator(attack, rng, context)
            if child is not None and child.attack_id not in seen:
                frontier.push(child, base_priority=verdict.progress)
        crossed = compose(scoring[-6:], rng, context)
        if crossed is not None and crossed.attack_id not in seen:
            frontier.push(crossed, base_priority=verdict.progress)

    report.spent_usd = log.spent_usd()
    if resumed:
        report.stopped_because += f" (resumed over {resumed} recorded episodes)"
    return report


def _control_for(
    attack: Attack,
    target: Target,
    store: ObjectStore,
    config: SearchConfig,
    cache: dict[str, EpisodeResult],
) -> EpisodeResult:
    control = attack.control()
    cached = cache.get(control.attack_id)
    if cached is not None:
        return cached
    result = drive(
        control, target.open_episode(control, build_defences(config.defences, control, store))
    )
    cache[control.attack_id] = result
    return result


def _record(report: SearchReport, attack: Attack, verdict: Verdict) -> None:
    stats = report.by_class.setdefault(attack.attack_class.value, ClassStats())
    stats.attempts += 1
    report.episodes += 1
    if not verdict.succeeded:
        return
    stats.successes += 1
    report.successes += 1
    report.successful_attacks.append(attack)
    report.first_success_at.setdefault(attack.attack_class.value, stats.attempts)
    if verdict.hypothetical:
        stats.hypothetical_successes += 1
    for criterion in verdict.criteria_fired:
        stats.criteria[criterion] += 1
    report.novel_mechanisms.add((attack.attack_class.value, verdict.criteria_fired))
