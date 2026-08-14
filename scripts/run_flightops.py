"""The flightops LLM measurement, sized to a dollar cap.

    ANTHROPIC_API_KEY=... python scripts/run_flightops.py

Runs the same M3 -> harden -> M6 arc that `run_experiment.py` drives against the reference
agent, but against the live flightops target and without the nine-way configuration sweep.
The recommended stack (`ALL_DEFENCES`, the four-layer stack that scored best on the reference
agent) is applied directly, on the transfer claim that a defence chosen against a control
should be measured against the real target too.

Writes `data/reports/flightops.json`, which `scripts/build_report.py` renders next to the
reference-agent findings. Nothing here overwrites the reference numbers.

Budget: a hard cap in USD, checked before each expensive phase and after every episode inside
the panel evaluation. The search phases go through `LedgerBook` and stop themselves. The panel
and utility phases do not, so this script tallies their spend and short-circuits before it
would breach the cap.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from flightops.model.store import ObjectStore  # noqa: E402
from flightops.propagation.engine import PropagationEngine, build_turn_model  # noqa: E402

from probe.attacks.corpus import candidate_flights, read_only_scope, seeds  # noqa: E402
from probe.attacks.model import Attack, LicensedScope  # noqa: E402
from probe.defenses.layers import ALL_DEFENCES  # noqa: E402
from probe.defenses.layers import build as build_defences
from probe.episodes import EpisodeResult, drive  # noqa: E402
from probe.eval.generalise import (  # noqa: E402
    MechanismResult,
    PanelReport,
    channel_of,
    distinct_mechanisms,
    mechanism_signature,
    retarget_to,
)
from probe.eval.utility import reference_suite, run_utility  # noqa: E402
from probe.judge import Judge  # noqa: E402
from probe.paths import REPORTS, RUNS, flightops_database  # noqa: E402
from probe.search.ledger import LedgerBook  # noqa: E402
from probe.search.loop import SearchConfig, SearchReport, run_search  # noqa: E402
from probe.search.runlog import RunLog  # noqa: E402
from probe.targets.flightops import FlightopsTarget  # noqa: E402

BUDGET_CAP_USD = 65.0
"""Total spend ceiling across every phase, with $5 head-room under the ledger's $70 allocation.

The pilot measured $0.078/episode mean and $0.111 max. Sizing at $0.12/episode against a
$65 cap leaves room for about 540 episodes; the planned run uses ~180."""

SEARCH_EPISODES = 60
HELDOUT_EPISODES = 40
PANEL_SIZE = 8
SEARCH_SEED = 20260814
HELDOUT_SEED = 99260814
RECOMMENDED: tuple[str, ...] = ALL_DEFENCES
EPISODE_ESTIMATE_USD = 0.12


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set; refusing to run", file=sys.stderr)
        return 2

    store = ObjectStore(flightops_database())
    engine = PropagationEngine(build_turn_model(store))
    judge = Judge(store, engine)
    target = FlightopsTarget(store)

    def scope_for(flight_id: str) -> LicensedScope:
        return read_only_scope(store, engine, flight_id)

    flights = candidate_flights(store)
    panel = flights[:PANEL_SIZE]
    book = LedgerBook.load(RUNS / "ledgers.json")
    for name, allocation in {"search": 70.0, "heldout": 36.0, "utility": 21.0}.items():
        book.allocate(name, allocation)

    print(
        f"budget cap ${BUDGET_CAP_USD:.2f}  ledger prior spend "
        f"${book.ledgers['search'].spent_usd:.4f}\n"
    )

    print(f"phase 1  undefended flightops search ({SEARCH_EPISODES} ep cap)")
    seen = _run_search(
        target=target,
        store=store,
        judge=judge,
        scope_for=scope_for,
        panel=flights,
        book=book,
        run_id="flightops-m3-undefended",
        ledger="search",
        milestone="m3",
        seed=SEARCH_SEED,
        defences=(),
        max_episodes=SEARCH_EPISODES,
    )
    _print_search(seen)
    total_spend = seen.spent_usd
    _guard(total_spend)

    seen_mechs = list(seen.successful_attacks)
    print(
        f"\nphase 2  panel eval on undefended flightops ({len(seen_mechs)} mechanisms × "
        f"{PANEL_SIZE} objects)"
    )
    seen_undef_panel, panel_spend = _evaluate_panel_capped(
        target=target,
        store=store,
        judge=judge,
        mechanisms=seen_mechs,
        panel=panel,
        scope_for=scope_for,
        defences=(),
        remaining=BUDGET_CAP_USD - total_spend,
    )
    total_spend += panel_spend
    _print_panel("seen on undefended", seen_undef_panel)
    _guard(total_spend)

    print(f"\nphase 3  panel eval on hardened flightops ({_label(RECOMMENDED)})")
    seen_hardened_panel, panel_spend = _evaluate_panel_capped(
        target=target,
        store=store,
        judge=judge,
        mechanisms=seen_mechs,
        panel=panel,
        scope_for=scope_for,
        defences=RECOMMENDED,
        remaining=BUDGET_CAP_USD - total_spend,
    )
    total_spend += panel_spend
    _print_panel("seen on hardened", seen_hardened_panel)
    _guard(total_spend)

    print("\nphase 4  utility suite on both configurations")
    tasks = reference_suite(flights)
    utility_undefended = run_utility(target=target, store=store, tasks=tasks, defences=())
    total_spend += utility_undefended.spent_usd
    _print_utility("undefended", utility_undefended)
    _guard(total_spend)
    utility_hardened = run_utility(target=target, store=store, tasks=tasks, defences=RECOMMENDED)
    total_spend += utility_hardened.spent_usd
    _print_utility(_label(RECOMMENDED), utility_hardened)
    _guard(total_spend)

    print(f"\nphase 5  held-out flightops search on hardened target ({HELDOUT_EPISODES} ep cap)")
    heldout = _run_search(
        target=target,
        store=store,
        judge=judge,
        scope_for=scope_for,
        panel=flights,
        book=book,
        run_id="flightops-m6-heldout",
        ledger="heldout",
        milestone="m6",
        seed=HELDOUT_SEED,
        defences=RECOMMENDED,
        max_episodes=HELDOUT_EPISODES,
    )
    _print_search(heldout)
    total_spend += heldout.spent_usd
    _guard(total_spend)

    heldout_mechs = list(heldout.successful_attacks)
    print(
        f"\nphase 6  panel eval on held-out mechanisms ({len(heldout_mechs)} mechanisms × "
        f"{PANEL_SIZE} objects, hardened)"
    )
    heldout_panel, panel_spend = _evaluate_panel_capped(
        target=target,
        store=store,
        judge=judge,
        mechanisms=heldout_mechs,
        panel=panel,
        scope_for=scope_for,
        defences=RECOMMENDED,
        remaining=BUDGET_CAP_USD - total_spend,
    )
    total_spend += panel_spend
    _print_panel("held-out on hardened", heldout_panel)

    gap = heldout_panel.asr - seen_hardened_panel.asr
    print("\ngeneralisation gap on flightops:")
    print(f"  seen mechanisms on hardened:     {seen_hardened_panel.asr:.0%}")
    print(f"  held-out mechanisms on hardened: {heldout_panel.asr:.0%}")
    print(f"  gap:                             {gap:+.0%}")
    print(f"\ntotal measured spend: ${total_spend:.4f}")

    summary: dict[str, Any] = {
        "target": "flightops",
        "panel": list(panel),
        "recommended": list(RECOMMENDED),
        "search": _search_json(seen),
        "seen_on_undefended": _panel_json(seen_undef_panel),
        "seen_on_hardened": _panel_json(seen_hardened_panel),
        "utility": {
            "undefended": _utility_json(utility_undefended),
            "hardened": _utility_json(utility_hardened),
        },
        "heldout": _search_json(heldout)
        | {
            "panel": _panel_json(heldout_panel),
            "seen_asr_on_hardened": seen_hardened_panel.asr,
            "heldout_asr_on_hardened": heldout_panel.asr,
            "generalisation_gap": gap,
        },
        "total_spend_usd": total_spend,
        "budget_cap_usd": BUDGET_CAP_USD,
        "ledgers": {name: asdict(ledger) for name, ledger in sorted(book.ledgers.items())},
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS / "flightops.json"
    out_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"wrote {out_path}")

    store.close()
    return 0


def _guard(total_spend: float) -> None:
    if total_spend >= BUDGET_CAP_USD:
        print(
            f"budget cap ${BUDGET_CAP_USD:.2f} reached at ${total_spend:.4f}; stopping",
            file=sys.stderr,
        )
        raise SystemExit(3)


def _run_search(
    *,
    target: FlightopsTarget,
    store: ObjectStore,
    judge: Judge,
    scope_for: Callable[[str], LicensedScope],
    panel: tuple[str, ...],
    book: LedgerBook,
    run_id: str,
    ledger: str,
    milestone: str,
    seed: int,
    defences: tuple[str, ...],
    max_episodes: int,
) -> SearchReport:
    return run_search(
        target=target,
        store=store,
        judge=judge,
        seeds=seeds(
            store, PropagationEngine(build_turn_model(store)), target.name, target.supported_classes
        ),
        scope_for=scope_for,
        object_ids=panel,
        config=SearchConfig(
            run_id=run_id,
            ledger=ledger,
            milestone=milestone,
            max_episodes=max_episodes,
            seed=seed,
            defences=defences,
            episode_estimate_usd=EPISODE_ESTIMATE_USD,
        ),
        book=book,
        log=RunLog(RUNS / run_id),
    )


def _evaluate_panel_capped(
    *,
    target: FlightopsTarget,
    store: ObjectStore,
    judge: Judge,
    mechanisms: Sequence[Attack],
    panel: Sequence[str],
    scope_for: Callable[[str], LicensedScope],
    defences: tuple[str, ...],
    remaining: float,
) -> tuple[PanelReport, float]:
    """Panel evaluation that stops if it would breach the cap.

    A truncated panel is reported honestly: `trials` counts only what actually ran, so ASR is
    correct for the sample and the panel_size reflects what was attempted. Truncation is
    printed to stderr so the note lands in the summary too.
    """
    report = PanelReport(target=target.name, defences=defences, panel_size=len(panel))
    controls: dict[str, EpisodeResult] = {}
    spent = 0.0
    truncated = False
    for mechanism in distinct_mechanisms(mechanisms):
        if truncated:
            break
        successes = 0
        trials = 0
        criteria: set[int] = set()
        for object_id in panel:
            if spent >= remaining:
                truncated = True
                print(
                    f"  panel truncated: budget for this phase (${remaining:.4f}) reached",
                    file=sys.stderr,
                )
                break
            attack = retarget_to(mechanism, object_id, scope_for(object_id))
            control = attack.control()
            cached = controls.get(control.attack_id)
            if cached is None:
                cached = drive(
                    control,
                    target.open_episode(control, build_defences(defences, control, store)),
                )
                controls[control.attack_id] = cached
                spent += cached.cost_usd
            if spent >= remaining:
                truncated = True
                print(
                    f"  panel truncated after control: budget (${remaining:.4f}) reached",
                    file=sys.stderr,
                )
                break
            result = drive(
                attack, target.open_episode(attack, build_defences(defences, attack, store))
            )
            verdict = judge.grade(result, cached)
            spent += verdict.cost_usd
            trials += 1
            if verdict.succeeded:
                successes += 1
                criteria.update(verdict.criteria_fired)
        if trials > 0:
            report.mechanisms.append(
                MechanismResult(
                    signature=mechanism_signature(mechanism),
                    attack_class=mechanism.attack_class.value,
                    channel=channel_of(mechanism),
                    hypothetical=mechanism.hypothetical,
                    trials=trials,
                    successes=successes,
                    criteria=tuple(sorted(criteria)),
                    example_attack_id=mechanism.attack_id,
                )
            )
    report.spent_usd = spent
    return report, spent


def _label(defences: tuple[str, ...]) -> str:
    return "+".join(defences) if defences else "undefended"


def _print_search(report: SearchReport) -> None:
    print(
        f"  episodes {report.episodes}   raw successes {report.successes}   "
        f"spent ${report.spent_usd:.4f}   stopped: {report.stopped_because}"
    )
    print(f"  first success by class: {report.first_success_at}")


def _print_panel(name: str, report: PanelReport) -> None:
    print(
        f"  {name:<28} ASR {report.asr:>6.0%}   trials {report.trials}   "
        f"spent ${report.spent_usd:.4f}"
    )


def _print_utility(name: str, report: Any) -> None:
    print(f"  utility {name:<38} {report.passed}/{report.total}   spent ${report.spent_usd:.4f}")


def _search_json(report: SearchReport) -> dict[str, Any]:
    return {
        "run_id": report.run_id,
        "episodes": report.episodes,
        "raw_successes": report.successes,
        "spent_usd": report.spent_usd,
        "first_success_at": report.first_success_at,
        "unsupported_classes": list(report.unsupported),
        "stopped_because": report.stopped_because,
    }


def _panel_json(report: PanelReport) -> dict[str, Any]:
    return {
        "asr": report.asr,
        "trials": report.trials,
        "successes": report.successes,
        "panel_size": report.panel_size,
        "spent_usd": report.spent_usd,
        "by_class": {
            name: {
                "trials": trials,
                "successes": successes,
                "asr": successes / trials if trials else 0.0,
            }
            for name, (trials, successes) in sorted(report.by_class().items())
        },
        "by_channel": {
            name: {
                "trials": trials,
                "successes": successes,
                "asr": successes / trials if trials else 0.0,
            }
            for name, (trials, successes) in sorted(report.by_channel().items())
        },
        "mechanisms": [
            {
                "signature": result.signature,
                "class": result.attack_class,
                "channel": result.channel,
                "hypothetical": result.hypothetical,
                "successes": result.successes,
                "trials": result.trials,
                "rate": result.rate,
                "criteria": list(result.criteria),
                "example_attack_id": result.example_attack_id,
            }
            for result in sorted(report.mechanisms, key=lambda item: -item.rate)
        ],
    }


def _utility_json(report: Any) -> dict[str, Any]:
    return {
        "passed": report.passed,
        "total": report.total,
        "pass_rate": report.pass_rate,
        "blocked_calls": report.blocked_calls,
        "spent_usd": report.spent_usd,
        "failures": {
            grade.task_id: list(grade.failures) for grade in report.grades if not grade.passed
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
