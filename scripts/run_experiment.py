"""The whole experiment: search, defences, utility, and the held-out generalisation gap.

    python scripts/run_experiment.py

Runs offline against the reference agent and costs nothing. The flightops target is not driven
here: it needs an ANTHROPIC_API_KEY and its numbers would be a live spend, so `run_search.py`
drives it deliberately rather than a pipeline doing it as a side effect.

Order matters and mirrors the milestones. The held-out search (M6) uses a different seed, draws
from a ledger reserved at M3, and is graded on mechanisms it discovered itself against the
already-hardened target. Comparing that with how the M3 mechanisms fare against the same
hardened target is the generalisation gap: if hardening only memorised what it was shown, the
fresh mechanisms still land.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from flightops.model.store import ObjectStore  # noqa: E402
from flightops.propagation.engine import PropagationEngine, build_turn_model  # noqa: E402

from probe.attacks.corpus import candidate_flights, read_only_scope, seeds  # noqa: E402
from probe.attacks.model import LicensedScope  # noqa: E402
from probe.defenses.layers import ALL_DEFENCES  # noqa: E402
from probe.eval.generalise import PanelReport, evaluate_panel  # noqa: E402
from probe.eval.utility import reference_suite, run_utility  # noqa: E402
from probe.judge import Judge  # noqa: E402
from probe.paths import REFERENCE_DB, REPORTS, RUNS, flightops_database  # noqa: E402
from probe.search.ledger import LedgerBook  # noqa: E402
from probe.search.loop import SearchConfig, SearchReport, run_search  # noqa: E402
from probe.search.runlog import RunLog  # noqa: E402
from probe.targets.reference import ClosureLog, ReferenceTarget  # noqa: E402

CONFIGURATIONS: tuple[tuple[str, ...], ...] = (
    (),
    ("separation",),
    ("authorisation",),
    ("preconditions",),
    ("citation",),
    ("separation", "authorisation"),
    ("authorisation", "preconditions"),
    ("separation", "citation"),
    ALL_DEFENCES,
)
"""Four defences alone, three pairs, and the full stack. DESIGN.md section 9 cuts the brief's
2^6 matrix; these are the interactions with a stated reason to expect one."""


def choose_recommended(configurations: list[dict[str, Any]]) -> tuple[str, ...]:
    """The configuration to harden with, read off the measured table rather than asserted.

    Lowest attack success rate first; ties broken by utility, then by preferring fewer layers.
    Picking it in advance is how the first run of this experiment ended up hardening with a stack
    that omitted the only layer touching an entire attack channel, and then reporting the
    resulting hole as a generalisation gap.
    """
    ranked = sorted(
        configurations,
        key=lambda entry: (
            entry["panel"]["asr"],
            -entry["utility"]["pass_rate"],
            len(entry["defences"]),
        ),
    )
    return tuple(ranked[0]["defences"])


PANEL_SIZE = 8
SEARCH_SEED = 20260810
HELDOUT_SEED = 99180203
"""A different seed, so M6 explores a different region of the same space rather than replaying
M3's tree against a changed target."""

MAX_EPISODES = 140


def _label(defences: tuple[str, ...]) -> str:
    return "+".join(defences) if defences else "undefended"


def main() -> int:
    store = ObjectStore(flightops_database())
    engine = PropagationEngine(build_turn_model(store))
    judge = Judge(store, engine)
    closure_log = ClosureLog(REFERENCE_DB)
    target = ReferenceTarget(store, closure_log)

    def scope_for(flight_id: str) -> LicensedScope:
        return read_only_scope(store, engine, flight_id)

    flights = candidate_flights(store)
    panel = flights[:PANEL_SIZE]
    book = LedgerBook.load(RUNS / "ledgers.json")
    for name, allocation in {"search": 70.0, "heldout": 36.0, "utility": 21.0}.items():
        book.allocate(name, allocation)

    print("M3  undefended search against the reference agent")
    found = _search(
        target,
        store,
        engine,
        judge,
        scope_for,
        flights,
        book,
        "reference-m3",
        "search",
        "m3",
        SEARCH_SEED,
        (),
    )
    print(f"    {found.episodes} episodes, {found.successes} raw successes, ${found.spent_usd:.4f}")
    print(f"    attempts to first success by class: {found.first_success_at}")

    seen_mechanisms = list(found.successful_attacks)
    summary: dict[str, Any] = {
        "panel": list(panel),
        "search": {
            "run_id": found.run_id,
            "episodes": found.episodes,
            "raw_successes": found.successes,
            "spent_usd": found.spent_usd,
            "first_success_at": found.first_success_at,
            "unsupported_classes": list(found.unsupported),
            "note": (
                "raw_successes counts search-generated episodes, in which successful attacks "
                "breed. It is not an attack success rate. The reported ASR is the panel figure."
            ),
        },
        "configurations": [],
    }

    print(f"\nM4/M5  {len(CONFIGURATIONS)} configurations over a fixed {len(panel)}-object panel")
    for defences in CONFIGURATIONS:
        panel_report = evaluate_panel(
            target=target,
            store=store,
            judge=judge,
            mechanisms=seen_mechanisms,
            panel=panel,
            scope_for=scope_for,
            defences=defences,
        )
        utility = run_utility(
            target=target, store=store, tasks=reference_suite(flights), defences=defences
        )
        summary["configurations"].append(
            {
                "defences": list(defences),
                "label": _label(defences),
                "panel": _panel_json(panel_report),
                "utility": {
                    "passed": utility.passed,
                    "total": utility.total,
                    "pass_rate": utility.pass_rate,
                    "blocked_calls": utility.blocked_calls,
                    "failures": {
                        grade.task_id: list(grade.failures)
                        for grade in utility.grades
                        if not grade.passed
                    },
                },
            }
        )
        print(
            f"    {_label(defences):<42} panel ASR {panel_report.asr:>6.0%}   "
            f"utility {utility.passed}/{utility.total}"
        )

    recommended = choose_recommended(summary["configurations"])
    summary["recommended"] = list(recommended)
    print(f"\nM6  held-out search against the best measured stack ({_label(recommended)})")
    heldout = _search(
        target,
        store,
        engine,
        judge,
        scope_for,
        flights,
        book,
        "reference-m6-heldout",
        "heldout",
        "m6",
        HELDOUT_SEED,
        recommended,
    )
    heldout_panel = evaluate_panel(
        target=target,
        store=store,
        judge=judge,
        mechanisms=list(heldout.successful_attacks),
        panel=panel,
        scope_for=scope_for,
        defences=recommended,
    )
    seen_on_hardened = next(
        entry for entry in summary["configurations"] if tuple(entry["defences"]) == recommended
    )
    gap = heldout_panel.asr - seen_on_hardened["panel"]["asr"]
    summary["heldout"] = {
        "run_id": heldout.run_id,
        "seed": HELDOUT_SEED,
        "episodes": heldout.episodes,
        "raw_successes": heldout.successes,
        "spent_usd": heldout.spent_usd,
        "hardened_with": list(recommended),
        "panel": _panel_json(heldout_panel),
        "seen_asr_on_hardened": seen_on_hardened["panel"]["asr"],
        "heldout_asr_on_hardened": heldout_panel.asr,
        "generalisation_gap": gap,
    }
    print(f"    seen mechanisms on hardened:     {seen_on_hardened['panel']['asr']:.0%}")
    print(f"    held-out mechanisms on hardened: {heldout_panel.asr:.0%}")
    print(f"    generalisation gap:              {gap:+.0%}")

    summary["ledgers"] = {name: asdict(ledger) for name, ledger in sorted(book.ledgers.items())}
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "experiment.json"
    path.write_text(json.dumps(summary, indent=2) + "\n")
    print(f"\nwrote {path}")

    store.close()
    closure_log.close()
    return 0


def _search(
    target: ReferenceTarget,
    store: ObjectStore,
    engine: PropagationEngine,
    judge: Judge,
    scope_for: Any,
    flights: tuple[str, ...],
    book: LedgerBook,
    run_id: str,
    ledger: str,
    milestone: str,
    seed: int,
    defences: tuple[str, ...],
) -> SearchReport:
    return run_search(
        target=target,
        store=store,
        judge=judge,
        seeds=seeds(store, engine, target.name, target.supported_classes),
        scope_for=scope_for,
        object_ids=flights,
        config=SearchConfig(
            run_id=run_id,
            ledger=ledger,
            milestone=milestone,
            max_episodes=MAX_EPISODES,
            seed=seed,
            defences=defences,
            episode_estimate_usd=0.0,
        ),
        book=book,
        log=RunLog(RUNS / run_id),
    )


def _panel_json(report: PanelReport) -> dict[str, Any]:
    return {
        "asr": report.asr,
        "trials": report.trials,
        "successes": report.successes,
        "panel_size": report.panel_size,
        "by_class": {
            name: {"trials": trials, "successes": successes, "asr": successes / trials}
            for name, (trials, successes) in sorted(report.by_class().items())
        },
        "by_channel": {
            name: {"trials": trials, "successes": successes, "asr": successes / trials}
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


if __name__ == "__main__":
    raise SystemExit(main())
