"""Run one budgeted search against one target.

    python scripts/run_search.py --target reference --ledger search --milestone m3
    python scripts/run_search.py --target reference --ledger search --defences separation
    python scripts/run_search.py --target flightops --ledger search --milestone m3   # needs a key

The reference target runs offline against a deterministic policy: no API key, no cost, and the
same result every time for a given seed. The flightops target drives a live model and spends
money, which is why the ledger is not optional.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from flightops.model.store import ObjectStore  # noqa: E402
from flightops.propagation.engine import PropagationEngine, build_turn_model  # noqa: E402

from probe.attacks.corpus import candidate_flights, read_only_scope, seeds  # noqa: E402
from probe.attacks.model import LicensedScope  # noqa: E402
from probe.defenses.layers import DEFENCES  # noqa: E402
from probe.judge import Judge  # noqa: E402
from probe.paths import REFERENCE_DB, RUNS, flightops_database, flightops_root  # noqa: E402
from probe.search.ledger import LedgerBook  # noqa: E402
from probe.search.loop import SearchConfig, SearchReport, run_search  # noqa: E402
from probe.search.runlog import RunLog  # noqa: E402
from probe.targets.base import Target  # noqa: E402
from probe.targets.flightops import FlightopsTarget  # noqa: E402
from probe.targets.reference import ClosureLog, ReferenceTarget  # noqa: E402

LEDGER_FILE = RUNS / "ledgers.json"

DEFAULT_ALLOCATION = {"search": 70.0, "heldout": 36.0, "utility": 21.0}
"""DESIGN.md section 7.4. Allocated once; `LedgerBook.allocate` never tops an existing one up."""


def _commit(repo: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("reference", "flightops"), required=True)
    parser.add_argument("--ledger", default="search")
    parser.add_argument("--milestone", default="m3")
    parser.add_argument("--defences", default="", help="comma separated; empty means undefended")
    parser.add_argument("--max-episodes", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260810)
    parser.add_argument("--run-id", default=None)
    args = parser.parse_args()

    defences = tuple(name for name in args.defences.split(",") if name)
    unknown = [name for name in defences if name not in DEFENCES]
    if unknown:
        raise SystemExit(f"unknown defence(s): {', '.join(unknown)}; have {', '.join(DEFENCES)}")

    run_id = args.run_id or f"{args.target}-{'-'.join(defences) if defences else 'undefended'}"

    store = ObjectStore(flightops_database())
    engine = PropagationEngine(build_turn_model(store))
    judge = Judge(store, engine)

    closure_log: ClosureLog | None = None
    target: Target
    if args.target == "reference":
        closure_log = ClosureLog(REFERENCE_DB)
        target = ReferenceTarget(store, closure_log)
    else:
        target = FlightopsTarget(store)

    book = LedgerBook.load(LEDGER_FILE)
    for name, allocation in DEFAULT_ALLOCATION.items():
        book.allocate(name, allocation)

    log = RunLog(RUNS / run_id)
    config = SearchConfig(
        run_id=run_id,
        ledger=args.ledger,
        milestone=args.milestone,
        max_episodes=args.max_episodes,
        seed=args.seed,
        defences=defences,
        episode_estimate_usd=0.0 if args.target == "reference" else 0.25,
    )

    def scope_for(flight_id: str) -> LicensedScope:
        return read_only_scope(store, engine, flight_id)

    report = run_search(
        target=target,
        store=store,
        judge=judge,
        seeds=seeds(store, engine, target.name, target.supported_classes),
        scope_for=scope_for,
        object_ids=candidate_flights(store),
        config=config,
        book=book,
        log=log,
    )
    manifest = log.manifest_path
    if manifest.exists():
        text = (
            manifest.read_text()
            .replace('"probe_commit": ""', f'"probe_commit": "{_commit(Path.cwd())}"')
            .replace('"flightops_commit": ""', f'"flightops_commit": "{_commit(flightops_root())}"')
        )
        manifest.write_text(text)

    _print(report)
    store.close()
    if closure_log is not None:
        closure_log.close()
    return 0


def _print(report: SearchReport) -> None:
    print(f"\nrun {report.run_id}  target={report.target}  defences={report.defences or '(none)'}")
    print(f"  episodes {report.episodes}   successes {report.successes}   ASR {report.asr:.0%}")
    print(f"  spent ${report.spent_usd:.4f}   stopped: {report.stopped_because}")
    if report.usd_per_novel is not None:
        print(
            f"  novel mechanisms {len(report.novel_mechanisms)} at ${report.usd_per_novel:.4f} each"
        )
    print("\n  class                      attempts  successes   ASR   criteria")
    for name, stats in sorted(report.by_class.items()):
        criteria = ",".join(str(c) for c in sorted(stats.criteria)) or "-"
        print(
            f"  {name:<26} {stats.attempts:>8} {stats.successes:>10} {stats.asr:>6.0%}   {criteria}"
        )
    for name in report.unsupported:
        print(f"  {name:<26} {'n/a':>8} {'n/a':>10} {'n/a':>6}   target has no surface for it")


if __name__ == "__main__":
    raise SystemExit(main())
