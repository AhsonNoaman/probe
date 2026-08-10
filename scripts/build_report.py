"""Regenerate the static findings report from the committed run artefacts.

    python scripts/build_report.py

Reads `data/reports/experiment.json` and the run logs it names, and writes
`data/reports/findings.md`. Pure rendering: it drives no target, spends nothing, and needs no
API key. Re-running it without re-running the experiment reproduces the same file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from probe.eval.report import read_run, render  # noqa: E402
from probe.paths import REPORTS, RUNS  # noqa: E402


def main() -> int:
    summary_path = REPORTS / "experiment.json"
    if not summary_path.exists():
        print(
            f"no experiment summary at {summary_path}; run scripts/run_experiment.py first",
            file=sys.stderr,
        )
        return 1

    summary = json.loads(summary_path.read_text())
    runs = [
        read_run(RUNS / run_id)
        for run_id in (summary["search"]["run_id"], summary["heldout"]["run_id"])
    ]

    path = REPORTS / "findings.md"
    path.write_text(render(summary, runs))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
