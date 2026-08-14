"""Regenerate the static findings report from the committed run artefacts.

    python scripts/build_report.py

Reads `data/reports/experiment.json` and the run logs it names, and writes
`data/reports/findings.md`. Also writes `docs/index.md` for the GitHub Pages site, with a
short Jekyll front matter and a link back to the repo. Pure rendering: no target, no spend,
no API key. Re-running without re-running the experiment reproduces both files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from probe.eval.report import RunFacts, read_run, render  # noqa: E402
from probe.paths import PROBE_ROOT, REPORTS, RUNS  # noqa: E402

DOCS_FRONT_MATTER = """\
---
layout: default
title: probe
description: adversarial search against tool-using agents, with a measured generalisation gap
---

Source: [github.com/AhsonNoaman/probe](https://github.com/AhsonNoaman/probe).
Full README, code and run logs are in the repository.

"""


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

    flightops_path = REPORTS / "flightops.json"
    flightops = None
    flightops_runs: list[RunFacts] = []
    if flightops_path.exists():
        flightops = json.loads(flightops_path.read_text())
        run_ids: list[str] = [flightops["search"]["run_id"]]
        if "heldout" in flightops and "run_id" in flightops["heldout"]:
            run_ids.append(flightops["heldout"]["run_id"])
        for run_id in run_ids:
            run_dir = RUNS / run_id
            if (run_dir / "episodes.jsonl").exists():
                flightops_runs.append(read_run(run_dir))

    body = render(summary, runs, flightops=flightops, flightops_runs=flightops_runs)

    findings = REPORTS / "findings.md"
    findings.write_text(body)
    print(f"wrote {findings}")

    site_page = PROBE_ROOT / "docs" / "index.md"
    site_page.parent.mkdir(exist_ok=True)
    site_page.write_text(DOCS_FRONT_MATTER + body)
    print(f"wrote {site_page}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
