"""The README's numbers against the committed run.

The brief's standard is that every number in the README is traceable to a committed transcript.
Traceable by inspection decays the first time a run is repeated and a table is not, and a stale
percentage in a README is indistinguishable from a fabricated one to anybody reading it.

So the tables are parsed and compared to `data/reports/experiment.json`. If the experiment is
re-run and the README is not updated, this fails and names the row.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from probe.paths import PROBE_ROOT, REPORTS

README = PROBE_ROOT / "README.md"

ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$")


def _cells(line: str) -> list[str]:
    match = ROW.match(line)
    assert match is not None
    return [cell.strip().strip("*").strip("`") for cell in match.group("cells").split("|")]


def _rows(markdown: str) -> list[list[str]]:
    return [
        _cells(line)
        for line in markdown.splitlines()
        if ROW.match(line) and not set(line) <= set("|- ")
    ]


@pytest.fixture(scope="module")
def summary() -> dict[str, Any]:
    path = REPORTS / "experiment.json"
    if not path.exists():
        pytest.skip("no committed experiment; run scripts/run_experiment.py")
    return dict(json.loads(path.read_text()))


@pytest.fixture(scope="module")
def readme() -> str:
    return README.read_text()


@pytest.fixture(scope="module")
def prose(readme: str) -> str:
    """The README with line wrapping removed, so a phrase check is not a line-length check."""
    return " ".join(readme.split())


def _percent(value: float) -> str:
    return f"{value * 100:.0f}%"


def test_configuration_table_matches_the_committed_run(
    readme: str, summary: dict[str, Any]
) -> None:
    """Every security-versus-utility row in the README is a row in experiment.json."""
    by_label = {entry["label"]: entry for entry in summary["configurations"]} | {
        "all four": summary["configurations"][-1]
    }
    rows = {cells[0]: cells for cells in _rows(readme) if cells and cells[0] in by_label}

    assert len(rows) == len(summary["configurations"]), (
        "the README configuration table has drifted from the measured set of configurations"
    )
    for label, cells in rows.items():
        entry = by_label[label]
        assert cells[1] == _percent(entry["panel"]["asr"]), f"{label}: panel ASR"
        assert cells[2] == f"{entry['utility']['passed']}/{entry['utility']['total']}", (
            f"{label}: utility"
        )
        assert cells[3] == str(entry["utility"]["blocked_calls"]), f"{label}: blocked calls"


def test_channel_table_matches_the_committed_run(readme: str, summary: dict[str, Any]) -> None:
    """The channel split is the README's central claim, so it is the one most worth pinning."""
    undefended = next(entry for entry in summary["configurations"] if not entry["defences"])
    hardened = next(
        entry for entry in summary["configurations"] if entry["defences"] == summary["recommended"]
    )
    channels = undefended["panel"]["by_channel"]
    rows = {cells[0]: cells for cells in _rows(readme) if cells and cells[0] in channels}

    assert set(rows) == set(channels), "the README channel table omits a measured channel"
    for name, cells in rows.items():
        assert cells[2] == _percent(channels[name]["asr"]), f"{name}: undefended"
        assert cells[3] == _percent(hardened["panel"]["by_channel"][name]["asr"]), (
            f"{name}: hardened"
        )


def test_generalisation_gap_matches_the_committed_run(readme: str, summary: dict[str, Any]) -> None:
    heldout = summary["heldout"]
    gap = f"+{heldout['generalisation_gap'] * 100:.0f} points"

    assert gap in readme, f"the README does not state the measured gap of {gap}"
    assert _percent(heldout["seen_asr_on_hardened"]) in readme
    assert _percent(heldout["heldout_asr_on_hardened"]) in readme


def test_search_efficiency_table_matches_the_committed_run(
    readme: str, summary: dict[str, Any]
) -> None:
    first_success = {
        name.replace("_", " "): str(count)
        for name, count in summary["search"]["first_success_at"].items()
    }
    rows = {cells[0]: cells for cells in _rows(readme) if cells and cells[0] in first_success}

    assert set(rows) == set(first_success), "the README omits a class the search found"
    for name, cells in rows.items():
        assert cells[1] == first_success[name], f"{name}: episodes to first success"


def test_episode_counts_match_the_committed_runs(readme: str, summary: dict[str, Any]) -> None:
    episodes = summary["search"]["episodes"] + summary["heldout"]["episodes"]
    panel = sum(
        len(entry["panel"]["mechanisms"]) * len(summary["panel"])
        for entry in [*summary["configurations"], summary["heldout"]]
    )

    assert f"{episodes} search episodes" in readme
    assert f"{panel:,} panel episodes" in readme


def test_readme_states_the_scope_and_the_unrun_target(prose: str) -> None:
    """Two claims that must survive every future edit to this file."""
    assert "No third-party system, model provider, or anyone else's deployment" in prose
    assert "never run" in prose
    assert "ANTHROPIC_API_KEY" in prose


def test_readme_reports_zero_spend_because_the_ledgers_do(
    readme: str, summary: dict[str, Any]
) -> None:
    spent = sum(ledger["spent_usd"] for ledger in summary["ledgers"].values())

    assert f"${spent:.4f}" in readme
