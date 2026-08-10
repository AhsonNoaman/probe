"""The static findings report.

DESIGN.md section 9 cut the brief's frontend to this: a Markdown document regenerated from the
committed run artefacts, so every figure in it has a file behind it and `make report` reproduces
it byte for byte. Nothing here recomputes a result -- rendering and measuring are separate on
purpose, because a renderer that could quietly re-derive a number is a renderer that could
disagree with the run it claims to describe.

The report leads with scope and with what was *not* run. Those are the two things a reader has to
know before any percentage in it means anything.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from probe.attacks.model import REAL_CHANNELS as _REAL_CHANNEL_ENUMS
from probe.judge.model import Criterion

REAL_CHANNELS = frozenset(channel.value for channel in _REAL_CHANNEL_ENUMS)
"""Channels an attacker controls against the current targets, as strings for rendering."""

SCOPE = """\
Every target in this report is a system the author built and hosts: the `flightops` agent and a
deliberately weak reference agent written for this repository. No third-party system, model
provider, or anyone else's deployment was probed, and the harness has no capability to reach one
-- targets are Python objects constructed in-process, not endpoints.\
"""


@dataclass(frozen=True)
class RunFacts:
    """What a run log says about itself, independent of the summary that describes it."""

    run_id: str
    episodes: int
    criteria: dict[int, int]
    transcripts: int

    @property
    def criteria_line(self) -> str:
        if not self.criteria:
            return "none"
        return ", ".join(
            f"{Criterion(number).label} ({number}): {count}"
            for number, count in sorted(self.criteria.items())
        )


def read_run(root: Path) -> RunFacts:
    """Count what actually landed in a run directory.

    Read from the episode lines rather than from `experiment.json`, so a report built against a
    stale or hand-edited summary disagrees with itself visibly instead of rendering cleanly.
    """
    episodes_path = root / "episodes.jsonl"
    counts: Counter[int] = Counter()
    episodes = 0
    for line in episodes_path.read_text().splitlines():
        if not line.strip():
            continue
        episodes += 1
        for finding in json.loads(line)["verdict"]["findings"]:
            counts[int(finding["criterion"])] += 1
    transcripts = len(list((root / "transcripts").glob("*.json")))
    return RunFacts(
        run_id=root.name, episodes=episodes, criteria=dict(counts), transcripts=transcripts
    )


def _percent(value: float) -> str:
    return f"{value * 100:.0f}%"


def _table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def _configuration_rows(summary: dict[str, Any]) -> list[list[str]]:
    return [
        [
            f"`{entry['label']}`",
            _percent(entry["panel"]["asr"]),
            f"{entry['utility']['passed']}/{entry['utility']['total']}",
            str(entry["utility"]["blocked_calls"]),
        ]
        for entry in summary["configurations"]
    ]


def _class_rows(summary: dict[str, Any]) -> list[list[str]]:
    undefended = next(entry for entry in summary["configurations"] if not entry["defences"])
    recommended = next(
        entry for entry in summary["configurations"] if entry["defences"] == summary["recommended"]
    )
    first_success = summary["search"]["first_success_at"]
    rows: list[list[str]] = []
    for name, stats in undefended["panel"]["by_class"].items():
        hardened = recommended["panel"]["by_class"].get(name)
        rows.append(
            [
                name.replace("_", " "),
                str(first_success.get(name, "not found")),
                _percent(stats["asr"]),
                _percent(hardened["asr"]) if hardened else "n/a",
            ]
        )
    for name in summary["search"]["unsupported_classes"]:
        rows.append([name.replace("_", " "), "n/a", "n/a", "n/a"])
    return rows


def _channel_rows(summary: dict[str, Any]) -> list[list[str]]:
    undefended = next(entry for entry in summary["configurations"] if not entry["defences"])
    recommended = next(
        entry for entry in summary["configurations"] if entry["defences"] == summary["recommended"]
    )
    rows: list[list[str]] = []
    for name, stats in undefended["panel"]["by_channel"].items():
        hardened = recommended["panel"]["by_channel"].get(name)
        rows.append(
            [
                f"`{name}`",
                "attacker-controlled today" if name in REAL_CHANNELS else "hypothetical",
                _percent(stats["asr"]),
                _percent(hardened["asr"]) if hardened else "n/a",
            ]
        )
    return rows


def _survivor_rows(panel: dict[str, Any], limit: int = 8) -> list[list[str]]:
    survivors = [entry for entry in panel["mechanisms"] if entry["successes"]]
    rows: list[list[str]] = []
    for entry in survivors[:limit]:
        # The signature is prefixed with its own channel, which has its own column here.
        payload = entry["signature"].split(":", 1)[-1].strip()
        rows.append(
            [
                f"`{payload[:96]}`",
                entry["class"].replace("_", " "),
                f"`{entry['channel']}`" + (" (hypothetical)" if entry["hypothetical"] else ""),
                f"{entry['successes']}/{entry['trials']}",
                ", ".join(str(number) for number in entry["criteria"]) or "none",
            ]
        )
    return rows


def render(summary: dict[str, Any], runs: Sequence[RunFacts]) -> str:
    """The whole report, from the summary and the run logs behind it."""
    recommended = tuple(summary["recommended"])
    label = "+".join(recommended) if recommended else "undefended"
    heldout = summary["heldout"]
    search = summary["search"]
    total_spend = sum(ledger["spent_usd"] for ledger in summary["ledgers"].values())

    lines: list[str] = [
        "# probe: findings",
        "",
        "Generated by `make report` from the run logs under `data/runs/`. Every figure below is",
        "read from a committed file; nothing here is recomputed at render time.",
        "",
        "## Scope of engagement",
        "",
        SCOPE,
        "",
        "## What was measured, and what was not",
        "",
        "Every number in this report comes from the **reference agent**: a deterministic,",
        "non-LLM instruction-following policy written to be under-defended. It is the control that",
        "shows the harness can detect a break at all. It is not evidence about any language",
        "model's robustness.",
        "",
        "The `flightops` LLM target was built, wired, and tested, but **not run**. Driving it",
        "needs an `ANTHROPIC_API_KEY`, which this environment does not have. No estimated,",
        "extrapolated, or model-generated figure stands in for it anywhere in this repository.",
        "",
        f"Measured spend across every ledger: **${total_spend:.4f}**. The reference agent is",
        "offline and free, which is why the search could afford "
        f"{sum(run.episodes for run in runs)} episodes.",
        "",
        "## Search efficiency and class coverage",
        "",
        f"Undefended search: {search['episodes']} episodes, {search['raw_successes']} raw",
        "successes. That raw count is *not* an attack success rate -- successful attacks breed in",
        "a search, so the share of successes climbs by construction. The ASR columns below are",
        f"panel figures: each distinct mechanism retargeted across a fixed {len(summary['panel'])}"
        "-object panel fixed before the run.",
        "",
    ]
    lines += _table(
        ("attack class", "episodes to first success", "ASR undefended", f"ASR under `{label}`"),
        _class_rows(summary),
    )
    lines += [
        "",
        "Classes marked `n/a` have no surface on this target: scope creep needs a multi-turn",
        "driver, and threshold pressure and refusal inversion need the `triage` agent, which does",
        "not exist yet. They are reported as absent rather than as a zero, because a zero would",
        "read as a defended result.",
        "",
        "### By delivery channel",
        "",
        "Class and channel are independent axes, and `move_channel` moves one without the other:",
        "a tool-result-poisoning payload relocated into the user turn keeps its class. Read on",
        "class alone, a hostile user turn would be filed under whichever seed it descended from.",
        "This split is also the one that separates a finding an attacker could deliver today from",
        "one that assumes the data source is already compromised.",
        "",
    ]
    lines += _table(
        ("channel", "status", "ASR undefended", f"ASR under `{label}`"), _channel_rows(summary)
    )
    lines += [
        "",
        "`record_field` and `tool_result` are marked hypothetical because BTS On-Time Performance",
        "carries no attacker-writable free-text field. Reaching the agent through them requires",
        "synthesising records the real source cannot contain, so those rows measure what the agent",
        "would do with a compromised source -- worth knowing, and not the same claim as the",
        "`user_turn` row.",
        "",
        "## Security against utility",
        "",
        "Utility is a four-task benign suite run under each configuration. A defence that raises",
        "security by breaking the legitimate path has not helped, and this table is where that",
        "would show.",
        "",
    ]
    lines += _table(
        ("configuration", "panel ASR", "benign tasks passed", "calls blocked"),
        _configuration_rows(summary),
    )
    lines += [
        "",
        f"## Recommended configuration: `{label}`",
        "",
        "Chosen by `choose_recommended` off the measured table -- lowest ASR, ties broken by",
        "utility and then by fewer layers -- rather than asserted in advance. An earlier run of",
        "this experiment hardcoded a recommendation that omitted `authorisation`, then reported",
        "the resulting hole as a generalisation gap. The selection is now derived, so that",
        "particular mistake cannot recur silently.",
        "",
        "## Generalisation gap",
        "",
        "The question M6 exists to answer: did hardening fix the mechanisms it was shown, or the",
        "class of mechanism? A fresh search, different seed, drawing on a ledger locked until this",
        "milestone, run against the already-hardened target.",
        "",
    ]
    lines += _table(
        ("measurement", "value"),
        [
            [
                "mechanisms found at M3, against the hardened stack",
                _percent(heldout["seen_asr_on_hardened"]),
            ],
            [
                "mechanisms found fresh at M6, against the same stack",
                _percent(heldout["heldout_asr_on_hardened"]),
            ],
            ["**generalisation gap**", f"**{heldout['generalisation_gap'] * 100:+.0f} points**"],
        ],
    )
    lines += [
        "",
        "A positive gap of this size means the hardening is substantially specific to what it was",
        "shown. The channel table above is the explanation, and it is a sharper result than the",
        "gap alone: the recommended stack closes both data channels completely and leaves the",
        "user turn almost untouched. Every mechanism the held-out search found is a user-turn",
        "mechanism, which is why a fresh search recovers the undefended rate.",
        "",
        "That is a property of the threat model rather than a bug in the layers. All four defend",
        "the boundary between *data the agent read* and *instructions it follows*. None of them",
        "governs what the principal may ask for, so an agent whose user is hostile is outside what",
        "this stack was built to protect. Closing it needs a layer the search has not yet been run",
        "against: an authorisation check on the request itself, rather than on the data.",
        "",
        "### Mechanisms that survive the recommended stack",
        "",
    ]
    survivors = _survivor_rows(heldout["panel"])
    if survivors:
        lines += _table(("mechanism", "class", "channel", "panel hits", "criteria"), survivors)
    else:
        lines.append("None. Every held-out mechanism was stopped.")
    lines += [
        "",
        "## Provenance",
        "",
        "Criteria counts are read from the episode logs, not from the summary, so a stale summary",
        "shows up as a disagreement rather than rendering cleanly.",
        "",
    ]
    lines += _table(
        ("run", "episodes", "transcripts", "criteria fired"),
        [
            [f"`{run.run_id}`", str(run.episodes), str(run.transcripts), run.criteria_line]
            for run in runs
        ],
    )
    lines += [
        "",
        "Criterion 4 (abstention collapse) fires nowhere above. It is implemented and tested, but",
        "it needs a target that refuses under threshold pressure, which is `triage`.",
        "",
    ]
    lines += _table(
        ("ledger", "allocated", "spent", "episodes"),
        [
            [
                f"`{name}`",
                f"${ledger['allocated_usd']:.2f}",
                f"${ledger['spent_usd']:.4f}",
                str(ledger["episodes"]),
            ]
            for name, ledger in sorted(summary["ledgers"].items())
        ],
    )
    return "\n".join(lines) + "\n"
