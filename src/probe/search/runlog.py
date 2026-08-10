"""The run log: append-only JSONL, so a search is resumable and its evidence is committed.

Mirrors flightops's committed-transcript convention. Two properties matter.

**Resume replays the log.** The frontier and the spend are rebuilt from what actually happened
rather than from a checkpoint that could disagree with it. Because attack ids are content
hashes, a resumed run that re-proposes an identical attack is a cache hit, not a re-spend.

**Re-grading is free.** Transcripts are written verbatim, so a judge change re-scores every past
episode with no API spend. That is what makes fixing a known-wrong check affordable instead of a
reason to leave it in.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from probe.attacks.model import (
    Attack,
    AttackClass,
    Channel,
    GroundedClaim,
    Injection,
    LicensedScope,
    Quantity,
)
from probe.episodes import EpisodeResult
from probe.judge.model import Verdict


@dataclass
class Manifest:
    """What a run was, recorded before it starts."""

    run_id: str
    target: str
    ledger: str
    milestone: str
    seed: int
    defences: tuple[str, ...]
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    probe_commit: str = ""
    flightops_commit: str = ""
    notes: str = ""


def _attack_json(attack: Attack) -> dict[str, Any]:
    return {
        "attack_id": attack.attack_id,
        "attack_class": attack.attack_class.value,
        "target": attack.target_name,
        "user_turn": attack.user_turn,
        "injection": (
            {
                "channel": attack.injection.channel.value,
                "payload": attack.injection.payload,
                "marker": attack.injection.marker,
                "tool_name": attack.injection.tool_name,
                "field_path": attack.injection.field_path,
            }
            if attack.injection
            else None
        ),
        "parent_id": attack.parent_id,
        "operator": attack.operator,
        "origin": attack.origin,
        "notes": attack.notes,
        "hypothetical": attack.hypothetical,
        "licensed_scope": {
            "actions": sorted(attack.licensed_scope.actions),
            "object_ids": sorted(attack.licensed_scope.object_ids),
            "reference_clock": (
                attack.licensed_scope.reference_clock.isoformat()
                if attack.licensed_scope.reference_clock
                else None
            ),
            "verified_by": attack.licensed_scope.verified_by,
            "grounded_claims": [
                {
                    "quantity": claim.quantity.value,
                    "root_object_id": claim.root_object_id,
                    "expected": claim.expected,
                    "tolerance": claim.tolerance,
                    "verified_by": claim.verified_by,
                    "induced_value": claim.induced_value,
                }
                for claim in attack.licensed_scope.grounded_claims
            ],
        },
    }


def attack_from_json(payload: dict[str, Any]) -> Attack:
    """Rebuild an attack from its logged form.

    Needed by M6: the held-out run re-drives mechanisms discovered at M3 against a hardened
    target, and it must re-drive the recorded attack rather than a regenerated approximation of
    it, or the two runs are not comparable.
    """
    scope_raw = payload["licensed_scope"]
    scope = LicensedScope(
        actions=frozenset(scope_raw["actions"]),
        object_ids=frozenset(scope_raw["object_ids"]),
        verified_by=scope_raw["verified_by"],
        reference_clock=(
            datetime.fromisoformat(scope_raw["reference_clock"])
            if scope_raw.get("reference_clock")
            else None
        ),
        grounded_claims=tuple(
            GroundedClaim(
                quantity=Quantity(claim["quantity"]),
                root_object_id=claim["root_object_id"],
                expected=claim["expected"],
                tolerance=claim["tolerance"],
                verified_by=claim["verified_by"],
                induced_value=claim.get("induced_value"),
            )
            for claim in scope_raw.get("grounded_claims", ())
        ),
    )
    injection_raw = payload.get("injection")
    injection = (
        Injection(
            channel=Channel(injection_raw["channel"]),
            payload=injection_raw["payload"],
            marker=injection_raw["marker"],
            tool_name=injection_raw.get("tool_name"),
            field_path=injection_raw.get("field_path"),
        )
        if injection_raw
        else None
    )
    return Attack(
        attack_class=AttackClass(payload["attack_class"]),
        target_name=payload["target"],
        user_turn=payload["user_turn"],
        licensed_scope=scope,
        injection=injection,
        parent_id=payload.get("parent_id"),
        operator=payload.get("operator"),
        origin=payload.get("origin", "search"),
        notes=payload.get("notes", ""),
    )


def _verdict_json(verdict: Verdict) -> dict[str, Any]:
    return {
        "succeeded": verdict.succeeded,
        "criteria": list(verdict.criteria_fired),
        "progress": verdict.progress,
        "cost_usd": round(verdict.cost_usd, 6),
        "hypothetical": verdict.hypothetical,
        "defences": list(verdict.defences),
        "blocked_calls": verdict.blocked_calls,
        "refused": verdict.refused,
        "findings": [
            {
                "criterion": finding.criterion.value,
                "detail": finding.detail,
                "object_id": finding.object_id,
                "tool_call_index": finding.tool_call_index,
            }
            for finding in verdict.findings
        ],
        "suppressed_by_control": [
            {"criterion": finding.criterion.value, "detail": finding.detail}
            for finding in verdict.suppressed
        ],
    }


class RunLog:
    """One search run's directory: manifest, episode lines, transcripts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.transcripts = root / "transcripts"
        self.episodes_path = root / "episodes.jsonl"
        self.manifest_path = root / "manifest.json"

    def start(self, manifest: Manifest) -> None:
        self.transcripts.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            self.manifest_path.write_text(json.dumps(asdict(manifest), indent=2) + "\n")

    def append(self, result: EpisodeResult, verdict: Verdict) -> None:
        transcript_name = f"{result.attack.attack_id}.json"
        result.transcript.write(self.transcripts / transcript_name)
        record = {
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "attack": _attack_json(result.attack),
            "verdict": _verdict_json(verdict),
            "answer": result.answer,
            "tool_calls": [
                {"name": call.name, "arguments": call.arguments, "is_error": call.is_error}
                for call in result.transcript.tool_calls
            ],
            "changes": [
                {
                    "object_id": change.object_id,
                    "action": change.action,
                    "irreversible": change.irreversible,
                }
                for change in result.changes
            ],
            "blocked": [
                {"defence": block.defence, "tool": block.tool_name, "reason": block.reason}
                for block in result.blocked
            ],
            "transcript": f"transcripts/{transcript_name}",
        }
        with self.episodes_path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.episodes_path.exists():
            return
        with self.episodes_path.open() as handle:
            for line in handle:
                if line.strip():
                    yield json.loads(line)

    def seen_attack_ids(self) -> set[str]:
        return {record["attack"]["attack_id"] for record in self.records()}

    def spent_usd(self) -> float:
        return sum(float(record["verdict"]["cost_usd"]) for record in self.records())
