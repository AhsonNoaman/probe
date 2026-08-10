"""Budget ledgers, and the reservation that makes the held-out test honest.

DESIGN.md section 6.4. The brief forbids "a search run without recorded cost" and sets no
figure, so the enforcement lives here rather than in a resolution to be careful.

Three rules, all mechanical:

1. A run draws from exactly one named ledger and stops when it is empty. It never borrows.
2. `heldout` is allocated at M3 and refuses to pay out before M6. The lock is on the ledger, not
   on the operator's discipline: the whole value of a held-out set is that it was untouched, and
   an honour system is not evidence of that.
3. Cost is debited before the next episode is proposed, so a crash cannot lose spend.

`allocated_at` is recorded so a reader can see the held-out allocation predates the hardening
work rather than having been topped up afterwards.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

HELD_OUT = "heldout"
HELD_OUT_MILESTONE = "m6"


class BudgetExhausted(RuntimeError):
    """The ledger ran out. Carries what was asked for and what was left."""


class LedgerLocked(RuntimeError):
    """A reserved ledger was drawn on before its milestone."""


@dataclass
class Ledger:
    name: str
    allocated_usd: float
    spent_usd: float = 0.0
    episodes: int = 0
    allocated_at: str = ""

    @property
    def remaining_usd(self) -> float:
        return self.allocated_usd - self.spent_usd


@dataclass
class LedgerBook:
    """Every ledger for a project, persisted so allocation survives a restart."""

    path: Path
    ledgers: dict[str, Ledger] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> LedgerBook:
        if not path.exists():
            return cls(path=path)
        raw = json.loads(path.read_text())
        return cls(
            path=path,
            ledgers={name: Ledger(**values) for name, values in raw.items()},
        )

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {name: asdict(ledger) for name, ledger in sorted(self.ledgers.items())}, indent=2
            )
            + "\n"
        )

    def allocate(self, name: str, usd: float) -> Ledger:
        """Create a ledger, or return the existing one unchanged.

        Deliberately not a top-up. Re-running allocation must not quietly raise a ceiling that a
        previous run was measured against, and `heldout` in particular has to be provably the
        same allocation it was given at M3.
        """
        existing = self.ledgers.get(name)
        if existing is not None:
            return existing
        created = Ledger(
            name=name,
            allocated_usd=usd,
            allocated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        self.ledgers[name] = created
        self.save()
        return created

    def check(self, name: str, milestone: str) -> Ledger:
        ledger = self.ledgers.get(name)
        if ledger is None:
            raise KeyError(f"no ledger named {name!r}; allocate it first")
        if name == HELD_OUT and milestone != HELD_OUT_MILESTONE:
            raise LedgerLocked(
                f"the {HELD_OUT!r} ledger was reserved on {ledger.allocated_at} and only pays out "
                f"at milestone {HELD_OUT_MILESTONE}; this run declared {milestone!r}"
            )
        return ledger

    def debit(self, name: str, usd: float, milestone: str) -> Ledger:
        ledger = self.check(name, milestone)
        if usd > ledger.remaining_usd:
            raise BudgetExhausted(
                f"ledger {name!r} has ${ledger.remaining_usd:.4f} left and this episode cost "
                f"${usd:.4f}"
            )
        ledger.spent_usd += usd
        ledger.episodes += 1
        self.save()
        return ledger

    def affordable(self, name: str, estimate: float, milestone: str) -> bool:
        return self.check(name, milestone).remaining_usd >= estimate
