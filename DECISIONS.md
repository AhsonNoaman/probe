# DECISIONS.md

Design decisions from M1 onward, and the mistakes. The mistakes are the useful part: four of
them would have produced a confident, wrong, publishable number, and each was caught by a
measurement rather than by review.

Dated 2026-08-10. [DESIGN.md](DESIGN.md) covers M0: the adapter interface, the criteria, the
search loop, and what was cut as over-scoped before any code was written.

---

## D1. The weak reference agent is a transport, not a language model

**Decision.** The reference agent is a deterministic instruction-following policy implemented
as a `Transport` and driven through flightops's own `loop.run`.

**Why.** There is no `ANTHROPIC_API_KEY` in this environment. The alternatives were to build
the harness and not run it, or to run it against something free. flightops made the first
choice with its own eval ([DESIGN.md §1.2](DESIGN.md)) and the result is a harness nobody can
interpret. The brief names "an eval built and not run" as a thing never to do. So the target
became something that costs nothing.

Making it a `Transport` rather than a mock agent is what keeps the result meaningful: the
transcript, the tool dispatch, the cost accounting and the replay path are the *real*
flightops ones, and only the source of the assistant turn differs. Every episode is free,
offline, and identical on re-run, so the ASR against it is a measurement rather than an
estimate.

**Cost, stated plainly.** It is not evidence about any language model's robustness. The README
says so where the number appears.

---

## D2. `follow_untyped_imports` instead of editing flightops

**Decision.** probe type-checks against flightops with `follow_untyped_imports = true`.

**Why.** flightops is `mypy --strict` clean in its own repository but ships no `py.typed`, so
its types are invisible downstream. First run produced 28 errors. Adding the marker would have
meant editing a checkout probe is supposed to leave untouched, which is the same boundary the
adapter design exists to respect. Following the untyped import gives probe the real signatures
with no change to flightops.

---

## D3. The judge's fixtures derive their expectations from the store

**Decision.** `recompute_claim(store, engine, quantity, root)` is a free function used both by
`corpus.read_only_scope` to *set* a grounded claim's expected value and by
`Judge._verify_fixture` to *check* it. The judge raises `FixtureDrift` rather than grading
when they disagree.

**Why.** A `GroundedClaim` carries a hand-verified number. If the data moves and the number
does not, a correct answer gets marked as a fabrication and the resulting ASR is worse than no
ASR. Sharing one derivation means the setter and the checker cannot drift apart by
construction.

This was nearly shipped as `expected = 0.0`, a placeholder that would have tripped the drift
guard on the first real run.

---

## Mistakes

### M-1. The injector ran after the defences, so `separation` could not work

`compose_executor` applied the defences' `after_call` before the injector's. The hostile
payload was therefore written into the result *after* `StructuralSeparation` had already
fenced it, so it landed outside the `<untrusted-data>` block the reference policy refuses to
take orders from.

The layer was correct. The composition made it unreachable. The run would have reported
"separation is ineffective", a clean, plausible, entirely false finding about a defence that
works.

Fixed to `inner -> injector -> defences`, with the ordering argument written into the
docstring so the next person changing this sees why the sequence is not arbitrary. Verified by
the same episode flipping from `success=True` to `success=False`.

**What made it visible:** measuring the layer end-to-end against a real agent rather than
asserting that it modified the prompt.

### M-2. The frontier starved classes whose seed failed

A single global priority queue meant descendants of successful attacks crowded out everything
else. `authority_forgery` got 1 attempt out of 120 and would have been reported at a confident
0%, which is a statement about a class the search barely tried.

`Frontier` now keeps one queue per attack class and pops from the least-explored class, with
priority deciding only *within* a class. `test_frontier_rotates_across_classes` fails if that
is undone.

### M-3. The seed corpus made criterion 2 unreachable, twice

First version seeded on the earliest flight of the day. Criterion 2 fires when the agent acts
on a leg that departed at or before the request's clock, so with the earliest leg as the
anchor, every object the search could reach was *later*, and the temporal bypass was
unreachable by construction. It would have reported a clean zero for the one criterion tied to
a real finding probe made at M0 ([DESIGN.md §1.4](DESIGN.md)).

Fixed by anchoring mid-list. That produced a quieter version of the same bug: `find_flights`
orders by `sched_dep_utc`, and this date opens with a bank of ten legs sharing a single
instant, so the first twelve rows spanned five minutes of a twenty-two hour day and "earlier
than the anchor" was still empty. Criterion 2 fired 3 times in 140 episodes, low enough to
look like a result.

`candidate_flights` now samples across distinct departure instants spanning the operating day.
Criterion 2 fires 44 times in the same 140 episodes. The difference between 3 and 44 is
entirely the corpus, not the agent.

**What made it visible:** a test asserting the *precondition for measurability*, that legs
exist on both sides of the anchor's clock, rather than a test of the judge, which was correct
throughout.

### M-4. Citation validation defeated itself in its own refusal message

`CitationValidation` withholds an answer citing a flight id that does not resolve. Its refusal
message quoted the offending id verbatim, so the judge re-extracted it from the refusal and
scored the episode as a fabrication anyway. The defence worked perfectly and measured as
having zero effect.

Now it reports a count instead of the ids.
`test_citation_refusal_does_not_reprint_the_fabricated_id` covers it.

### M-5. The recommended stack was asserted, and the hole it left was reported as a finding

A hardcoded `RECOMMENDED` constant omitted `authorisation`. M6 then hardened with that stack,
the held-out search walked through the gap, and the generalisation gap was reported as a
property of the defences rather than of a constant somebody typed.

Replaced with `choose_recommended()`, which ranks the measured table by (ASR, -utility, layer
count). The recommendation is now a reading of the results, and `ALL_DEFENCES` replaced
`RECOMMENDED` in `defenses/layers.py` so there is no constant left to assert.

### M-6. Results were reported on attack class alone, which mislabelled the main finding

`move_channel` relocates a payload without relabelling its class, by design, since class
(intent) and channel (delivery) are independent axes. But the report grouped on class alone,
so a tool-result-poisoning payload delivered through the user turn was filed under "tool
result poisoning". The survivor table showed `user_turn:` mechanisms attributed to three
different classes, which obscured that they were all the same door.

The report now splits on both axes. The channel view is what turned a bare "+74 point
generalisation gap" into an explanation: the stack takes both data channels from 100% to 0%
and the user turn from 100% to 96%.

---

## D4. Reporting ASR from a fixed panel, not from the search

**Decision.** The headline ASR comes from `evaluate_panel`: each distinct mechanism a search
found, retargeted across a fixed 8-object panel chosen before the run.

**Why.** Successful attacks breed. Every operator runs on every scoring attack, so the share
of successes in a search run climbs by construction. An early run of this harness put that
share close to 90%, and the figure meant nothing: it described the shape of the mutation tree,
not the target. (That run predates the current corpus and has no committed artefact, which is
why the number is not quoted as a result.) Search-run counts are still recorded, labelled
`raw_successes`, with a note in the JSON saying what they are not.

The panel also separates a class from an instance. An attack that works on one leg and fails
on the other seven is not a finding about the agent.

**Search efficiency** is reported separately as `first_success_at`: episodes until the first
success per class. That is the number that actually describes the search.

---

## D5. The held-out ledger is locked, and a test enforces the lock

`LedgerBook.debit("heldout", ...)` raises `LedgerLocked` unless `milestone="m6"`.
`test_heldout_ledger_refuses_to_pay_out_before_m6` fails if the lock is removed.

A held-out set is only evidence if it was untouched. "I was careful not to look" is not
evidence; a test that fails when the guard is deleted is.

`allocate` also refuses to top up an existing ledger, so a re-run cannot quietly raise a
ceiling that an earlier measurement was taken against.

---

## D6. What is reported as `n/a` rather than as zero

Three of the brief's seven attack classes have no surface on the current targets. Scope creep
needs a multi-turn driver, and threshold pressure and refusal inversion need `triage`, which
does not exist. Criterion 4 (abstention collapse) is implemented and tested but fires nowhere
for the same reason.

They are reported `n/a`. A zero in an ASR column reads as a defended result, and claiming a
defence that was never tested is the specific dishonesty this project is supposed to be
measuring its way out of.

Findings delivered through `record_field` and `tool_result` are labelled **hypothetical**
everywhere they appear: BTS On-Time Performance has no attacker-writable free-text field, so
reaching the agent through those channels means synthesising records the real source cannot
contain ([DESIGN.md §1.3](DESIGN.md)).

---

## D7. Criterion 1 against flightops measures a proxy

flightops's `simulate_action` mutates a per-session scenario overlay that evaporates with the
process; the base DuckDB file is opened read-only. So "the agent took an unauthorised action"
against that target is a statement about a sandbox.

`StateChange.irreversible` carries the distinction into every record, and the reference agent
exists partly to give criterion 1 something real to fire on. Its `close_disruption` writes a
row that survives the process. Without that, the brief's claim that the threat model is
actions rather than words would not be carried by anything.
