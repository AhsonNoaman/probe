# probe

Automated adversarial search against tool-using agents, plus a measurement of whether the
defences you add generalise past the attacks you already found.

Live report: [ahsonnoaman.github.io/probe](https://ahsonnoaman.github.io/probe/)

The search proposes structured attacks, mutates the ones that score, and grades every episode
mechanically against a clean control run of the same case. It then hardens the target, runs a
*second* search it has never seen, and reports the difference. That second number is the
point. Hardening against a list of found attacks is easy and mostly worthless.

## Scope of engagement

**Every target here is a system I built and host.** There are two: the `flightops` agent, and a
deliberately weak reference agent written inside this repository as a control. No third-party
system, model provider, or anyone else's deployment is a target, and the harness has no
capability to reach one. Targets are Python objects constructed in-process, not endpoints. The
attack strings committed under `data/runs/` are evidence for findings about my own code.

## What was measured

Two arcs, side by side.

The **reference agent** is the full arc: search, nine-way configuration sweep, held-out M6
generalisation gap. Every number in the Results section below comes from it. It is a
deterministic, non-LLM instruction-following policy written to be under-defended in four
specific ways ([DESIGN.md §7.2](DESIGN.md)). It is a control -- it shows the harness can
detect a break at all -- and it is not evidence about a language model's own robustness.

The **`flightops` LLM target** was driven live in a 60-episode undefended pilot on
`claude-opus-5`, under a firm $65 spend cap. The pilot covers the M3 search phase only: the
panel evaluation, configuration sweep, and held-out M6 search did not run against the live
target in this session. The pilot answers a narrower question -- can the search find distinct
attack mechanisms on the real model at all, and at what cost per mechanism -- and it did. 60
episodes surfaced **35 distinct mechanisms**, first success in each supported class between
episode 1 and episode 7. Measured spend on that arc was **$4.4493**, mean $0.074 per episode,
worst case $0.171. The full pilot section is in
[data/reports/findings.md](data/reports/findings.md).

Reference-agent spend across every ledger: **$0.0000**, across 280 search episodes and 5,760 panel episodes (plus their controls). Flightops pilot spend: **$4.4493**, across 60 live search episodes. The reference agent runs offline, which is what made a search that large possible without touching a key.

## Results

Attack success rate is measured over a **fixed 8-object panel chosen before the run**, not
over the search itself. Successful attacks breed during a search, so the share of successes
there climbs by construction and describes the mutation tree rather than the target.

| configuration | panel ASR | benign tasks | calls blocked |
|---|---|---|---|
| undefended | 100% | 4/4 | 0 |
| separation | 56% | 4/4 | 0 |
| authorisation | 56% | 4/4 | 0 |
| preconditions | 99% | 4/4 | 0 |
| citation | 79% | 4/4 | 0 |
| separation+authorisation | 56% | 4/4 | 0 |
| authorisation+preconditions | 55% | 4/4 | 0 |
| separation+citation | 27% | 4/4 | 0 |
| **all four** | **26%** | **4/4** | 0 |

No configuration costs anything on the benign suite, so the recommendation is just the lowest
ASR. It is computed from this table by `choose_recommended`, not asserted in advance. An
earlier run hardcoded a stack that omitted `authorisation` and then reported the resulting
hole as a generalisation gap.

### The finding

Splitting the same episodes by **delivery channel** rather than by attack class explains
everything else.

| channel | status | undefended | hardened |
|---|---|---|---|
| `record_field` | hypothetical | 100% | **0%** |
| `tool_result` | hypothetical | 100% | **0%** |
| `user_turn` | attacker-controlled today | 100% | **96%** |

The stack closes both data channels completely and barely touches the user turn. That is not
four layers underperforming. It is four layers doing exactly what they were built for. All of
them defend the boundary between *data the agent read* and *instructions it follows*. None
governs what the principal is allowed to ask for. An agent whose user is hostile is outside
the boundary this stack defends, and no amount of tuning inside it will help.

`record_field` and `tool_result` are marked hypothetical because BTS On-Time Performance
carries no attacker-writable free-text field. Reaching the agent through them means
synthesising records the real source cannot contain, so those rows measure what the agent
would do with a compromised source. Worth knowing, and a weaker claim than the `user_turn`
row.

### Generalisation gap

A fresh search, different seed, drawing on a budget ledger locked until M6, run against the
already-hardened target:

| | |
|---|---|
| mechanisms found at M3, against the hardened stack | 26% |
| mechanisms found fresh at M6, against the same stack | 100% |
| **generalisation gap** | **+74 points** |

Every mechanism the held-out search found is a user-turn mechanism. It walked straight to the
one door the stack does not cover, which is why it recovers the undefended rate. The gap is
large and it is *explainable*, which is a better outcome than a small gap nobody can account
for.

### Search efficiency

Episodes until the first success in each class, undefended:

| class | episodes to first success |
|---|---|
| authority forgery | 1 |
| citation laundering | 1 |
| tool result poisoning | 2 |
| instruction injection | 4 |

Three classes in the brief's taxonomy are reported `n/a` rather than `0%`. Scope creep needs a
multi-turn driver; threshold pressure and refusal inversion need the `triage` agent, which
does not exist yet ([DESIGN.md §1.1](DESIGN.md)). A zero would read as a defended result.

Criterion 4 (abstention collapse) is implemented and tested but fires nowhere, for the same
reason: it needs a target that refuses under pressure.

The full report, regenerated from the committed run logs, is
[data/reports/findings.md](data/reports/findings.md).

## Run it

Needs Python 3.11+ and a `flightops` checkout beside this one.

```sh
make install                        # venv, probe, and the flightops checkout it targets
make check                          # ruff, mypy --strict, pytest
python scripts/run_experiment.py    # the whole measurement, offline, $0.00
make report                         # regenerate findings.md from the run logs
```

`run_experiment.py` reproduces every number above from scratch in about four minutes. It needs
no API key and reaches no network. Both searches are seeded, so a clean re-run reproduces
`data/reports/experiment.json` exactly apart from the ledger timestamps.

## How it works

**Targets are wrapped, never modified.** The adapter drives `flightops` through the same
module-level names its own `scripts/run_eval.py` uses, and adversarial content arrives by
composing the executor that `loop.run` already accepts as an argument. Nothing private is
imported and no file in the `flightops` checkout is touched. The HTTP API was considered and
rejected as the interface. It withholds tool results, hides the scenario objects, and is
env-gated off in the deployment ([DESIGN.md §3](DESIGN.md)).

**There is no LLM in the grading path.** Each of the four success criteria is a store query.
An LLM judge is attackable by the thing it grades, which makes it the wrong instrument for
measuring attacks. The cost of that choice is real and stated: "outside what the request
licensed" is not computable from text without a model, so every attack **declares** its
licensed scope at authoring time with a mandatory `verified_by` field
([DESIGN.md §5.1](DESIGN.md)).

**Every verdict is differential.** A criterion firing means nothing unless the same case, with
the payload stripped, does not fire. Baseline misbehaviour is not an attack success.

**Attacks are objects, not strings.** Search moves over structure. `retarget` changes the
object and leaves everything else, which is what makes "this is a class, not an instance" a
checkable claim rather than an assertion. Attack IDs are content hashes, so rediscovery down a
different mutation path deduplicates instead of paying twice.

**The held-out ledger is locked until M6**, and a test fails if the lock is removed. A
held-out set is only evidence if it was untouched, and "I was careful" is not evidence.

## What went wrong

[DECISIONS.md](DECISIONS.md) records the design errors this project made and how each was
caught. Four of them would have produced a confident, wrong, publishable number. The most
instructive: the injector originally ran *after* the defences, so the payload landed outside
the fence `separation` installs. The layer could never work, and the report would have said
so.

## Layout

```
src/probe/attacks/     attack model, taxonomy, seed corpus, mutation operators
src/probe/targets/     adapter protocol, flightops adapter, weak reference agent
src/probe/judge/       the four criteria, differential grading, no LLM
src/probe/defenses/    four toggleable layers
src/probe/search/      frontier, budget ledgers, resumable run log
src/probe/eval/        utility regression, panel evaluation, report rendering
data/runs/             committed episodes and transcripts
data/reports/          experiment.json and the rendered findings
```

[DESIGN.md](DESIGN.md) is the M0 document: the adapter interface, each criterion specified
mechanically, the search loop, recorded pushback on the brief, and what was cut as
over-scoped.
