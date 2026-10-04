# Confidence

Every number CyberRE attaches to a finding is computed from evidence and
validation. A model never emits one (ADR-009): asked for a confidence, a
model produces one that tracks how persuasive its own prose reads rather
than how much evidence exists.

## The formula

```
base  = sum(weight_i x factor_i)                      factors below
base  = max(floor, base - penalty x contradictions)   if contradicted

confidence = min(base, completeness) x reviewer x validation_gate
```

Two multiplications carry the weight.

**`min(base, completeness)`** caps confidence at how much of the requirement
set was actually established. A finding with two of five requirements cannot
score above 0.4 however compelling the reasoning.

**`validation_gate`** is 1.0 only for a validated finding and 0.0 otherwise,
so an unvalidated hypothesis scores exactly zero. That is invariant 1 as
arithmetic rather than as a rule someone has to remember.

**`reviewer`** is drawn from `{1.0, 0.5, 0.0}`. There is no value above 1.0
anywhere in the mapping, so invariant 9 - the reviewer cannot strengthen a
finding - holds by the shape of the type.

## Factors

| Factor | Weight | What it measures |
|---|---|---|
| `evidence_completeness` | 0.30 | Satisfied requirements over total. Dominant, because a finding missing half its requirements is half a finding. |
| `evidence_independence` | 0.20 | Distinct observations over records used. One analysis establishing four facts scores lower than four analyses agreeing. |
| `tool_reliability` | 0.15 | Mean reliability of the producing tools, from the registry. A property of the tool, never a per-run judgement. |
| `source_corroboration` | 0.10 | Independent sources agreeing, saturating at three. The third adds much less than the second. |
| `reachability_established` | 0.15 | Binary. Either a path from an entry point was shown or it was not; partial credit here would paper over the most common false-positive cause. |
| `provenance_quality` | 0.10 | Whether the evidence can be re-examined later - tool version, ruleset version, raw output reference. |

Weights live in `config/confidence.toml`, are normalised to sum to 1, and are
versioned. A finding scored under `v1` can be re-examined when `v2` disagrees,
because the version is stored on the breakdown.

They are a starting point, not a result. Tuning against the benchmark is M14
work, and the version should be bumped when they change.

## Status resolution

Order is deliberately pessimistic:

1. A **rejecting** reviewer overrides validation outright → `CONTRADICTED`.
2. A reviewer **requesting more evidence** turns a validated finding into
   `NOT_ENOUGH_EVIDENCE`. It has not been disproven, but it has not survived
   review either.
3. A **downgrade**, or a score below the threshold → `NEEDS_REVIEW`.
4. Only then → `VALIDATED`.

A non-validated outcome keeps its own status throughout. `UNREACHABLE` and
`NOT_APPLICABLE` are answers, and review does not improve them.

Severity is attached only to a validated finding. Every other status carries
its reason and no severity, because uncertainty is not an impact rating
(invariant 10).

## What is deliberately not here

No model-supplied number, at any point. No severity imported from a scanner -
those are recorded and never adopted. No way for an absent or failed reviewer
to read as approval: a review that could not run returns
`REQUEST_MORE_EVIDENCE` with multiplier 0.0, because treating a missing
reviewer as an approving one would quietly remove the gate.
