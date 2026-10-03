# ADR-009: Confidence is deterministic and capped by completeness

## Status
Accepted.

## Context
A model asked for a confidence number will produce one, fluently, and it will
correlate with how convincing the prose is rather than with how much evidence
exists.

## Decision
Confidence is computed in `core/findings` from named factors with configurable
weights in `config/confidence.yaml`, then
`min(base, completeness) * reviewer_multiplier * validation_gate`, where
`validation_gate` is 1.0 only for `VALIDATED` and `reviewer_multiplier` is drawn
from the set {1.0, 0.5, 0.0}. The model emits no numbers.

## Consequences
Two invariants become arithmetic rather than behavioural: an unvalidated
hypothesis scores exactly zero (invariant 1), and the reviewer has no value
available that could raise a score (invariant 9). Weights need tuning against
the benchmark; that is a data change, and it is auditable.
