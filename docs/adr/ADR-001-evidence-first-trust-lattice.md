# ADR-001: Evidence-first with an explicit trust lattice

## Status
Accepted.

## Context
The platform must not let a plausible-sounding model statement become a security
finding. An earlier draft expressed this as a property of the evidence schema -
a single `is_unverified` flag on agent claims - and relied on prose for the
rest. Prose is not a control: nothing structurally prevented an interpretation
from being promoted directly to a finding.

## Decision
Every object carries one of eight trust levels (`RAW_ARTEFACT`, `TOOL_OUTPUT`,
`AGENT_CLAIM`, `NORMALIZED_EVIDENCE`, `DERIVED_EVIDENCE`, `INTERPRETATION`,
`HYPOTHESIS`, `VALIDATED_FINDING`). Promotion happens at one chokepoint per
transition. Illegal transitions raise. No level carries instruction authority.

See `docs/TRUST_MODEL.md` for the table and the blocked transitions.

## Consequences
Invariants 1, 2, 5, 7 and 8 become enforceable by a single mechanism and are
testable. The cost is one extra field on every domain object and a promotion
function that every producer must go through - deliberate friction at exactly
the points where silent promotion would be a security defect.
