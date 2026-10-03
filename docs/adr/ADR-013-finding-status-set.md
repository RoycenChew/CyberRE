# ADR-013: Finding statuses carry the reason for a negative result

## Status
Accepted. Diverges from section 15.1 of the original design document.

## Context
The design document specifies Confirmed / Probable / Suspicious / Informational
/ Rejected / Insufficient Evidence. That set cannot distinguish an unreachable
vulnerability, an inapplicable CVE and a genuinely under-investigated case: all
three collapse into "Insufficient Evidence", discarding the reason, which is the
most actionable part of a negative result.

## Decision
`NOT_ENOUGH_EVIDENCE`, `UNVALIDATED`, `CONTRADICTED`, `NOT_APPLICABLE`,
`UNREACHABLE`, `NEEDS_REVIEW`, `VALIDATED`. Severity is an independent optional
field and is `None` for outcomes that do not warrant one.

## Consequences
Uncertainty is never coerced into a severity (invariant 10). A report can say
"this code path is not reachable" instead of "insufficient evidence", which is
the difference between a useful answer and a shrug.
