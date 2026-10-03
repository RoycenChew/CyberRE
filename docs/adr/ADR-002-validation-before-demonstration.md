# ADR-002: Validation precedes the first demonstration

## Status
Accepted. Supersedes the phase ordering in the original design document.

## Context
Both the original design document (Phase 1 MVP) and an early milestone plan put
an end-to-end demonstration before the validation engine and adversarial
reviewer. That creates a window in which the system produces things that look
like findings while nothing exists that is able to reject one. A demonstration
given in that window overstates what the system can do, and overstatement is the
specific failure mode this architecture exists to prevent.

## Decision
Validation (M10) and reviewer plus confidence (M11) ship before the dual
vertical slice (M12). Before M10 the system may produce `CandidateFinding` only.
`CandidateFinding` is a distinct type that the report generator cannot render,
so the demonstration path is structurally unavailable rather than merely
discouraged.

## Consequences
Visible progress arrives later. In exchange, the first thing anyone sees is a
finding that survived an engine designed to reject it.
