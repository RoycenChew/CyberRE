# ADR-014: The Approval Gateway is a core domain service

## Status
Accepted. Diverges from Phase 3 of the original design document.

## Context
An earlier plan implemented human approval as a LangGraph interrupt, and the
design document placed the approval workflow in Phase 3, after the capabilities
it governs. Both put the gate in the wrong place: a gate that arrives after the
dangerous operations, or that lives inside a replaceable workflow engine, is not
a gate.

## Decision
`ApprovalGateway` is a core domain service, introduced at M4 with the policy
engine. The graph calls it. Replacing the workflow runtime cannot remove it. The
dynamic-analysis consumer arrives at M13; the gate exists long before.

## Consequences
Approval is enforceable from the first risky capability onward, and it survives
a runtime swap.
