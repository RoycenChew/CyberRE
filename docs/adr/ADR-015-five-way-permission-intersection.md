# ADR-015: Effective permissions are a five-way intersection

## Status
Accepted.

## Context
An earlier draft intersected global policy with profile policy only. That cannot
express a development-versus-production distinction, per-capability
constraints, or per-user authorisation, all of which an enterprise deployment
needs.

## Decision
`effective = global AND environment AND profile AND capability AND user`.
Intersection only; no term can widen another. Computed by one function, so there
is a single place to audit.

## Consequences
Invariants 3 and 4 hold by construction. Debugging a denial means reading five
inputs, so the policy decision record names which term denied it.
