# ADR-008: Analysis profiles are declarative and never authoritative

## Status
Accepted.

## Context
Profiles (BINARY_RE, MALWARE_ANALYSIS, and the rest) need to steer capability
selection, evidence requirements, knowledge sources and depth. The hazard is
that a profile becomes either an autonomous agent or, worse, a way to grant
itself permissions the global policy withholds - MALWARE_ANALYSIS wanting
sandbox network access is the obvious case.

## Decision
A profile is YAML validated into a Pydantic model. `preferred_capabilities` is a
planner prior. `forbidden_capabilities` subtracts. `policy_requirements` may
request; it can never grant. `approval_requirements` may add gates, never remove
them. Effective permissions are an intersection (ADR-015).

## Consequences
Adding a profile is a data change. Invariant 3 is testable: a profile asking for
more than global policy allows yields the intersection, and a test asserts it.
