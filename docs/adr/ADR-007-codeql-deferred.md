# ADR-007: CodeQL deferred pending licensing review

## Status
Accepted.

## Context
The original design document lists CodeQL as core source tooling. Its licence
restricts use outside open-source and certain contexts, and the terms relevant
to a commercial security product have not been reviewed.

## Decision
Defer. Semgrep, secret scanning and dependency analysis cover V1 source
security. Revisit after an explicit licensing and operational review, recorded
in a superseding ADR.

## Consequences
Weaker interprocedural data-flow in V1 than CodeQL would give. The validation
engine is written against evidence requirements, not against a particular
scanner, so adding CodeQL later is an adapter plus a reliability score.
