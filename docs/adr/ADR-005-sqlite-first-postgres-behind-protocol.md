# ADR-005: SQLite for V1, PostgreSQL behind the protocol

## Status
Accepted. Supersedes Phase 2 of the original design document, which introduced
PostgreSQL earlier.

## Context
PostgreSQL is the production target. It is also a service to install, run and
keep running, which is friction during the phase when the data model is still
moving.

## Decision
`EvidenceStore`, `InvestigationStore`, `ObjectStore` and `KnowledgeStore` are
protocols. V1 implements SQLite plus a filesystem object store. PostgreSQL is
implemented at M16 against the identical contract suite. Core writes no SQL.

## Consequences
Zero-setup development. The swap is credible because both implementations are
held to one shared test suite, which is also how invariant 17 is proved.
