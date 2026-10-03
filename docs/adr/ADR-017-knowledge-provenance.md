# ADR-017: Knowledge records carry provenance, version and applicability

## Status
Accepted.

## Context
Knowledge-derived evidence ("VirtualAllocEx is an injection primitive") would
otherwise have weaker provenance than tool-derived evidence - a silent asymmetry
in an architecture whose premise is that everything is traceable.

## Decision
Every knowledge record carries `id`, `version`, `source_ref`, `confidence` and
`applicability` conditions, and produces evidence with provenance on the same
terms as a tool. Structured knowledge is deterministic lookup. Semantic
retrieval is separate and may never satisfy a validation requirement.

The seed set is deliberately small and high quality. Schema matters more than
volume; expansion is a data change.

## Consequences
Invariant 6 holds for knowledge as well as for tools. A finding that depended on
a knowledge claim can be re-examined when that claim is revised.
