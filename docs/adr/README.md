# Architecture Decision Records

One decision per file. Status is Accepted unless stated. A decision is changed
by writing a new ADR that supersedes the old one, never by editing history.

| ADR | Decision |
|---|---|
| [001](ADR-001-evidence-first-trust-lattice.md) | Evidence-first with an explicit trust lattice |
| [002](ADR-002-validation-before-demonstration.md) | Validation precedes the first demonstration |
| [003](ADR-003-langgraph-as-adapter.md) | LangGraph is an adapter, not the domain |
| [004](ADR-004-ghidra-headless-subprocess.md) | Ghidra via headless subprocess; three test tiers |
| [005](ADR-005-sqlite-first-postgres-behind-protocol.md) | SQLite for V1, PostgreSQL behind the protocol |
| [006](ADR-006-model-provider.md) | OpenAI-compatible provider first; provider by config |
| [007](ADR-007-codeql-deferred.md) | CodeQL deferred pending licensing review |
| [008](ADR-008-profiles-declarative.md) | Profiles are declarative and never authoritative |
| [009](ADR-009-confidence-deterministic.md) | Confidence is deterministic and completeness-capped |
| [010](ADR-010-docker-sandbox-development-grade.md) | Docker sandbox is development-grade, stated plainly |
| [011](ADR-011-engineering-plane-foundation-only.md) | Engineering plane: contracts only in V1 |
| [012](ADR-012-mcp-optional.md) | MCP is optional and absent from V1 |
| [013](ADR-013-finding-status-set.md) | Finding statuses carry the reason for a negative result |
| [014](ADR-014-approval-gateway-in-core.md) | The Approval Gateway lives in core |
| [015](ADR-015-five-way-permission-intersection.md) | Effective permissions are a five-way intersection |
| [016](ADR-016-independence-key-stored.md) | Evidence independence is a stored field |
| [017](ADR-017-knowledge-provenance.md) | Knowledge records carry provenance and applicability |
| [018](ADR-018-provider-data-residency.md) | Model provider data residency; bridges are dev-only |
| [019](ADR-019-graph-in-stdlib.md) | The evidence graph is implemented in the standard library |
| [020](ADR-020-storage-without-an-orm.md) | Storage uses the standard library, not an ORM |
| [021](ADR-021-profiles-in-toml.md) | Profiles are TOML, parsed with the standard library |
| [022](ADR-022-workflow-runtime.md) | The investigation runtime is a plain loop; LangGraph stays optional (proposed) |
| [023](ADR-023-ghidra-script-in-java.md) | The Ghidra export script is Java |
| [024](ADR-024-sandbox-isolation-grades.md) | Sandboxes are graded, and the grade gates detonation |
| [025](ADR-025-evaluation-benchmark.md) | Confidence weights are measured, not argued |

ADRs 013-017 record divergences from the original design document in
[`../prompts/`](../prompts/), per the requirement that conflicts be documented
rather than silently resolved.
