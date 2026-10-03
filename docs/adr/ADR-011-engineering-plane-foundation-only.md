# ADR-011: Engineering plane ships contracts only in V1

## Status
Accepted.

## Context
A full coding-agent layer - router, provider adapters, worktree isolation,
cross-agent review, consensus - is a large body of work that builds nothing the
investigation plane needs.

## Decision
V1 ships `CodingAgentProvider`, the capability-discovery enum, the handoff
schema, the audit record, and the `AgentClaim` evidence type with its
constraint. No router, no vendor adapters, no orchestration. The full design
stays documented so V1.1 implements against a known target.

## Consequences
Coding agents contribute through the repository and through `AGENTS.md` rather
than through an API. `AgentClaim` is the only runtime surface, and it cannot
satisfy a validation requirement (invariant 2).
