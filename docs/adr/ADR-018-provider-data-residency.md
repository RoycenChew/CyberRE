# ADR-018: Model provider data residency; subscription bridges are dev-only

## Status
Accepted.

## Context
Evidence packets contain source code and decompiled functions. Where that data
goes is a procurement question for any enterprise customer, not an
implementation detail. Separately, subscription bridges (OpenCode and similar)
can expose a coding-agent subscription as an OpenAI-compatible endpoint, which
is technically usable and tempting.

## Decision
Provider choice is configuration. `SECURITY.md` states, per provider, whether
data leaves the host. Local runtimes (Ollama, vLLM) are the zero-egress option
and are supported through the same adapter.

A subscription bridge is a valid local development convenience and is **not** a
supported deployment target: it shares rate limits with interactive use, depends
on undocumented internals with no stability guarantee, falls outside the
interactive-use licensing of those subscriptions, and would make CyberRE depend
on a coding agent, violating invariants 12-14.

## Consequences
Enterprise deployments can be configured for zero egress. The compiler packet
budget is sized partly so that a local model remains viable, to be validated at
M9.
