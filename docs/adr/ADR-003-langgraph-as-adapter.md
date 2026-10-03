# ADR-003: LangGraph is an adapter, not the domain

## Status
Accepted.

## Context
LangGraph gives us state transitions, checkpointing, resume and interrupts -
genuinely useful for a long-running investigation loop. The risk is the usual
one: business logic migrating into node bodies until the framework and the
domain are inseparable.

## Decision
`agent/logic` holds pure decision functions with no workflow import.
`agent/graph` holds thin LangGraph wrappers. A test forbids `agent.logic` from
importing `langgraph`. A second, plain-loop runtime is implemented in tests and
runs the same suite.

## Consequences
Slight indirection on every node. In return, invariant 15 is demonstrated rather
than asserted, and a LangGraph API break is contained to one package.
