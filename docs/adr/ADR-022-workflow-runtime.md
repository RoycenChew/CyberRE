# ADR-022: The investigation runtime is a plain loop; LangGraph stays optional

## Status
Proposed. Narrows ADR-003, which assumed LangGraph would be the runtime while
insisting it remain an adapter.

## Context
The architecture named LangGraph for state, checkpointing, conditional
transitions, resume and human-approval interrupts. ADR-003 then required that
all decision logic live in `agent/logic` as framework-free functions, with
`agent/graph` holding only thin wrappers, and that a second runtime exist to
prove the framework is replaceable (invariant 15).

Building toward it, the balance looks different from how it looked at freeze
time, because three of the five things LangGraph was wanted for already exist:

- **Checkpointing and resume.** `InvestigationStore.save_state` /
  `load_state` persist a validated, size-guarded state after any step. That
  is the whole mechanism, and it is already covered by the storage contract
  suite.
- **Human approval.** `ApprovalGateway` is a core domain service (ADR-014),
  deliberately not a workflow-engine interrupt, so that replacing the runtime
  cannot remove the gate.
- **Conditional transitions.** The loop has one branch - continue
  investigating or move to reasoning - decided by a pure sufficiency
  function.

What remains is a `while` loop with a budget check. Against that, LangGraph
brings `langchain-core` and its transitive dependencies into a product whose
runtime dependencies are currently pydantic and httpx, and whose core has
none.

The dependency policy asks whether the standard library can do the job, and
whether a dependency materially improves CyberRE. Here the honest answer to
the first is yes and to the second is not yet.

## Decision
Implement the runtime as a plain loop in `cyberre/runtime/`, over pure
decision functions in `cyberre/agent/logic/`. No LangGraph dependency in V1.

`agent/graph` stays reserved and empty. The boundary rule forbidding
`agent.logic` from importing a workflow engine stays in place, so a LangGraph
adapter can be added later without touching a single decision function - which
was the real point of ADR-003.

Invariant 15 is now demonstrated by the inverse of the original plan: rather
than a plain loop proving LangGraph is replaceable, the plain loop is the
runtime and the logic's independence from any engine is what a test asserts.

## Consequences
Two fewer dependency trees, and the loop is readable in one file.

What is given up is real and should be named: LangGraph's durable execution,
its streaming and its ecosystem tooling. If the investigation loop grows
genuine concurrency across long-running branches, or needs distributed
execution, this decision should be revisited in a superseding ADR rather than
worked around - adding a half-built scheduler to `runtime/` would be the worse
outcome.

This diverges from the frozen architecture, which named LangGraph in section
2 and in the M9 milestone. Correction section 24 says LangGraph *may* be used
rather than must, so this is within the frozen design's latitude, but it is
recorded here rather than left as a silent omission.
