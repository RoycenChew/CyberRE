# ADR-019: The evidence graph is implemented in the standard library

## Status
Accepted. Narrows the earlier intention to use `networkx`.

## Context
The frozen architecture named `networkx` for the evidence graph. Writing the
graph made it clear how little of a graph library is actually needed: the
queries are adjacency lookup, bounded breadth-first reachability, transitive
ancestry over `derived_from`, and a grouping over `independence_key`. All are
short, and all are exercised on graphs of hundreds to low thousands of nodes,
not millions.

The dependency policy asks whether the standard library can do the job. Here it
plainly can, and the dependency would sit in `cyberre.core` - the package whose
whole purpose is to be free of things that can change underneath it.

There is also a correctness argument. Independence analysis is not a generic
graph query; it is a domain rule about what counts as corroboration, and it is
the rule most likely to be quietly wrong. Writing it directly, against our own
types, keeps it readable and keeps its tests honest.

## Decision
Implement `cyberre.core.evidence.graph` over plain dictionaries. No graph
dependency in core.

Traversals are explicitly depth-bounded and cycle-safe. An evidence graph
should be acyclic, but it is assembled from tool output, and tool output is not
a thing to take on trust.

## Consequences
One fewer dependency, and the independence rule is legible in the place it
matters. If a future workload needs real graph algorithms - community
detection, large-scale pathfinding - the `EvidenceGraph` surface is small
enough to reimplement over a library or a graph database without touching
callers. That is the same replacement strategy the storage protocols use.
