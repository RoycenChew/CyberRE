"""Assemble an evidence graph from stored records.

Observations describe program structure - this function calls that one, this
input flows to that sink - and the graph is where those descriptions become
queryable. The translation lives here, in one place, so that "is this sink
reachable?" is answered from the same edges a report will cite.

Every structural edge records the evidence that asserted it. An edge CyberRE
inferred and an edge a tool observed are not the same kind of claim.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable

from cyberre.core.evidence.graph import Edge, EvidenceGraph, Node, NodeKind
from cyberre.core.models.enums import EdgeKind
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.hypothesis import Hypothesis
from cyberre.core.models.observation import (
    CallEdge,
    DataFlowPath,
    DependencyObservation,
    ImportObservation,
    ReachabilityObservation,
)


def function_node(name: str) -> Node:
    return Node(node_id=f"fn:{name}", kind=NodeKind.FUNCTION, label=name)


def package_node(ecosystem: str, name: str) -> Node:
    return Node(
        node_id=f"pkg:{ecosystem}:{name}",
        kind=NodeKind.PACKAGE,
        label=f"{ecosystem}:{name}",
    )


def _add_structural_edges(graph: EvidenceGraph, evidence: Evidence) -> None:
    """Translate one observation into the relationships it asserts."""
    observation = evidence.observation
    eid = evidence.evidence_id

    match observation:
        case CallEdge():
            caller = function_node(observation.caller)
            callee = function_node(observation.callee)
            graph.add_node(caller)
            graph.add_node(callee)
            graph.add_edge(
                Edge(
                    source=caller.node_id,
                    kind=EdgeKind.DEPENDS_ON,
                    target=callee.node_id,
                    evidence_id=eid,
                )
            )

        case DataFlowPath():
            source = function_node(observation.source)
            sink = function_node(observation.sink)
            graph.add_node(source)
            graph.add_node(sink)
            # Intermediate steps become their own hops, so a reported taint
            # path can be read step by step rather than asserted end to end.
            chain = [source.node_id]
            for step in observation.steps:
                node = function_node(step)
                graph.add_node(node)
                chain.append(node.node_id)
            chain.append(sink.node_id)
            for left, right in itertools.pairwise(chain):
                graph.add_edge(
                    Edge(
                        source=left,
                        kind=EdgeKind.DEPENDS_ON,
                        target=right,
                        evidence_id=eid,
                    )
                )

        case ReachabilityObservation() if observation.reachable:
            target = function_node(observation.target)
            graph.add_node(target)
            if observation.entry_point is not None:
                entry = Node(
                    node_id=f"entry:{observation.entry_point}",
                    kind=NodeKind.ENTRY_POINT,
                    label=observation.entry_point,
                )
                graph.add_node(entry)
                graph.add_edge(
                    Edge(
                        source=entry.node_id,
                        kind=EdgeKind.DEPENDS_ON,
                        target=target.node_id,
                        evidence_id=eid,
                    )
                )

        case ReachabilityObservation():
            # reachable=False asserts no edge. The absence is the finding, and
            # inventing an edge here would quietly destroy it.
            graph.add_node(function_node(observation.target))

        case ImportObservation():
            symbol = Node(
                node_id=f"fn:{observation.symbol}",
                kind=NodeKind.EXTERNAL,
                label=observation.symbol,
                attributes={"library": observation.library or ""},
            )
            graph.add_node(symbol)
            graph.add_edge(
                Edge(
                    source=evidence.artefact_id,
                    kind=EdgeKind.DEPENDS_ON,
                    target=symbol.node_id,
                    evidence_id=eid,
                )
            )

        case DependencyObservation():
            package = package_node(observation.ecosystem, observation.name)
            graph.add_node(package)
            graph.add_edge(
                Edge(
                    source=evidence.artefact_id,
                    kind=EdgeKind.DEPENDS_ON,
                    target=package.node_id,
                    evidence_id=eid,
                )
            )

        case _:
            # Observations with no structural claim - a string, a section, a
            # scanner hit - are evidence nodes only. They still support
            # hypotheses; they just do not describe program topology.
            pass


def build_graph(
    evidence: Iterable[Evidence],
    hypotheses: Iterable[Hypothesis] = (),
) -> EvidenceGraph:
    """Build a graph from evidence and hypotheses.

    Deterministic: the same inputs produce the same graph, which is what lets
    an investigation be replayed and compared.
    """
    graph = EvidenceGraph()

    for item in evidence:
        graph.add_evidence(item)
        graph.add_node(Node(node_id=item.artefact_id, kind=NodeKind.ARTEFACT))
        graph.add_edge(
            Edge(
                source=item.evidence_id,
                kind=EdgeKind.OBSERVED_IN,
                target=item.artefact_id,
            )
        )
        _add_structural_edges(graph, item)

    for hypothesis in hypotheses:
        graph.add_node(
            Node(
                node_id=hypothesis.hypothesis_id,
                kind=NodeKind.HYPOTHESIS,
                label=str(hypothesis.hypothesis_class),
            )
        )
        for evidence_id in hypothesis.supporting_evidence:
            graph.add_edge(
                Edge(
                    source=evidence_id,
                    kind=EdgeKind.SUPPORTS,
                    target=hypothesis.hypothesis_id,
                )
            )
        for evidence_id in hypothesis.contradicting_evidence:
            graph.add_edge(
                Edge(
                    source=evidence_id,
                    kind=EdgeKind.CONTRADICTS,
                    target=hypothesis.hypothesis_id,
                )
            )

    return graph
