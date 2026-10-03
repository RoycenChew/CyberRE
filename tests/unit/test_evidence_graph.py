"""Evidence graph behaviour.

The independence tests are the ones that matter most: that logic decides what
counts as corroboration, and corroboration is what confidence is built from.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.evidence.graph import (
    Edge,
    EvidenceGraph,
    Node,
    NodeKind,
    UnknownNodeError,
)
from cyberre.core.models.enums import EdgeKind
from cyberre.core.trust.levels import TrustLevel

pytestmark = pytest.mark.unit


@pytest.fixture
def graph() -> EvidenceGraph:
    return EvidenceGraph()


def call_edge(source: str, target: str, evidence_id: str | None = None) -> Edge:
    return Edge(source=source, kind=EdgeKind.DEPENDS_ON, target=target, evidence_id=evidence_id)


class TestConstruction:
    def test_adding_an_edge_creates_missing_endpoints(self, graph: EvidenceGraph) -> None:
        """Evidence often arrives before the entity it refers to is described."""
        graph.add_edge(call_edge("main", "handler"))
        assert "main" in graph
        assert graph.node("handler").kind is NodeKind.EXTERNAL

    def test_adding_evidence_also_adds_its_derivation_edges(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        """Left to the caller, an omitted edge turns derived evidence into
        apparent corroboration."""
        parent = make_evidence(independence_key="k1")
        child = make_evidence(
            independence_key="k2",
            derived_from=(parent.evidence_id,),
            trust_level=TrustLevel.DERIVED_EVIDENCE,
        )
        graph.add_evidence(parent)
        graph.add_evidence(child)
        assert graph.ancestors(child.evidence_id) == frozenset({parent.evidence_id})

    def test_node_count_and_edge_count(self, graph: EvidenceGraph) -> None:
        graph.add_edge(call_edge("a", "b"))
        graph.add_edge(call_edge("b", "c"))
        assert len(graph) == 3
        assert graph.edge_count == 2


class TestUnknownNodesAreAnError:
    def test_querying_a_missing_node_raises(self, graph: EvidenceGraph) -> None:
        """'No path from X' and 'X is not here' are different answers."""
        with pytest.raises(UnknownNodeError):
            graph.out_edges("ghost")

    def test_pathfinding_from_a_missing_node_raises(self, graph: EvidenceGraph) -> None:
        graph.add_node(Node(node_id="a", kind=NodeKind.FUNCTION))
        with pytest.raises(UnknownNodeError):
            graph.find_path("a", "ghost")

    def test_evidence_lookup_for_a_plain_node_raises(self, graph: EvidenceGraph) -> None:
        graph.add_node(Node(node_id="a", kind=NodeKind.FUNCTION))
        with pytest.raises(UnknownNodeError):
            graph.evidence("a")


class TestReachability:
    def test_finds_the_shortest_path(self, graph: EvidenceGraph) -> None:
        for src, dst in [("a", "b"), ("b", "c"), ("c", "d"), ("a", "d")]:
            graph.add_edge(call_edge(src, dst))
        path = graph.find_path("a", "d")
        assert path is not None
        assert path.nodes == ("a", "d")
        assert path.length == 1

    def test_returns_none_when_unreachable(self, graph: EvidenceGraph) -> None:
        graph.add_edge(call_edge("a", "b"))
        graph.add_node(Node(node_id="z", kind=NodeKind.SINK))
        assert graph.find_path("a", "z") is None

    def test_a_node_reaches_itself_trivially(self, graph: EvidenceGraph) -> None:
        graph.add_node(Node(node_id="a", kind=NodeKind.FUNCTION))
        path = graph.find_path("a", "a")
        assert path is not None and path.length == 0

    def test_edge_kinds_can_be_restricted(self, graph: EvidenceGraph) -> None:
        """A 'supports' edge is not a call path."""
        graph.add_edge(Edge(source="a", kind=EdgeKind.SUPPORTS, target="b"))
        assert graph.find_path("a", "b", kinds=(EdgeKind.DEPENDS_ON,)) is None
        assert graph.find_path("a", "b", kinds=(EdgeKind.SUPPORTS,)) is not None

    def test_cycles_do_not_hang(self, graph: EvidenceGraph) -> None:
        """Tool output is not something to take on trust."""
        graph.add_edge(call_edge("a", "b"))
        graph.add_edge(call_edge("b", "a"))
        graph.add_node(Node(node_id="z", kind=NodeKind.SINK))
        assert graph.find_path("a", "z") is None

    def test_depth_is_bounded(self, graph: EvidenceGraph) -> None:
        for i in range(10):
            graph.add_edge(call_edge(f"n{i}", f"n{i + 1}"))
        assert graph.find_path("n0", "n10", max_depth=3) is None
        assert graph.find_path("n0", "n10", max_depth=20) is not None

    def test_path_carries_the_evidence_for_each_hop(self, graph: EvidenceGraph) -> None:
        """A reported call path must be traceable to what observed it."""
        graph.add_edge(call_edge("a", "b", evidence_id="ev-1"))
        graph.add_edge(call_edge("b", "c", evidence_id="ev-2"))
        path = graph.find_path("a", "c")
        assert path is not None
        assert path.evidence_ids() == ("ev-1", "ev-2")

    def test_inferred_edges_contribute_no_evidence(self, graph: EvidenceGraph) -> None:
        graph.add_edge(call_edge("a", "b"))
        path = graph.find_path("a", "b")
        assert path is not None
        assert path.evidence_ids() == ()

    def test_reachable_from_excludes_the_source(self, graph: EvidenceGraph) -> None:
        graph.add_edge(call_edge("a", "b"))
        graph.add_edge(call_edge("b", "c"))
        assert graph.reachable_from("a") == frozenset({"b", "c"})


class TestInvariant7Independence:
    """Correlated evidence must not read as corroboration."""

    def test_records_sharing_a_key_count_once(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        """Three parsers over one Semgrep hit are one observation."""
        shared = "same-underlying-hit"
        ids = []
        for _ in range(3):
            ev = make_evidence(independence_key=shared)
            graph.add_evidence(ev)
            ids.append(ev.evidence_id)
        assert graph.count_independent(ids) == 1

    def test_distinct_observations_count_separately(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        ids = []
        for i in range(3):
            ev = make_evidence(independence_key=f"key-{i}")
            graph.add_evidence(ev)
            ids.append(ev.evidence_id)
        assert graph.count_independent(ids) == 3

    def test_derived_evidence_adds_no_new_source(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        """The case that bites: a transform may derive a *different* key while
        still being the same underlying sighting."""
        parent = make_evidence(independence_key="root")
        child = make_evidence(
            independence_key="transformed",
            derived_from=(parent.evidence_id,),
            trust_level=TrustLevel.DERIVED_EVIDENCE,
        )
        graph.add_evidence(parent)
        graph.add_evidence(child)
        assert graph.count_independent([parent.evidence_id, child.evidence_id]) == 1

    def test_a_deep_derivation_chain_is_still_one_source(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        root = make_evidence(independence_key="root")
        graph.add_evidence(root)
        ids = [root.evidence_id]
        previous = root.evidence_id
        for i in range(5):
            ev = make_evidence(
                independence_key=f"derived-{i}",
                derived_from=(previous,),
                trust_level=TrustLevel.DERIVED_EVIDENCE,
            )
            graph.add_evidence(ev)
            ids.append(ev.evidence_id)
            previous = ev.evidence_id
        assert graph.count_independent(ids) == 1

    def test_a_derivation_counts_when_its_parent_is_absent(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        """Only duplication *within the set being counted* is discounted."""
        parent = make_evidence(independence_key="root")
        child = make_evidence(
            independence_key="transformed",
            derived_from=(parent.evidence_id,),
            trust_level=TrustLevel.DERIVED_EVIDENCE,
        )
        other = make_evidence(independence_key="unrelated")
        for ev in (parent, child, other):
            graph.add_evidence(ev)
        assert graph.count_independent([child.evidence_id, other.evidence_id]) == 2

    def test_a_cyclic_derivation_still_reports_one_source(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        """Malformed input must not make corroboration vanish entirely."""
        a = make_evidence(independence_key="a")
        b = make_evidence(independence_key="b")
        graph.add_evidence(a)
        graph.add_evidence(b)
        graph.add_edge(Edge(source=a.evidence_id, kind=EdgeKind.DERIVED_FROM, target=b.evidence_id))
        graph.add_edge(Edge(source=b.evidence_id, kind=EdgeKind.DERIVED_FROM, target=a.evidence_id))
        assert graph.count_independent([a.evidence_id, b.evidence_id]) == 1

    def test_unknown_ids_are_ignored_rather_than_counted(
        self, graph: EvidenceGraph, make_evidence: Any
    ) -> None:
        ev = make_evidence(independence_key="only")
        graph.add_evidence(ev)
        assert graph.count_independent([ev.evidence_id, "ev-missing"]) == 1

    def test_an_empty_set_has_no_sources(self, graph: EvidenceGraph) -> None:
        assert graph.count_independent([]) == 0

    def test_the_result_is_deterministic(self, graph: EvidenceGraph, make_evidence: Any) -> None:
        """Replay must produce the same answer, so selection is ordered."""
        ids = []
        for _ in range(4):
            ev = make_evidence(independence_key="shared")
            graph.add_evidence(ev)
            ids.append(ev.evidence_id)
        first = graph.independent_sources(ids)
        assert first == graph.independent_sources(reversed(ids))


class TestContradictions:
    def test_contradictions_are_detected(self, graph: EvidenceGraph) -> None:
        graph.add_edge(Edge(source="ev-1", kind=EdgeKind.CONTRADICTS, target="hy-1"))
        assert graph.has_contradiction("hy-1")

    def test_support_is_not_contradiction(self, graph: EvidenceGraph) -> None:
        graph.add_edge(Edge(source="ev-1", kind=EdgeKind.SUPPORTS, target="hy-1"))
        assert graph.has_contradiction("hy-1") is False
        assert len(graph.supporting("hy-1")) == 1

    def test_conflicting_pairs_are_surfaced_not_resolved(self, graph: EvidenceGraph) -> None:
        """A contradiction is information; silently picking a winner is how a
        platform ends up confidently wrong."""
        graph.add_edge(Edge(source="ev-1", kind=EdgeKind.CONTRADICTS, target="ev-2"))
        graph.add_edge(Edge(source="ev-2", kind=EdgeKind.CONTRADICTS, target="ev-1"))
        assert graph.conflicting_evidence_pairs() == [("ev-1", "ev-2")]

    def test_no_conflicts_in_a_consistent_graph(self, graph: EvidenceGraph) -> None:
        graph.add_edge(Edge(source="ev-1", kind=EdgeKind.SUPPORTS, target="hy-1"))
        assert graph.conflicting_evidence_pairs() == []


class TestQueries:
    def test_nodes_can_be_listed_by_kind(self, graph: EvidenceGraph) -> None:
        graph.add_node(Node(node_id="f1", kind=NodeKind.FUNCTION))
        graph.add_node(Node(node_id="e1", kind=NodeKind.ENTRY_POINT))
        assert [n.node_id for n in graph.nodes_of_kind(NodeKind.ENTRY_POINT)] == ["e1"]

    def test_edges_can_be_filtered_by_kind(self, graph: EvidenceGraph) -> None:
        graph.add_edge(Edge(source="a", kind=EdgeKind.SUPPORTS, target="b"))
        graph.add_edge(Edge(source="a", kind=EdgeKind.DEPENDS_ON, target="b"))
        assert len(graph.out_edges("a")) == 2
        assert len(graph.out_edges("a", kind=EdgeKind.SUPPORTS)) == 1
