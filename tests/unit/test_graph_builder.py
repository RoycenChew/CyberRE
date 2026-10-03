"""Building a graph from evidence.

The scenario at the bottom is the one that matters: it is the shape of the
question M10 will ask - does a reachable path connect an attacker-controlled
source to a dangerous sink - answered entirely from observations.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.evidence.builder import build_graph, function_node
from cyberre.core.evidence.graph import NodeKind
from cyberre.core.models.enums import EdgeKind, EvidenceType, HypothesisStatus
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.location import BinaryLocation, PackageLocation
from cyberre.core.models.observation import (
    CallEdge,
    DataFlowPath,
    DependencyObservation,
    ImportObservation,
    ReachabilityObservation,
)

pytestmark = pytest.mark.unit


def binary_at(address: int, function: str) -> BinaryLocation:
    return BinaryLocation(address=address, function=function)


class TestStructuralEdges:
    def test_a_call_observation_becomes_a_call_edge(self, make_evidence: Any) -> None:
        ev = make_evidence(
            evidence_type=EvidenceType.CALL_EDGE,
            observation=CallEdge(caller="main", callee="handler"),
            location=binary_at(0x401000, "main"),
        )
        graph = build_graph([ev])
        path = graph.find_path("fn:main", "fn:handler")
        assert path is not None
        assert path.evidence_ids() == (ev.evidence_id,)

    def test_a_data_flow_becomes_a_hop_per_step(self, make_evidence: Any) -> None:
        """So a taint path can be read step by step, not asserted end to end."""
        ev = make_evidence(
            evidence_type=EvidenceType.DATA_FLOW,
            observation=DataFlowPath(
                source="read_request",
                sink="os_system",
                steps=("parse_params", "build_command"),
            ),
            location=binary_at(0x402000, "read_request"),
        )
        graph = build_graph([ev])
        path = graph.find_path("fn:read_request", "fn:os_system")
        assert path is not None
        assert path.nodes == (
            "fn:read_request",
            "fn:parse_params",
            "fn:build_command",
            "fn:os_system",
        )

    def test_reachable_observation_links_the_entry_point(self, make_evidence: Any) -> None:
        ev = make_evidence(
            evidence_type=EvidenceType.REACHABILITY,
            observation=ReachabilityObservation(
                target="handler", entry_point="http_route", reachable=True
            ),
            location=binary_at(0x403000, "handler"),
        )
        graph = build_graph([ev])
        assert graph.find_path("entry:http_route", "fn:handler") is not None

    def test_unreachable_observation_creates_no_edge(self, make_evidence: Any) -> None:
        """The absence *is* the finding; inventing an edge would destroy it."""
        ev = make_evidence(
            evidence_type=EvidenceType.REACHABILITY,
            observation=ReachabilityObservation(
                target="dead_code", entry_point="main", reachable=False
            ),
            location=binary_at(0x404000, "dead_code"),
        )
        graph = build_graph([ev])
        assert "fn:dead_code" in graph
        assert "entry:main" not in graph

    def test_an_import_links_the_artefact_to_the_symbol(self, make_evidence: Any) -> None:
        ev = make_evidence(
            evidence_type=EvidenceType.IMPORT,
            observation=ImportObservation(library="kernel32.dll", symbol="VirtualAllocEx"),
            location=binary_at(0x405000, None),
        )
        graph = build_graph([ev])
        assert "fn:VirtualAllocEx" in graph
        assert graph.node("fn:VirtualAllocEx").attributes["library"] == "kernel32.dll"

    def test_a_dependency_becomes_a_package_node(self, make_evidence: Any) -> None:
        ev = make_evidence(
            evidence_type=EvidenceType.DEPENDENCY,
            observation=DependencyObservation(ecosystem="pypi", name="requests", version="2.25.0"),
            location=PackageLocation(ecosystem="pypi", name="requests", version="2.25.0"),
        )
        graph = build_graph([ev])
        assert graph.node("pkg:pypi:requests").kind is NodeKind.PACKAGE

    def test_observations_without_structure_add_only_an_evidence_node(
        self, make_evidence: Any
    ) -> None:
        """A scanner hit supports hypotheses; it does not describe topology."""
        ev = make_evidence()
        graph = build_graph([ev])
        assert ev.evidence_id in graph
        assert [n.node_id for n in graph.nodes_of_kind(NodeKind.FUNCTION)] == []


class TestEvidenceLinkage:
    def test_every_evidence_is_linked_to_its_artefact(self, make_evidence: Any) -> None:
        ev = make_evidence()
        graph = build_graph([ev])
        edges = graph.out_edges(ev.evidence_id, kind=EdgeKind.OBSERVED_IN)
        assert [e.target for e in edges] == [ev.artefact_id]

    def test_hypothesis_support_and_contradiction_are_recorded(self, make_evidence: Any) -> None:
        supporting = make_evidence(independence_key="k1")
        against = make_evidence(independence_key="k2")
        hypothesis = Hypothesis(
            investigation_id="inv-1",
            statement="Command injection is present.",
            hypothesis_class=HypothesisClass(taxonomy="cwe", identifier="78"),
            supporting_evidence=(supporting.evidence_id,),
            contradicting_evidence=(against.evidence_id,),
            status=HypothesisStatus.TESTING,
            created_by="reasoner",
        )
        graph = build_graph([supporting, against], [hypothesis])
        assert len(graph.supporting(hypothesis.hypothesis_id)) == 1
        assert graph.has_contradiction(hypothesis.hypothesis_id)


class TestDeterminism:
    def test_the_same_input_builds_the_same_graph(self, make_evidence: Any) -> None:
        """Replay compares graphs, so construction must be order-stable."""
        items = [make_evidence(independence_key=f"k{i}") for i in range(5)]
        first = build_graph(items)
        second = build_graph(items)
        assert len(first) == len(second)
        assert first.edge_count == second.edge_count
        assert {n.node_id for n in first} == {n.node_id for n in second}


class TestEndToEndReachabilityQuestion:
    """The question validation will actually ask at M10."""

    def test_a_reachable_taint_path_is_discoverable_from_observations(
        self, make_evidence: Any
    ) -> None:
        reachable = make_evidence(
            independence_key="reach",
            evidence_type=EvidenceType.REACHABILITY,
            observation=ReachabilityObservation(
                target="read_request", entry_point="http_route", reachable=True
            ),
            location=binary_at(0x401000, "read_request"),
        )
        flow = make_evidence(
            independence_key="flow",
            evidence_type=EvidenceType.DATA_FLOW,
            observation=DataFlowPath(
                source="read_request", sink="os_system", steps=("build_command",)
            ),
            location=binary_at(0x402000, "read_request"),
        )
        graph = build_graph([reachable, flow])

        path = graph.find_path("entry:http_route", "fn:os_system")

        assert path is not None, "an attacker-reachable path to the sink should be found"
        assert set(path.evidence_ids()) == {reachable.evidence_id, flow.evidence_id}
        # Two tools, two distinct observations - genuine corroboration.
        assert graph.count_independent(path.evidence_ids()) == 2

    def test_a_sanitised_flow_still_records_the_sanitiser(self, make_evidence: Any) -> None:
        """Present sanitisers are the reviewer's strongest argument against."""
        flow = make_evidence(
            evidence_type=EvidenceType.DATA_FLOW,
            observation=DataFlowPath(
                source="read_request",
                sink="os_system",
                steps=("build_command",),
                sanitizers=("shlex.quote",),
            ),
            location=binary_at(0x402000, "read_request"),
        )
        graph = build_graph([flow])
        observation = graph.evidence(flow.evidence_id).observation
        assert observation.sanitizers == ("shlex.quote",)  # type: ignore[union-attr]

    def test_function_node_ids_are_namespaced(self) -> None:
        """So a function called 'main' cannot collide with an artefact id."""
        assert function_node("main").node_id == "fn:main"
