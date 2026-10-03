"""The evidence graph.

Relates evidence, hypotheses, findings and the program entities they talk
about, so that questions validation needs to answer - is this sink reachable,
does anything contradict this, how many *independent* sources support it - are
queries rather than judgements.

Implemented over plain dictionaries (ADR-019). Traversals are depth-bounded
and cycle-safe: the graph is assembled from tool output, and tool output is
not something to take on trust.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from enum import StrEnum

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import EdgeKind
from cyberre.core.models.evidence import Evidence

#: Depth ceiling for any traversal. A path longer than this is not a useful
#: explanation of a security finding even if it exists, and the bound means a
#: malformed graph degrades into a short answer rather than a hang.
MAX_TRAVERSAL_DEPTH = 64


class NodeKind(StrEnum):
    """What a node represents.

    Program entities (function, file, package) are nodes in their own right,
    not attributes of evidence, because reachability is a question about the
    program and several pieces of evidence may speak about the same function.
    """

    EVIDENCE = "evidence"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"
    ARTEFACT = "artefact"
    FUNCTION = "function"
    FILE = "file"
    PACKAGE = "package"
    ENTRY_POINT = "entry_point"
    SINK = "sink"
    EXTERNAL = "external"


class Node(DomainModel):
    node_id: NonEmptyStr
    kind: NodeKind
    label: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class Edge(DomainModel):
    source: NonEmptyStr
    kind: EdgeKind
    target: NonEmptyStr
    evidence_id: str | None = None
    """Which evidence asserts this relationship.

    An edge without one is an inference by CyberRE itself. Recording the
    difference is what lets a reported call path be traced back to the tool
    that observed each hop.
    """


class Path(DomainModel):
    """A traversal result, kept with its edges so it can be explained."""

    nodes: tuple[str, ...]
    edges: tuple[Edge, ...]

    @property
    def length(self) -> int:
        return len(self.edges)

    def evidence_ids(self) -> tuple[str, ...]:
        """Evidence backing each hop, in order, skipping inferred edges."""
        return tuple(e.evidence_id for e in self.edges if e.evidence_id is not None)


class UnknownNodeError(KeyError):
    """A query named a node the graph does not contain.

    Raised rather than returning an empty result: "no path from X" and "X is
    not in the graph" are different answers, and conflating them would let a
    typo read as evidence of unreachability.
    """


class EvidenceGraph:
    """A directed labelled multigraph over investigation entities."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._out: dict[str, list[Edge]] = {}
        self._in: dict[str, list[Edge]] = {}
        self._evidence: dict[str, Evidence] = {}

    # ---------------------------------------------------------------- build

    def add_node(self, node: Node) -> None:
        """Add or replace a node."""
        self._nodes[node.node_id] = node
        self._out.setdefault(node.node_id, [])
        self._in.setdefault(node.node_id, [])

    def add_evidence(self, evidence: Evidence) -> None:
        """Add an evidence node, plus its derivation edges.

        The `derived_from` edges are added here rather than left to the caller
        because independence analysis depends on them, and an omitted edge
        would silently turn derived evidence into apparent corroboration.
        """
        self.add_node(
            Node(
                node_id=evidence.evidence_id,
                kind=NodeKind.EVIDENCE,
                label=evidence.evidence_type.value,
            )
        )
        self._evidence[evidence.evidence_id] = evidence
        for parent in evidence.derived_from:
            self.add_edge(
                Edge(
                    source=evidence.evidence_id,
                    kind=EdgeKind.DERIVED_FROM,
                    target=parent,
                )
            )

    def add_edge(self, edge: Edge) -> None:
        """Add an edge, creating placeholder endpoints if needed.

        Placeholders are tolerated because evidence often arrives before the
        entity it refers to has been described - an import observed before the
        function that calls it has been analysed.
        """
        for node_id in (edge.source, edge.target):
            if node_id not in self._nodes:
                self.add_node(Node(node_id=node_id, kind=NodeKind.EXTERNAL))
        self._out[edge.source].append(edge)
        self._in[edge.target].append(edge)

    # ----------------------------------------------------------------- read

    def __contains__(self, node_id: object) -> bool:
        return node_id in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._out.values())

    def node(self, node_id: str) -> Node:
        self._require(node_id)
        return self._nodes[node_id]

    def evidence(self, evidence_id: str) -> Evidence:
        if evidence_id not in self._evidence:
            raise UnknownNodeError(f"no evidence node '{evidence_id}' in the graph")
        return self._evidence[evidence_id]

    def nodes_of_kind(self, kind: NodeKind) -> Sequence[Node]:
        return [n for n in self._nodes.values() if n.kind is kind]

    def out_edges(self, node_id: str, *, kind: EdgeKind | None = None) -> Sequence[Edge]:
        self._require(node_id)
        edges = self._out[node_id]
        return [e for e in edges if kind is None or e.kind is kind]

    def in_edges(self, node_id: str, *, kind: EdgeKind | None = None) -> Sequence[Edge]:
        self._require(node_id)
        edges = self._in[node_id]
        return [e for e in edges if kind is None or e.kind is kind]

    def _require(self, node_id: str) -> None:
        if node_id not in self._nodes:
            raise UnknownNodeError(f"no node '{node_id}' in the graph")

    # ------------------------------------------------------------ traversal

    def find_path(
        self,
        source: str,
        target: str,
        *,
        kinds: Iterable[EdgeKind] | None = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> Path | None:
        """Shortest path from `source` to `target`, or ``None``.

        Breadth-first, so the path returned is the shortest one - the most
        convincing form of a reachability argument, and the shortest thing to
        read in a report.

        ``None`` means "no path within `max_depth` over these edge kinds". It
        is not proof of unreachability in general; a caller that reports
        ``UNREACHABLE`` must also be satisfied that the graph is complete
        enough for the absence to mean something.
        """
        self._require(source)
        self._require(target)
        allowed = frozenset(kinds) if kinds is not None else None

        if source == target:
            return Path(nodes=(source,), edges=())

        previous: dict[str, tuple[str, Edge]] = {}
        seen = {source}
        queue: deque[tuple[str, int]] = deque([(source, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._out[current]:
                if allowed is not None and edge.kind not in allowed:
                    continue
                nxt = edge.target
                if nxt in seen:
                    continue
                seen.add(nxt)
                previous[nxt] = (current, edge)
                if nxt == target:
                    return self._reconstruct(source, target, previous)
                queue.append((nxt, depth + 1))
        return None

    @staticmethod
    def _reconstruct(source: str, target: str, previous: dict[str, tuple[str, Edge]]) -> Path:
        nodes: list[str] = [target]
        edges: list[Edge] = []
        cursor = target
        while cursor != source:
            parent, edge = previous[cursor]
            edges.append(edge)
            nodes.append(parent)
            cursor = parent
        return Path(nodes=tuple(reversed(nodes)), edges=tuple(reversed(edges)))

    def reachable_from(
        self,
        source: str,
        *,
        kinds: Iterable[EdgeKind] | None = None,
        max_depth: int = MAX_TRAVERSAL_DEPTH,
    ) -> frozenset[str]:
        """Every node reachable from `source` within `max_depth`."""
        self._require(source)
        allowed = frozenset(kinds) if kinds is not None else None
        seen = {source}
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._out[current]:
                if allowed is not None and edge.kind not in allowed:
                    continue
                if edge.target not in seen:
                    seen.add(edge.target)
                    queue.append((edge.target, depth + 1))
        return frozenset(seen - {source})

    def ancestors(
        self, evidence_id: str, *, max_depth: int = MAX_TRAVERSAL_DEPTH
    ) -> frozenset[str]:
        """Transitive `derived_from` closure for a piece of evidence.

        The set of things it was computed from. Two records whose closures
        meet are not independent observations.
        """
        self._require(evidence_id)
        return self.reachable_from(evidence_id, kinds=(EdgeKind.DERIVED_FROM,), max_depth=max_depth)

    # --------------------------------------------------------- independence

    def root_observation(self, evidence_id: str) -> str:
        """The independence key identifying the underlying observation.

        For derived evidence this is inherited from its origin, so a chain of
        transforms resolves back to the one thing that was actually seen.
        """
        evidence = self.evidence(evidence_id)
        return evidence.independence_key

    def independent_sources(self, evidence_ids: Iterable[str]) -> frozenset[str]:
        """Collapse `evidence_ids` to one representative per distinct source.

        This is the function that decides what counts as corroboration, and
        it applies two tests, because either alone is insufficient:

        * records sharing an ``independence_key`` describe one observation;
        * a record derived from another in the set adds no new observation,
          however different its key.

        The second case is the one that bites: a transform can legitimately
        derive a different key while still being the same underlying sighting.
        """
        ids = [eid for eid in evidence_ids if eid in self._evidence]
        if not ids:
            return frozenset()

        by_key: dict[str, str] = {}
        for eid in sorted(ids):
            by_key.setdefault(self.root_observation(eid), eid)
        candidates = set(by_key.values())

        independent: set[str] = set()
        for eid in sorted(candidates):
            lineage = self.ancestors(eid)
            if lineage & candidates:
                # Derived from something already in the set; not a new source.
                continue
            independent.add(eid)

        # Everything derived from everything else (a cycle, or a set holding
        # only derivations whose parents are also present) would leave nothing.
        # Keep one representative rather than claiming zero sources.
        if not independent and candidates:
            independent.add(min(candidates))
        return frozenset(independent)

    def count_independent(self, evidence_ids: Iterable[str]) -> int:
        """How many genuinely distinct observations back a claim."""
        return len(self.independent_sources(evidence_ids))

    # ------------------------------------------------------- contradictions

    def supporting(self, node_id: str) -> Sequence[Edge]:
        """Edges asserting support *for* `node_id`."""
        return self.in_edges(node_id, kind=EdgeKind.SUPPORTS)

    def contradicting(self, node_id: str) -> Sequence[Edge]:
        """Edges asserting contradiction of `node_id`."""
        return self.in_edges(node_id, kind=EdgeKind.CONTRADICTS)

    def has_contradiction(self, node_id: str) -> bool:
        return bool(self.contradicting(node_id))

    def conflicting_evidence_pairs(self) -> Sequence[tuple[str, str]]:
        """Pairs of nodes directly asserted to contradict each other.

        Surfaced rather than resolved. A contradiction is information - it is
        what makes an investigation escalate - and silently picking a winner
        is how a platform ends up confidently wrong.
        """
        pairs: set[tuple[str, str]] = set()
        for edges in self._out.values():
            for edge in edges:
                if edge.kind is EdgeKind.CONTRADICTS:
                    pairs.add(tuple(sorted((edge.source, edge.target))))  # type: ignore[arg-type]
        return sorted(pairs)

    def __iter__(self) -> Iterator[Node]:
        return iter(self._nodes.values())
