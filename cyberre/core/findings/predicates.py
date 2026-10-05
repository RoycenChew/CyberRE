"""Evidence predicates: the testable units a requirement is built from.

Each predicate answers one question about the evidence and returns the
evidence IDs that answer it - not a boolean. Returning the IDs is what lets
the engine check independence across a whole requirement set afterwards, and
what lets a finding cite the specific evidence that satisfied each part.

Predicates are deterministic and model-free. "Is this sink reachable from an
entry point?" is a graph query, and a model's opinion on it is not evidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

from cyberre.core.evidence.graph import EvidenceGraph
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence
from cyberre.core.trust.levels import may_satisfy_requirement


@dataclass(frozen=True)
class PredicateContext:
    """Everything a predicate may look at.

    Deliberately narrow. A predicate that could reach the model, the network
    or the filesystem would stop being deterministic, and the whole point of
    validation is that it gives the same answer every time.
    """

    evidence: Sequence[Evidence]
    graph: EvidenceGraph
    os_name: str | None = None
    architecture: str | None = None

    def flow_sites(self, markers: frozenset[str]) -> frozenset[str]:
        """Symbols where a flow to these sinks was observed.

        Reachability has to be tied to the site it is about. Matching on
        the sink name alone let a reachable call to `subprocess.call` in
        one function satisfy the reachability requirement for an entirely
        different call in another - flagged twice by adversarial review
        before it was fixed here.
        """
        sites: set[str] = set()
        for evidence in self.of_type(EvidenceType.DATA_FLOW):
            sink = str(getattr(evidence.observation, "sink", "")).lower()
            if not any(marker in sink for marker in markers):
                continue
            symbol = getattr(evidence.location, "symbol", None)
            if symbol:
                sites.add(str(symbol))
        return frozenset(sites)

    def admissible(self) -> list[Evidence]:
        """Evidence that may satisfy a requirement at all.

        Filters by trust level, which is where invariant 2 bites: an agent
        claim is never in this list, however confidently it was worded.
        """
        return [e for e in self.evidence if may_satisfy_requirement(e.trust_level)]

    def of_type(self, *types: EvidenceType) -> list[Evidence]:
        wanted = set(types)
        return [e for e in self.admissible() if e.evidence_type in wanted]


class Predicate(ABC):
    """One checkable question about the evidence."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Phrased as what must be true, because an unsatisfied predicate is
        rendered into the report as the thing that is missing."""

    @abstractmethod
    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        """Evidence IDs satisfying this, or an empty set."""

    def holds(self, context: PredicateContext) -> bool:
        return bool(self.satisfied_by(context))


@dataclass(frozen=True)
class HasEvidenceOfType(Predicate):
    """Evidence of a given kind exists."""

    types: frozenset[EvidenceType]
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        return frozenset(e.evidence_id for e in context.of_type(*self.types))


@dataclass(frozen=True)
class HasScannerFinding(Predicate):
    """A scanner matched a rule naming one of these weaknesses.

    A scanner hit satisfies at most the *sink* part of a requirement set. It
    is listed as its own predicate so that a set cannot accidentally be
    satisfied by a scanner hit alone.
    """

    cwe_ids: frozenset[str]
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        found: set[str] = set()
        for evidence in context.of_type(EvidenceType.SCANNER_FINDING):
            reported = getattr(evidence.observation, "cwe", ())
            if any(any(wanted in str(entry) for wanted in self.cwe_ids) for entry in reported):
                found.add(evidence.evidence_id)
        return frozenset(found)


@dataclass(frozen=True)
class HasDataFlow(Predicate):
    """A data-flow path reaches a sink of interest."""

    sink_markers: frozenset[str]
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        found: set[str] = set()
        for evidence in context.of_type(EvidenceType.DATA_FLOW):
            sink = str(getattr(evidence.observation, "sink", "")).lower()
            if any(marker in sink for marker in self.sink_markers):
                found.add(evidence.evidence_id)
        return frozenset(found)


@dataclass(frozen=True)
class FlowIsUnsanitised(Predicate):
    """A data-flow path with no sanitiser on it.

    Distinct from "no sanitiser was observed". A flow that records a
    sanitiser is positive evidence *against* the hypothesis, which is why
    sanitisers are captured on the observation rather than inferred later.
    """

    sink_markers: frozenset[str]

    @property
    def description(self) -> str:
        return "a flow to the sink carries no sanitiser"

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        found: set[str] = set()
        for evidence in context.of_type(EvidenceType.DATA_FLOW):
            observation = evidence.observation
            sink = str(getattr(observation, "sink", "")).lower()
            if not any(marker in sink for marker in self.sink_markers):
                continue
            if not getattr(observation, "sanitizers", ()):
                found.add(evidence.evidence_id)
        return frozenset(found)


@dataclass(frozen=True)
class IsReachable(Predicate):
    """Something is reachable from an entry point.

    Satisfied either by an explicit reachability observation or by a path
    through the evidence graph. Both are deterministic; neither is a model's
    opinion.
    """

    targets: frozenset[str]
    label: str = "the code is reachable from an entry point"

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        found: set[str] = set()
        sites = context.flow_sites(self.targets)

        for evidence in context.of_type(EvidenceType.REACHABILITY):
            observation = evidence.observation
            target = str(getattr(observation, "target", "")).lower()
            if not getattr(observation, "reachable", False):
                continue
            if not any(marker in target for marker in self.targets):
                continue
            if not self._same_site(evidence, sites):
                continue
            found.add(evidence.evidence_id)

        if not found:
            found |= self._via_graph(context)
        return frozenset(found)

    @staticmethod
    def _same_site(evidence: Evidence, sites: frozenset[str]) -> bool:
        """Whether this reachability is about a site where a flow was seen.

        When no flow carries a symbol there is nothing to tie to, so the
        evidence is accepted - the alternative would silently reject
        reachability from tools that do not report symbols.
        """
        if not sites:
            return True
        symbol = getattr(evidence.location, "symbol", None)
        return symbol is None or str(symbol) in sites

    def _via_graph(self, context: PredicateContext) -> set[str]:
        from cyberre.core.evidence.graph import NodeKind

        entries = [node.node_id for node in context.graph.nodes_of_kind(NodeKind.ENTRY_POINT)]
        if not entries:
            return set()

        found: set[str] = set()
        for node in context.graph:
            if not any(marker in node.node_id.lower() for marker in self.targets):
                continue
            for entry in entries:
                path = context.graph.find_path(entry, node.node_id)
                if path is not None:
                    found.update(path.evidence_ids())
        return found


@dataclass(frozen=True)
class ReachabilityDisproven(Predicate):
    """Positive evidence that something is *not* reachable.

    Its own predicate because "we found no path" and "we established there is
    no path" are different claims, and only the second justifies reporting
    UNREACHABLE rather than NOT_ENOUGH_EVIDENCE.
    """

    targets: frozenset[str]

    @property
    def description(self) -> str:
        return "no path reaches the code from any entry point"

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        """Only when nothing says a path *does* reach it.

        An artefact commonly contains several sites calling the same sink,
        some reachable and some not. Matching on the sink name alone let
        one dead call refute a live one elsewhere in the same file, which
        produced a finding whose own evidence contradicted its status -
        caught by the adversarial reviewer, which is what it is for.

        Refutation is the strongest negative the system can assert, so it
        requires unanimity: any positive reachability for the same target
        withdraws it, and the outcome falls back to the ordinary
        requirement check.
        """
        sites = context.flow_sites(self.targets)
        refuting: set[str] = set()
        for evidence in context.of_type(EvidenceType.REACHABILITY):
            observation = evidence.observation
            target = str(getattr(observation, "target", "")).lower()
            if not any(marker in target for marker in self.targets):
                continue
            if not IsReachable._same_site(evidence, sites):
                continue
            if getattr(observation, "reachable", True):
                return frozenset()
            refuting.add(evidence.evidence_id)
        return frozenset(refuting)


@dataclass(frozen=True)
class HasApiSequence(Predicate):
    """Every call in a sequence is present.

    All of them, not some. A partial sequence is the single most common way
    a benign binary resembles a malicious one - importing VirtualAllocEx
    without the rest is ordinary allocation.
    """

    symbols: frozenset[str]
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        by_symbol: dict[str, str] = {}
        for evidence in context.of_type(EvidenceType.IMPORT, EvidenceType.CALL_EDGE):
            observation = evidence.observation
            for attribute in ("symbol", "callee"):
                name = getattr(observation, attribute, None)
                if name and str(name) in self.symbols:
                    by_symbol.setdefault(str(name), evidence.evidence_id)

        if set(by_symbol) != set(self.symbols):
            return frozenset()
        return frozenset(by_symbol.values())


@dataclass(frozen=True)
class HasVersionedDependency(Predicate):
    """A dependency is declared *with a resolved version*.

    An unpinned dependency cannot be matched against an advisory range, so
    it does not satisfy this. That is the difference between a name match
    and an applicability finding.
    """

    @property
    def description(self) -> str:
        return "the dependency is declared with a resolved version"

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        return frozenset(
            e.evidence_id
            for e in context.of_type(EvidenceType.DEPENDENCY)
            if getattr(e.observation, "version", None)
        )


@dataclass(frozen=True)
class HasKnowledgeRecord(Predicate):
    """An authoritative knowledge record applies.

    Only structured knowledge reaches here. Semantic retrieval may never
    satisfy a requirement: a passage that reads as relevant is not a fact
    that applies (ADR-017).
    """

    record_prefix: str
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        return frozenset(
            e.evidence_id
            for e in context.of_type(EvidenceType.KNOWLEDGE_RECORD)
            if str(getattr(e.observation, "record_id", "")).startswith(self.record_prefix)
        )


@dataclass(frozen=True)
class AnyOf(Predicate):
    """Satisfied when any member is.

    Used where a requirement can be met more than one way - a sink observed
    by a scanner or by data-flow analysis, say - without weakening the
    requirement itself.
    """

    options: tuple[Predicate, ...]
    label: str

    @property
    def description(self) -> str:
        return self.label

    def satisfied_by(self, context: PredicateContext) -> frozenset[str]:
        for option in self.options:
            found = option.satisfied_by(context)
            if found:
                return found
        return frozenset()
