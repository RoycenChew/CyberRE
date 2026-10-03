"""Storage protocols.

Structural protocols rather than base classes: an adapter satisfies one by
having the right shape, so core never needs to know an implementation exists.
Every implementation is held to one shared contract test suite, which is what
makes invariant 17 a tested claim rather than an intention.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from cyberre.core.models.artefact import Artefact
from cyberre.core.models.evidence import AgentClaimRecord, Evidence, ToolFailure
from cyberre.core.models.finding import CandidateFinding, Finding
from cyberre.core.models.hypothesis import Hypothesis
from cyberre.core.models.state import InvestigationState


@runtime_checkable
class ObjectStore(Protocol):
    """Content-addressed storage for bytes.

    Addressing by content hash, not by name, is what makes caching and
    provenance line up: the key of a stored object *is* the hash recorded in
    the evidence that refers to it.
    """

    def put(self, data: bytes, *, media_type: str | None = None) -> str:
        """Store `data` and return its reference."""
        ...

    def get(self, ref: str) -> bytes:
        """Retrieve previously stored bytes.

        Raises:
            KeyError: if `ref` is unknown. Never returns empty bytes for a
                missing object - a silent empty read would look like a tool
                that produced nothing.
        """
        ...

    def exists(self, ref: str) -> bool: ...


@runtime_checkable
class EvidenceStore(Protocol):
    """Persistence for evidence, claims and failures.

    Agent claims and tool failures have their own methods rather than sharing
    the evidence table, so that "fetch the evidence" cannot return something
    that is not evidence (invariant 2).
    """

    def add_evidence(self, evidence: Evidence) -> None: ...

    def add_many(self, evidence: Iterable[Evidence]) -> None: ...

    def get_evidence(self, evidence_id: str) -> Evidence:
        """Raises ``KeyError`` if unknown."""
        ...

    def list_evidence(self, investigation_id: str) -> Sequence[Evidence]: ...

    def add_agent_claim(self, claim: AgentClaimRecord) -> None: ...

    def list_agent_claims(self, investigation_id: str) -> Sequence[AgentClaimRecord]: ...

    def add_tool_failure(self, failure: ToolFailure) -> None: ...

    def list_tool_failures(self, investigation_id: str) -> Sequence[ToolFailure]: ...


@runtime_checkable
class InvestigationStore(Protocol):
    """Persistence for the investigation record itself."""

    def save_state(self, state: InvestigationState) -> None: ...

    def load_state(self, investigation_id: str) -> InvestigationState:
        """Raises ``KeyError`` if unknown."""
        ...

    def add_artefact(self, artefact: Artefact) -> None: ...

    def get_artefact(self, artefact_id: str) -> Artefact: ...

    def save_hypothesis(self, hypothesis: Hypothesis) -> None: ...

    def list_hypotheses(self, investigation_id: str) -> Sequence[Hypothesis]: ...

    def save_candidate(self, candidate: CandidateFinding) -> None: ...

    def save_finding(self, finding: Finding) -> None: ...

    def list_findings(self, investigation_id: str) -> Sequence[Finding]: ...
