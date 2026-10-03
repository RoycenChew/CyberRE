"""In-memory storage.

Not a test double. This is the second real implementation of the storage
protocols, and its existence is what makes "storage is replaceable" a tested
claim rather than an intention: both implementations are held to one contract
suite, and a protocol change that only one can satisfy fails immediately
(invariant 17).

It is also the right store for a replay run, which should leave nothing on
disk, and for an ephemeral investigation whose records are not being kept.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from cyberre.core.models.artefact import Artefact
from cyberre.core.models.evidence import AgentClaimRecord, Evidence, ToolFailure
from cyberre.core.models.finding import CandidateFinding, Finding
from cyberre.core.models.hypothesis import Hypothesis
from cyberre.core.models.state import InvestigationState


class MemoryObjectStore:
    """Content-addressed blobs in a dictionary."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, data: bytes, *, media_type: str | None = None) -> str:
        ref = hashlib.sha256(data).hexdigest()
        self._blobs[ref] = data
        return ref

    def get(self, ref: str) -> bytes:
        if ref not in self._blobs:
            raise KeyError(f"no object '{ref}' in memory store")
        return self._blobs[ref]

    def exists(self, ref: str) -> bool:
        return ref in self._blobs


class MemoryStore:
    """Evidence and investigation storage in process memory.

    Mirrors :class:`~cyberre.adapters.storage.sqlite.store.SqliteStore`,
    including its ordering guarantees - a contract suite that passed here but
    not there would be testing the suite rather than the implementations.
    """

    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._claims: dict[str, AgentClaimRecord] = {}
        self._failures: dict[str, ToolFailure] = {}
        self._states: dict[str, InvestigationState] = {}
        self._artefacts: dict[str, Artefact] = {}
        self._hypotheses: dict[str, Hypothesis] = {}
        self._candidates: dict[str, CandidateFinding] = {}
        self._findings: dict[str, Finding] = {}

    # ------------------------------------------------------- EvidenceStore

    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence[evidence.evidence_id] = evidence

    def add_many(self, evidence: Iterable[Evidence]) -> None:
        for item in evidence:
            self.add_evidence(item)

    def get_evidence(self, evidence_id: str) -> Evidence:
        if evidence_id not in self._evidence:
            raise KeyError(f"no evidence '{evidence_id}'")
        return self._evidence[evidence_id]

    def list_evidence(self, investigation_id: str) -> Sequence[Evidence]:
        return sorted(
            (e for e in self._evidence.values() if e.investigation_id == investigation_id),
            key=lambda e: (e.created_at, e.evidence_id),
        )

    def add_agent_claim(self, claim: AgentClaimRecord) -> None:
        self._claims[claim.claim_id] = claim

    def list_agent_claims(self, investigation_id: str) -> Sequence[AgentClaimRecord]:
        return sorted(
            (c for c in self._claims.values() if c.investigation_id == investigation_id),
            key=lambda c: (c.created_at, c.claim_id),
        )

    def add_tool_failure(self, failure: ToolFailure) -> None:
        self._failures[failure.failure_id] = failure

    def list_tool_failures(self, investigation_id: str) -> Sequence[ToolFailure]:
        return sorted(
            (f for f in self._failures.values() if f.investigation_id == investigation_id),
            key=lambda f: (f.occurred_at, f.failure_id),
        )

    # -------------------------------------------------- InvestigationStore

    def save_state(self, state: InvestigationState) -> None:
        state.check_size()
        self._states[state.investigation_id] = state

    def load_state(self, investigation_id: str) -> InvestigationState:
        if investigation_id not in self._states:
            raise KeyError(f"no investigation '{investigation_id}'")
        return self._states[investigation_id]

    def add_artefact(self, artefact: Artefact) -> None:
        self._artefacts[artefact.artefact_id] = artefact

    def get_artefact(self, artefact_id: str) -> Artefact:
        if artefact_id not in self._artefacts:
            raise KeyError(f"no artefact '{artefact_id}'")
        return self._artefacts[artefact_id]

    def find_artefact_by_hash(self, sha256: str) -> Artefact | None:
        matches = sorted(
            (a for a in self._artefacts.values() if a.sha256 == sha256),
            key=lambda a: a.artefact_id,
        )
        return matches[0] if matches else None

    def save_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

    def list_hypotheses(self, investigation_id: str) -> Sequence[Hypothesis]:
        return sorted(
            (h for h in self._hypotheses.values() if h.investigation_id == investigation_id),
            key=lambda h: h.hypothesis_id,
        )

    def save_candidate(self, candidate: CandidateFinding) -> None:
        self._candidates[candidate.candidate_id] = candidate

    def list_candidates(self, investigation_id: str) -> Sequence[CandidateFinding]:
        return sorted(
            (c for c in self._candidates.values() if c.investigation_id == investigation_id),
            key=lambda c: c.candidate_id,
        )

    def save_finding(self, finding: Finding) -> None:
        self._findings[finding.finding_id] = finding

    def list_findings(self, investigation_id: str) -> Sequence[Finding]:
        return sorted(
            (f for f in self._findings.values() if f.investigation_id == investigation_id),
            key=lambda f: f.finding_id,
        )
