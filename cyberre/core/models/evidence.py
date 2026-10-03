"""Evidence, and the failure record that is deliberately not evidence."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import (
    DomainModel,
    NonEmptyStr,
    Sha256,
    TimestampField,
    new_id,
    stable_digest,
)
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.location import Location
from cyberre.core.models.observation import Observation
from cyberre.core.models.provenance import Provenance
from cyberre.core.trust.levels import TrustLevel

#: Trust levels an :class:`Evidence` record may hold. Evidence is by definition
#: normalised or derived from normalised evidence; an agent claim is recorded as
#: :class:`AgentClaimRecord` instead, so the two cannot be confused in a query.
EVIDENCE_LEVELS = frozenset({TrustLevel.NORMALIZED_EVIDENCE, TrustLevel.DERIVED_EVIDENCE})


def derive_independence_key(
    tool: str,
    artefact_sha256: str,
    location: str,
    observation_kind: str,
) -> str:
    """Key identifying the *underlying observation*, not the record.

    Two records sharing this key describe one thing seen once. Three parsers
    over a single Semgrep hit share a key and count as one source; treating
    them as three is the standard way these systems inflate confidence
    (ADR-016).
    """
    return stable_digest(tool, artefact_sha256, location, observation_kind)


class Evidence(DomainModel):
    """One structured, provenanced observation.

    Immutable. A correction is a new record pointing at the old one through
    `supersedes`, because an audit trail that can be edited is not one.
    """

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    investigation_id: NonEmptyStr
    artefact_id: NonEmptyStr
    artefact_sha256: Sha256

    evidence_type: EvidenceType
    observation: Observation
    location: Location
    provenance: Provenance
    """Required, with no default. This is how invariant 6 is enforced:
    evidence without provenance cannot be constructed."""

    trust_level: TrustLevel = TrustLevel.NORMALIZED_EVIDENCE
    independence_key: NonEmptyStr
    """Stored, not computed on demand, so the check cannot be forgotten by a
    caller (ADR-016)."""

    derived_from: tuple[str, ...] = ()
    """Evidence IDs this was derived from. Non-empty implies DERIVED_EVIDENCE."""

    supersedes: str | None = None
    source_reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    """Reliability of the producing tool, from the capability registry.

    A property of the tool, never of how convincing the observation reads.
    """

    created_at: datetime = TimestampField

    @model_validator(mode="after")
    def _check_trust_level(self) -> Evidence:
        if self.trust_level not in EVIDENCE_LEVELS:
            raise ValueError(
                f"Evidence must be at {sorted(level.name for level in EVIDENCE_LEVELS)}; "
                f"got {self.trust_level.name}. An agent assertion belongs in "
                f"AgentClaimRecord, which cannot satisfy a validation requirement."
            )
        if self.derived_from and self.trust_level is not TrustLevel.DERIVED_EVIDENCE:
            raise ValueError(
                "evidence with derived_from must be DERIVED_EVIDENCE, so that it is "
                "not counted as an independent source"
            )
        return self

    @model_validator(mode="after")
    def _check_observation_matches_type(self) -> Evidence:
        """The declared type and the observation must agree.

        Relevance filtering and requirement matching both key off
        `evidence_type`; if it can disagree with the payload, both silently
        operate on the wrong set.
        """
        expected = self.observation.kind
        if self.evidence_type.value != expected:
            raise ValueError(
                f"evidence_type '{self.evidence_type.value}' does not match "
                f"observation kind '{expected}'"
            )
        return self

    @property
    def is_independent_source(self) -> bool:
        """Whether this record represents a distinct underlying observation."""
        return not self.derived_from


class AgentClaimRecord(DomainModel):
    """A coding agent's assertion, kept structurally apart from evidence.

    A separate type rather than an evidence subtype, so that "give me the
    evidence" can never accidentally return one. Invariant 2 is enforced in
    three independent places - here, in the trust lattice, and in the
    validation engine - because it is the invariant most likely to be eroded
    by a convenient shortcut.
    """

    claim_id: str = Field(default_factory=lambda: new_id("ac"))
    investigation_id: NonEmptyStr
    artefact_id: NonEmptyStr
    agent: NonEmptyStr
    statement: NonEmptyStr
    location: Location | None = None
    trust_level: TrustLevel = TrustLevel.AGENT_CLAIM
    is_unverified: bool = True
    created_at: datetime = TimestampField

    @model_validator(mode="after")
    def _stays_inert(self) -> AgentClaimRecord:
        if self.trust_level is not TrustLevel.AGENT_CLAIM:
            raise ValueError("an agent claim is always at trust level AGENT_CLAIM")
        if not self.is_unverified:
            raise ValueError(
                "an agent claim is always unverified; corroboration produces separate "
                "evidence rather than upgrading the claim"
            )
        return self


class ToolFailure(DomainModel):
    """A capability that did not produce a usable result.

    Explicitly *not* evidence. A failed scan means we know less, not that we
    observed something, and an investigation that lost a tool reports PARTIAL
    rather than quietly reporting success with a smaller evidence set.
    """

    failure_id: str = Field(default_factory=lambda: new_id("tf"))
    investigation_id: NonEmptyStr
    capability_id: NonEmptyStr
    artefact_id: str | None = None
    reason: NonEmptyStr
    detail: str | None = None
    recoverable: bool = True
    occurred_at: datetime = TimestampField
