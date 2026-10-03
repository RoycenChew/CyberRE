"""Findings and the candidate findings that precede validation.

Two distinct types, not one type with a flag. ``CandidateFinding`` is what the
reasoner produces; ``Finding`` is what the validation engine produces. Because
the report generator accepts only ``Finding``, there is no code path by which
an unvalidated conclusion reaches a report (ADR-002).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id
from cyberre.core.models.enums import (
    REPORTABLE_AS_FINDING,
    FindingStatus,
    ReviewVerdict,
    Severity,
)
from cyberre.core.models.hypothesis import HypothesisClass
from cyberre.core.models.location import Location
from cyberre.core.trust.levels import TrustLevel

#: What a reviewer verdict does to a confidence score. There is no value above
#: 1.0 anywhere in this mapping, so the reviewer cannot strengthen a finding -
#: invariant 9 holds by the shape of the type, not by instruction.
REVIEWER_MULTIPLIER: dict[ReviewVerdict, float] = {
    ReviewVerdict.UPHOLD: 1.0,
    ReviewVerdict.DOWNGRADE: 0.5,
    ReviewVerdict.REJECT: 0.0,
    ReviewVerdict.REQUEST_MORE_EVIDENCE: 0.0,
}


class ConfidenceBreakdown(DomainModel):
    """How a confidence score was arrived at.

    Stored rather than recomputed so that a finding can be explained months
    later, including under weights that have since been retuned.
    """

    factors: dict[str, float]
    weights: dict[str, float]
    base_score: float = Field(ge=0.0, le=1.0)
    completeness: float = Field(ge=0.0, le=1.0)
    reviewer_multiplier: float = Field(ge=0.0, le=1.0)
    validation_gate: float = Field(ge=0.0, le=1.0)
    final_score: float = Field(ge=0.0, le=1.0)
    formula_version: NonEmptyStr

    @model_validator(mode="after")
    def _final_score_respects_the_cap(self) -> ConfidenceBreakdown:
        """Confidence may never exceed evidence completeness.

        The cap is the anti-overclaim lever: a finding with two of five
        required evidence kinds cannot score above 0.4 however persuasive the
        reasoning was.
        """
        capped = min(self.base_score, self.completeness)
        expected = capped * self.reviewer_multiplier * self.validation_gate
        if abs(self.final_score - expected) > 1e-9:
            raise ValueError(
                f"final_score {self.final_score} does not equal "
                f"min(base, completeness) * reviewer * gate = {expected}"
            )
        return self


class ReviewResult(DomainModel):
    """The adversarial reviewer's attempt to disprove a finding."""

    review_id: str = Field(default_factory=lambda: new_id("rv"))
    verdict: ReviewVerdict
    rationale: NonEmptyStr
    cited_evidence: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    alternative_explanation: str | None = None
    reviewed_at: datetime = TimestampField

    @property
    def multiplier(self) -> float:
        return REVIEWER_MULTIPLIER[self.verdict]


class CandidateFinding(DomainModel):
    """A reasoner's proposal, before validation.

    Deliberately has no severity and no confidence. It cannot be rendered into
    a report, so the demonstration path is structurally unavailable until the
    validation engine exists to reject things (ADR-002).
    """

    candidate_id: str = Field(default_factory=lambda: new_id("cf"))
    investigation_id: NonEmptyStr
    hypothesis_id: NonEmptyStr
    title: NonEmptyStr
    description: NonEmptyStr
    cited_evidence: tuple[str, ...] = Field(min_length=1)
    """At least one evidence ID. A candidate citing nothing is an assertion,
    and assertions do not enter the pipeline."""

    trust_level: TrustLevel = TrustLevel.INTERPRETATION
    created_at: datetime = TimestampField


class Finding(DomainModel):
    """The output of validation: an outcome with its reason and its evidence.

    Note that most statuses are *negative* outcomes. ``NOT_ENOUGH_EVIDENCE``
    and ``UNREACHABLE`` are successful conclusions, and carry no severity -
    uncertainty is never expressed as a severity (invariant 10).
    """

    finding_id: str = Field(default_factory=lambda: new_id("fi"))
    investigation_id: NonEmptyStr
    hypothesis_id: NonEmptyStr

    title: NonEmptyStr
    description: NonEmptyStr
    status: FindingStatus
    severity: Severity | None = None
    confidence: ConfidenceBreakdown | None = None

    evidence_ids: tuple[str, ...] = ()
    affected_components: tuple[str, ...] = ()
    locations: tuple[Location, ...] = ()

    hypothesis_class: HypothesisClass
    cwe: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()

    impact: str | None = None
    remediation: str | None = None
    validation_plan: str | None = None
    """What would settle an unresolved question. The most useful content of a
    NOT_ENOUGH_EVIDENCE finding."""

    unsatisfied_requirements: tuple[str, ...] = ()
    review: ReviewResult | None = None
    trust_level: TrustLevel = TrustLevel.VALIDATED_FINDING
    created_at: datetime = TimestampField

    @model_validator(mode="after")
    def _validated_findings_are_evidenced(self) -> Finding:
        """A validated finding must cite evidence and carry a confidence score.

        Invariant 1, at the data layer: there is no way to represent "validated,
        but we are not saying why".
        """
        if self.status in REPORTABLE_AS_FINDING:
            if not self.evidence_ids:
                raise ValueError("a validated finding must reference evidence")
            if self.confidence is None:
                raise ValueError("a validated finding must carry a confidence breakdown")
        return self

    @model_validator(mode="after")
    def _only_validated_findings_carry_severity(self) -> Finding:
        """Uncertainty is not a severity (invariant 10)."""
        if self.severity is not None and self.status not in REPORTABLE_AS_FINDING:
            raise ValueError(
                f"status '{self.status.value}' must not carry a severity; "
                f"an unresolved outcome reports its reason, not an impact rating"
            )
        return self

    @model_validator(mode="after")
    def _rejected_review_cannot_leave_a_validated_finding(self) -> Finding:
        """The reviewer can only weaken (invariant 9)."""
        if (
            self.review is not None
            and self.review.verdict is ReviewVerdict.REJECT
            and self.status in REPORTABLE_AS_FINDING
        ):
            raise ValueError(
                "a finding rejected by the adversarial reviewer cannot remain validated"
            )
        return self

    @property
    def is_reportable(self) -> bool:
        """Whether this may be presented as an established finding."""
        return self.status in REPORTABLE_AS_FINDING
