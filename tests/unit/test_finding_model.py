"""Findings, candidates and confidence.

These tests encode the three claims the architecture most needs to be true:
an unvalidated conclusion cannot reach a report, uncertainty is not a severity,
and the reviewer can only weaken a finding.
"""

from __future__ import annotations

import pytest
from cyberre.core.models.enums import FindingStatus, ReviewVerdict, Severity
from cyberre.core.models.finding import (
    REVIEWER_MULTIPLIER,
    CandidateFinding,
    ConfidenceBreakdown,
    Finding,
    ReviewResult,
)
from cyberre.core.models.hypothesis import HypothesisClass
from pydantic import ValidationError

pytestmark = pytest.mark.unit


def breakdown(
    *,
    base: float = 0.9,
    completeness: float = 1.0,
    reviewer: float = 1.0,
    gate: float = 1.0,
) -> ConfidenceBreakdown:
    return ConfidenceBreakdown(
        factors={"evidence_completeness": completeness},
        weights={"evidence_completeness": 1.0},
        base_score=base,
        completeness=completeness,
        reviewer_multiplier=reviewer,
        validation_gate=gate,
        final_score=min(base, completeness) * reviewer * gate,
        formula_version="v1",
    )


def finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "investigation_id": "inv-1",
        "hypothesis_id": "hy-1",
        "title": "Command injection in request handler",
        "description": "User input reaches subprocess without sanitisation.",
        "status": FindingStatus.VALIDATED,
        "hypothesis_class": HypothesisClass(taxonomy="cwe", identifier="78"),
        "evidence_ids": ("ev-1", "ev-2"),
        "confidence": breakdown(),
    }
    return Finding(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestInvariant1ValidatedFindingsAreEvidenced:
    def test_validated_finding_requires_evidence(self) -> None:
        with pytest.raises(ValidationError, match="must reference evidence"):
            finding(evidence_ids=())

    def test_validated_finding_requires_a_confidence_breakdown(self) -> None:
        with pytest.raises(ValidationError, match="confidence breakdown"):
            finding(confidence=None)

    def test_a_candidate_must_cite_evidence(self) -> None:
        """A candidate citing nothing is an assertion, not an inference."""
        with pytest.raises(ValidationError):
            CandidateFinding(
                investigation_id="inv-1",
                hypothesis_id="hy-1",
                title="Something",
                description="Looks bad",
                cited_evidence=(),
            )


class TestInvariant10UnknownIsNotASeverity:
    @pytest.mark.parametrize(
        "status",
        [
            FindingStatus.NOT_ENOUGH_EVIDENCE,
            FindingStatus.UNREACHABLE,
            FindingStatus.NOT_APPLICABLE,
            FindingStatus.CONTRADICTED,
            FindingStatus.UNVALIDATED,
            FindingStatus.NEEDS_REVIEW,
        ],
    )
    def test_non_validated_outcomes_cannot_carry_severity(self, status: FindingStatus) -> None:
        with pytest.raises(ValidationError, match="must not carry a severity"):
            finding(
                status=status,
                severity=Severity.HIGH,
                evidence_ids=(),
                confidence=None,
            )

    def test_unknown_outcomes_are_constructible_and_carry_their_reason(self) -> None:
        result = finding(
            status=FindingStatus.UNREACHABLE,
            severity=None,
            confidence=None,
            evidence_ids=("ev-9",),
            validation_plan="Confirm no entry point reaches handler() after the refactor.",
        )
        assert result.is_reportable is False
        assert result.validation_plan is not None

    def test_only_validated_findings_are_reportable(self) -> None:
        assert finding().is_reportable is True
        assert (
            finding(
                status=FindingStatus.NOT_ENOUGH_EVIDENCE, confidence=None, evidence_ids=()
            ).is_reportable
            is False
        )


class TestInvariant9ReviewerCannotStrengthen:
    def test_no_verdict_multiplies_above_one(self) -> None:
        assert max(REVIEWER_MULTIPLIER.values()) == 1.0

    def test_every_verdict_has_a_multiplier(self) -> None:
        assert set(REVIEWER_MULTIPLIER) == set(ReviewVerdict)

    def test_rejected_finding_cannot_remain_validated(self) -> None:
        review = ReviewResult(
            verdict=ReviewVerdict.REJECT,
            rationale="The sink is parameterised; the input never reaches a shell.",
        )
        with pytest.raises(ValidationError, match="cannot remain validated"):
            finding(review=review)

    def test_rejected_finding_is_representable_as_a_negative_outcome(self) -> None:
        review = ReviewResult(
            verdict=ReviewVerdict.REJECT,
            rationale="Parameterised query; not injectable.",
        )
        result = finding(
            status=FindingStatus.CONTRADICTED,
            review=review,
            confidence=None,
            evidence_ids=("ev-1",),
        )
        assert result.review is not None
        assert result.review.multiplier == 0.0


class TestConfidenceCap:
    def test_confidence_cannot_exceed_completeness(self) -> None:
        """Two of five required evidence kinds cannot score 0.9."""
        with pytest.raises(ValidationError, match="does not equal"):
            ConfidenceBreakdown(
                factors={},
                weights={},
                base_score=0.9,
                completeness=0.4,
                reviewer_multiplier=1.0,
                validation_gate=1.0,
                final_score=0.9,
                formula_version="v1",
            )

    def test_the_cap_is_applied(self) -> None:
        capped = breakdown(base=0.9, completeness=0.4)
        assert capped.final_score == pytest.approx(0.4)

    def test_an_unvalidated_hypothesis_scores_zero(self) -> None:
        """validation_gate makes invariant 1 arithmetic."""
        assert breakdown(base=1.0, completeness=1.0, gate=0.0).final_score == 0.0

    def test_a_downgrade_halves_the_score(self) -> None:
        assert breakdown(base=0.8, completeness=0.8, reviewer=0.5).final_score == pytest.approx(0.4)


class TestCandidateCannotMasqueradeAsAFinding:
    def test_candidate_is_a_different_type(self) -> None:
        candidate = CandidateFinding(
            investigation_id="inv-1",
            hypothesis_id="hy-1",
            title="Possible injection",
            description="Pattern matched.",
            cited_evidence=("ev-1",),
        )
        assert not isinstance(candidate, Finding)

    def test_candidate_has_no_severity_or_confidence_fields(self) -> None:
        assert "severity" not in CandidateFinding.model_fields
        assert "confidence" not in CandidateFinding.model_fields


class TestRoundTrip:
    def test_finding_survives_serialisation(self) -> None:
        original = finding()
        assert Finding.model_validate_json(original.model_dump_json()) == original
