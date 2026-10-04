"""Assembling a finding from validation, review and confidence.

The last gate. Everything upstream produces inputs; this decides what the
finding's status actually is, and it resolves the one case where the three
can disagree: validation says the requirements are met, the reviewer says
otherwise.

The reviewer wins when it weakens. That asymmetry is the point - validation
asks "is there enough?", review asks "is it wrong?", and a yes to the second
beats a yes to the first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from cyberre.core.findings.confidence import ConfidenceEngine
from cyberre.core.findings.validation import ValidationOutcome
from cyberre.core.models.enums import FindingStatus, ReviewVerdict, Severity
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.finding import CandidateFinding, Finding, ReviewResult
from cyberre.core.models.hypothesis import HypothesisClass
from cyberre.core.models.location import Location

#: Severity by weakness class. A starting point tied to the class, not to
#: how the finding reads - CVSS scoring from validated evidence is a later
#: refinement, and guessing in the meantime would be worse than a documented
#: default.
DEFAULT_SEVERITY: dict[str, Severity] = {
    "cwe:78": Severity.HIGH,
    "cwe:89": Severity.HIGH,
    "cwe:22": Severity.MEDIUM,
    "cwe:502": Severity.HIGH,
    "cwe:787": Severity.HIGH,
    "cwe:798": Severity.HIGH,
    "cve:applicability": Severity.MEDIUM,
    "behaviour:process_injection": Severity.HIGH,
    "behaviour:persistence": Severity.MEDIUM,
    "behaviour:credential_access": Severity.HIGH,
    "behaviour:anti_analysis": Severity.LOW,
    "behaviour:dynamic_resolution": Severity.LOW,
    "behaviour:packing": Severity.INFORMATIONAL,
}


def resolve_status(
    outcome: ValidationOutcome,
    review: ReviewResult | None,
    *,
    confidence: float,
    needs_review_below: float,
) -> FindingStatus:
    """The final status.

    Order matters, and it is deliberately pessimistic:

    1. A rejecting reviewer overrides validation outright.
    2. A reviewer asking for more evidence turns a validated finding into
       NOT_ENOUGH_EVIDENCE - it has not been disproven, but it has not
       survived review either.
    3. A downgrade or a low score holds the finding for a human.
    4. Only then can it be VALIDATED.

    A non-validated outcome keeps its own status throughout: UNREACHABLE and
    NOT_APPLICABLE are answers, and review does not improve them.
    """
    if outcome.status is not FindingStatus.VALIDATED:
        return outcome.status

    if review is not None:
        if review.verdict is ReviewVerdict.REJECT:
            return FindingStatus.CONTRADICTED
        if review.verdict is ReviewVerdict.REQUEST_MORE_EVIDENCE:
            return FindingStatus.NOT_ENOUGH_EVIDENCE
        if review.verdict is ReviewVerdict.DOWNGRADE:
            return FindingStatus.NEEDS_REVIEW

    if confidence < needs_review_below:
        return FindingStatus.NEEDS_REVIEW

    return FindingStatus.VALIDATED


def assemble(
    candidate: CandidateFinding,
    outcome: ValidationOutcome,
    hypothesis_class: HypothesisClass,
    *,
    evidence: Mapping[str, Evidence],
    confidence_engine: ConfidenceEngine,
    review: ReviewResult | None = None,
    contradictions: int = 0,
    locations: Sequence[Location] = (),
    remediation: str | None = None,
) -> Finding:
    """Build the finding.

    Severity is attached only to a validated finding. Every other status
    carries its reason and no severity, because uncertainty is not an impact
    rating (invariant 10) - and the Finding model refuses the combination
    anyway, so this is belt and braces on a rule that matters.
    """
    breakdown = confidence_engine.score(
        outcome, evidence=evidence, review=review, contradictions=contradictions
    )

    status = resolve_status(
        outcome,
        review,
        confidence=breakdown.final_score,
        needs_review_below=confidence_engine.config.needs_review_below,
    )

    is_validated = status is FindingStatus.VALIDATED
    class_key = str(hypothesis_class)

    return Finding(
        investigation_id=candidate.investigation_id,
        hypothesis_id=candidate.hypothesis_id,
        title=candidate.title,
        description=candidate.description,
        status=status,
        severity=DEFAULT_SEVERITY.get(class_key) if is_validated else None,
        confidence=breakdown if is_validated else None,
        evidence_ids=outcome.satisfied_evidence_ids,
        hypothesis_class=hypothesis_class,
        cwe=(hypothesis_class.identifier,) if hypothesis_class.taxonomy == "cwe" else (),
        locations=tuple(locations),
        remediation=remediation,
        validation_plan=_validation_plan(outcome, review),
        unsatisfied_requirements=outcome.unsatisfied,
        review=review,
    )


def _validation_plan(outcome: ValidationOutcome, review: ReviewResult | None) -> str | None:
    """What would settle an unresolved question.

    The most useful content of a negative finding. An analyst reading
    NOT_ENOUGH_EVIDENCE wants to know what to go and check, not to be told
    again that we were unsure.
    """
    wanted: list[str] = []
    for result in outcome.results:
        if not result.satisfied:
            wanted.append(result.description)
    if review is not None:
        wanted.extend(review.missing_evidence)

    if not wanted:
        return None
    return "Establish: " + "; ".join(dict.fromkeys(wanted))
