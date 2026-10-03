"""Hypotheses: testable statements, typed to a weakness class on creation.

The class is what determines which evidence is required (M10 looks the
requirement set up by it). Typing on creation is deliberate: if a model could
describe a hypothesis in free text, it would also be defining its own bar for
proof.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id, utcnow
from cyberre.core.models.enums import HypothesisStatus
from cyberre.core.trust.levels import TrustLevel


class HypothesisClass(DomainModel):
    """Which weakness a hypothesis is about.

    A pair of (taxonomy, identifier) rather than a bare string, so that
    ``CWE-78`` and an internal behaviour class such as
    ``behaviour:process_injection`` can coexist without ambiguity.
    """

    taxonomy: NonEmptyStr
    """e.g. ``cwe``, ``cve-applicability``, ``behaviour``."""

    identifier: NonEmptyStr
    """e.g. ``78``, ``CVE-2021-44228``, ``process_injection``."""

    def __str__(self) -> str:
        return f"{self.taxonomy}:{self.identifier}"


class Hypothesis(DomainModel):
    """A statement that evidence may or may not support.

    Status transitions are driven by the validation engine. A model may
    propose a hypothesis; it cannot declare one supported.
    """

    hypothesis_id: str = Field(default_factory=lambda: new_id("hy"))
    investigation_id: NonEmptyStr
    statement: NonEmptyStr
    hypothesis_class: HypothesisClass

    status: HypothesisStatus = HypothesisStatus.UNTESTED
    trust_level: TrustLevel = TrustLevel.HYPOTHESIS

    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    cites: tuple[str, ...] = ()
    """Evidence IDs the generating reasoner cited.

    A hypothesis citing nothing was invented rather than inferred, and the
    reasoner output check rejects it before it reaches this model.
    """

    unsatisfied_requirements: tuple[str, ...] = ()
    """Requirement IDs still unmet. These are the investigation's next
    information needs, which is how "what do I need to know next?" becomes
    concrete rather than aspirational."""

    created_by: NonEmptyStr
    created_at: datetime = TimestampField
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _confirmation_requires_validation(self) -> Hypothesis:
        """``CONFIRMED`` is reachable only through the validation engine.

        A hypothesis object cannot be constructed already confirmed; the
        validation engine produces a Finding, and the hypothesis is updated
        from that outcome.
        """
        if self.status is HypothesisStatus.CONFIRMED and not self.supporting_evidence:
            raise ValueError(
                "a confirmed hypothesis must reference supporting evidence; "
                "confirmation without evidence is exactly what this architecture "
                "exists to prevent"
            )
        return self

    @model_validator(mode="after")
    def _evidence_sets_are_disjoint(self) -> Hypothesis:
        overlap = set(self.supporting_evidence) & set(self.contradicting_evidence)
        if overlap:
            raise ValueError(
                f"evidence cannot both support and contradict a hypothesis: {sorted(overlap)}"
            )
        return self
