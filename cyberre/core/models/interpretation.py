"""Interpretation: what evidence might mean.

The stage between observation and hypothesis (correction section 7), and the
one most easily skipped. "Imports VirtualAllocEx" is an observation.
"VirtualAllocEx is a process-injection primitive" is an interpretation - true
of the API, and not yet a claim about this binary. Collapsing the two is how
an import list becomes a malware verdict.

An interpretation is trust level 5. It cannot satisfy a validation
requirement and it cannot become a finding; it exists to be turned into a
hypothesis that validation can then test.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id
from cyberre.core.trust.levels import TrustLevel


class Interpretation(DomainModel):
    """A possible meaning of some evidence, under some knowledge."""

    interpretation_id: str = Field(default_factory=lambda: new_id("in"))
    investigation_id: NonEmptyStr
    statement: NonEmptyStr
    """What this might mean, stated so a reader can disagree with it."""

    cites_evidence: tuple[str, ...] = Field(min_length=1)
    """Evidence IDs. An interpretation of nothing is an assertion, and the
    minimum length makes that unrepresentable."""

    cites_knowledge: tuple[str, ...] = ()
    """Knowledge record IDs, with versions, so the reasoning can be
    re-examined when a record changes."""

    suggests_hypothesis_class: str | None = None
    """The weakness class this would become, as ``taxonomy:identifier``.

    ``None`` for an interpretation that informs without proposing anything -
    recognising a compiler, for instance.
    """

    counter_explanation: str | None = None
    """The innocent reading, where the knowledge layer records one.

    Carried alongside the interpretation rather than left for the reviewer to
    recall. Most uses of most dangerous APIs are legitimate, and an
    interpretation that travels without its counter-argument is half an
    analysis.
    """

    missing_for_hypothesis: tuple[str, ...] = ()
    """What would have to also be true. These become the investigation's next
    information needs rather than being silently assumed."""

    knowledge_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    """Confidence in the *knowledge claim*, not in the conclusion.

    That a documented API does what the documentation says is near certain.
    Whether this binary is doing something wrong with it is a different
    question, answered by validation and scored by the confidence engine.
    """

    produced_by: NonEmptyStr
    """Which component drew the inference - a knowledge table or a model.
    Deterministic interpretations and model interpretations carry different
    weight downstream."""

    trust_level: TrustLevel = TrustLevel.INTERPRETATION
    created_at: datetime = TimestampField

    @model_validator(mode="after")
    def _stays_an_interpretation(self) -> Interpretation:
        if self.trust_level is not TrustLevel.INTERPRETATION:
            raise ValueError(
                "an interpretation is always at trust level INTERPRETATION; "
                "promoting it to a hypothesis creates a Hypothesis, and only "
                "validation produces a Finding"
            )
        return self

    @property
    def is_actionable(self) -> bool:
        """Whether this proposes something a hypothesis could test."""
        return self.suggests_hypothesis_class is not None
