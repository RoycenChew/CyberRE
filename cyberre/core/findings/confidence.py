"""The confidence engine.

Every number CyberRE attaches to a finding is computed here from evidence
and validation. A model never emits one, because a model asked for a
confidence will produce one that tracks how persuasive its own prose reads
rather than how much evidence exists (ADR-009).

Two multiplications carry most of the weight:

    confidence = min(base, completeness) x reviewer x validation_gate

`min(base, completeness)` caps confidence at how much of the requirement set
was actually established - a finding with two of five requirements cannot
score above 0.4 however compelling the reasoning.

`validation_gate` is 1.0 only for a validated finding, so an unvalidated
hypothesis scores exactly zero. That is invariant 1 expressed as arithmetic
rather than as a rule someone has to remember.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path

from cyberre.core.findings.validation import ValidationOutcome
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import FindingStatus, ReviewVerdict
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.finding import REVIEWER_MULTIPLIER, ConfidenceBreakdown, ReviewResult

DEFAULT_CONFIG_PATH = Path("config") / "confidence.toml"

#: Fallback weights, used when no configuration file is present. Kept in
#: sync with config/confidence.toml by a test, so the two cannot drift into
#: scoring the same finding differently.
FALLBACK_WEIGHTS: dict[str, float] = {
    "evidence_completeness": 0.30,
    "evidence_independence": 0.20,
    "tool_reliability": 0.15,
    "source_corroboration": 0.10,
    "reachability_established": 0.15,
    "provenance_quality": 0.10,
}


class ConfidenceConfig(DomainModel):
    """Weights and thresholds, versioned."""

    version: NonEmptyStr = "v1"
    weights: dict[str, float] = FALLBACK_WEIGHTS
    needs_review_below: float = 0.45
    contradiction_penalty: float = 0.25
    contradiction_floor: float = 0.1
    corroboration_saturation: int = 3

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> ConfidenceConfig:
        """Load from TOML, falling back to the defaults if absent.

        A missing file is not an error: the fallback is the same scoring, so
        a deployment without the file is not silently scored differently.
        """
        if not path.is_file():
            return cls()
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        thresholds = document.get("thresholds", {})
        return cls(
            version=str(document.get("version", "v1")),
            weights={str(k): float(v) for k, v in document.get("weights", {}).items()},
            needs_review_below=float(thresholds.get("needs_review_below", 0.45)),
            contradiction_penalty=float(thresholds.get("contradiction_penalty", 0.25)),
            contradiction_floor=float(thresholds.get("contradiction_floor", 0.1)),
            corroboration_saturation=int(thresholds.get("corroboration_saturation", 3)),
        )

    def normalised_weights(self) -> dict[str, float]:
        """Weights scaled to sum to 1.

        Normalising rather than validating: a deployment that retunes one
        weight should not have to rebalance the rest by hand, and a set that
        happens to sum to 1.1 should not silently produce scores above 1.
        """
        total = sum(self.weights.values())
        if total <= 0:
            raise ValueError("confidence weights must sum to more than zero")
        return {name: value / total for name, value in self.weights.items()}


def _corroboration(independent_sources: int, saturation: int) -> float:
    """How much independent agreement there is, saturating.

    The third corroborating source adds much less than the second: at some
    point more tools saying the same thing stops being informative, and a
    linear factor would keep rewarding it.
    """
    if independent_sources <= 0:
        return 0.0
    return min(1.0, independent_sources / max(1, saturation))


def _tool_reliability(evidence: Sequence[Evidence]) -> float:
    """Mean reliability of the tools behind the satisfied requirements."""
    if not evidence:
        return 0.0
    return sum(item.source_reliability for item in evidence) / len(evidence)


def _provenance_quality(evidence: Sequence[Evidence]) -> float:
    """How well the evidence can be re-examined later.

    Complete provenance means a tool version and either a ruleset version or
    a reference to the raw output. Evidence that cannot be traced back is
    still evidence; it is just worth less when the question is whether a
    finding will stand up six months from now.
    """
    if not evidence:
        return 0.0
    scored = 0.0
    for item in evidence:
        tool = item.provenance.tool
        points = 0.0
        if tool.tool_version:
            points += 0.5
        if tool.ruleset_version or tool.script_version or tool.config_hash:
            points += 0.25
        if item.provenance.raw_output_ref:
            points += 0.25
        scored += points
    return scored / len(evidence)


def _independence(independent_sources: int, used_evidence: int) -> float:
    """Distinct observations as a fraction of records used.

    One analysis establishing four facts scores lower than four analyses
    agreeing, which is the distinction M10 reports and this consumes.
    """
    if used_evidence <= 0:
        return 0.0
    return min(1.0, independent_sources / used_evidence)


def _reachability(outcome: ValidationOutcome) -> float:
    """Whether a reachability requirement was satisfied.

    Binary rather than graded. Either a path from an entry point was
    established or it was not, and a partial credit here would let the most
    common false-positive cause be papered over.
    """
    reachability_results = [
        result for result in outcome.results if result.requirement_id.endswith(".reachable")
    ]
    if not reachability_results:
        # The class has no reachability requirement - an embedded credential,
        # say - so its absence is not a deficiency.
        return 1.0
    return 1.0 if all(r.satisfied for r in reachability_results) else 0.0


class ConfidenceEngine:
    """Computes a confidence score from validation and evidence."""

    def __init__(self, config: ConfidenceConfig | None = None) -> None:
        self._config = config if config is not None else ConfidenceConfig()

    @property
    def config(self) -> ConfidenceConfig:
        return self._config

    def score(
        self,
        outcome: ValidationOutcome,
        *,
        evidence: Mapping[str, Evidence],
        review: ReviewResult | None = None,
        contradictions: int = 0,
    ) -> ConfidenceBreakdown:
        """Score a validated outcome.

        An unvalidated outcome scores zero through `validation_gate` rather
        than by being refused here, so a caller can ask "how close is this?"
        without the engine pretending the answer is a finding.
        """
        used = [evidence[eid] for eid in outcome.satisfied_evidence_ids if eid in evidence]

        factors = {
            "evidence_completeness": outcome.completeness,
            "evidence_independence": _independence(outcome.independent_source_count, len(used)),
            "tool_reliability": _tool_reliability(used),
            "source_corroboration": _corroboration(
                outcome.independent_source_count, self._config.corroboration_saturation
            ),
            "reachability_established": _reachability(outcome),
            "provenance_quality": _provenance_quality(used),
        }

        weights = self._config.normalised_weights()
        base = sum(weights.get(name, 0.0) * value for name, value in factors.items())
        base = self._apply_contradictions(base, contradictions)

        reviewer_multiplier = (
            review.multiplier if review is not None else REVIEWER_MULTIPLIER[ReviewVerdict.UPHOLD]
        )
        validation_gate = 1.0 if outcome.status is FindingStatus.VALIDATED else 0.0

        # Round first, then derive. ConfidenceBreakdown re-checks that
        # final_score equals min(base, completeness) x reviewer x gate from
        # the stored fields, so computing the score from unrounded values
        # and storing rounded ones would fail that check on some inputs -
        # and the check is worth more than the sixth decimal place.
        rounded_base = round(base, 6)
        rounded_completeness = round(outcome.completeness, 6)
        final = min(rounded_base, rounded_completeness) * reviewer_multiplier * validation_gate

        return ConfidenceBreakdown(
            factors={name: round(value, 6) for name, value in factors.items()},
            weights={name: round(value, 6) for name, value in weights.items()},
            base_score=rounded_base,
            completeness=rounded_completeness,
            reviewer_multiplier=reviewer_multiplier,
            validation_gate=validation_gate,
            final_score=final,
            formula_version=self._config.version,
        )

    def _apply_contradictions(self, base: float, contradictions: int) -> float:
        """Subtract for contradicting evidence, down to a floor.

        A floor rather than zero, because contradicted evidence does not
        make the supporting evidence vanish. The reviewer and the status
        carry that judgement; this only reflects that agreement is weaker.
        """
        if contradictions <= 0:
            return base
        penalty = self._config.contradiction_penalty * contradictions
        return max(self._config.contradiction_floor, base - penalty)

    def needs_human_review(self, breakdown: ConfidenceBreakdown) -> bool:
        """Whether a finding should be held rather than reported.

        A low-confidence finding that reaches a report costs an analyst more
        time than one that is withheld with its reasoning attached.
        """
        return breakdown.final_score < self._config.needs_review_below
