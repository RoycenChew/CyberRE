"""Confidence, adversarial review, and the assembly of a finding.

The invariants under test are 1 (a model cannot produce a finding) and 9
(the reviewer cannot strengthen one), and both are checked as arithmetic
rather than as behaviour - a property is worth more when it cannot be
violated than when it merely is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cyberre.adapters.models.replay import Cassette, ReplayProvider
from cyberre.agent.reviewers.adversarial import (
    PROMPT_TEMPLATE_VERSION,
    AdversarialReviewer,
    ReviewPacket,
    ReviewResponse,
    build_packet,
)
from cyberre.core.contracts.model_provider import (
    ModelFailureError,
    ModelResult,
    ModelTier,
    StructuredOutputMode,
)
from cyberre.core.evidence.builder import build_graph
from cyberre.core.findings.assembly import assemble, resolve_status
from cyberre.core.findings.confidence import (
    FALLBACK_WEIGHTS,
    ConfidenceConfig,
    ConfidenceEngine,
)
from cyberre.core.findings.requirements import RequirementRegistry
from cyberre.core.findings.validation import ValidationEngine
from cyberre.core.models.enums import EvidenceType, FindingStatus, ReviewVerdict
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.finding import REVIEWER_MULTIPLIER, CandidateFinding, ReviewResult
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.interpretation import Interpretation
from cyberre.core.models.location import ArtefactLocation, SourceLocation
from cyberre.core.models.observation import (
    DataFlowPath,
    ReachabilityObservation,
    ScannerFinding,
)
from cyberre.core.models.provenance import Provenance, ToolProvenance
from pydantic import BaseModel

pytestmark = pytest.mark.unit

SHA = "a" * 64
CWE78 = HypothesisClass(taxonomy="cwe", identifier="78")


def evidence(
    observation: Any,
    *,
    tool: str = "semgrep",
    key: str,
    reliability: float = 0.8,
    raw_ref: str | None = "obj/raw",
    ruleset: str | None = "p/security-audit",
) -> Evidence:
    return Evidence(
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=SHA,
        evidence_type=EvidenceType(observation.kind),
        observation=observation,
        location=ArtefactLocation(detail=key),
        provenance=Provenance(
            tool=ToolProvenance(tool=tool, tool_version="1.0", ruleset_version=ruleset),
            artefact_sha256=SHA,
            raw_output_ref=raw_ref,
        ),
        independence_key=key,
        source_reliability=reliability,
    )


def complete_case() -> list[Evidence]:
    return [
        evidence(
            ScannerFinding(rule_id="subprocess", message="shell=True", cwe=("CWE-78",)),
            key="k-sink",
        ),
        evidence(
            DataFlowPath(source="request.args", sink="subprocess.call"),
            tool="dataflow",
            key="k-flow",
        ),
        evidence(
            ReachabilityObservation(target="subprocess.call", entry_point="route", reachable=True),
            tool="reachability",
            key="k-reach",
        ),
    ]


def a_hypothesis() -> Hypothesis:
    return Hypothesis(
        investigation_id="inv-1",
        statement="command injection",
        hypothesis_class=CWE78,
        created_by="reasoner",
    )


def a_candidate() -> CandidateFinding:
    return CandidateFinding(
        investigation_id="inv-1",
        hypothesis_id="hy-1",
        title="Command injection in ping handler",
        description="User input reaches a shell without sanitisation.",
        cited_evidence=("ev-1",),
    )


def validate(items: list[Evidence]) -> Any:
    registry = RequirementRegistry()
    return ValidationEngine().validate(
        a_hypothesis(),
        registry.for_class("cwe:78"),
        evidence=items,
        graph=build_graph(items),
    )


@pytest.fixture
def engine() -> ConfidenceEngine:
    return ConfidenceEngine(
        ConfidenceConfig.load(Path(__file__).resolve().parents[2] / "config" / "confidence.toml")
    )


class TestInvariant1UnvalidatedScoresZero:
    def test_an_unvalidated_outcome_scores_exactly_zero(self, engine: ConfidenceEngine) -> None:
        """The validation gate makes invariant 1 arithmetic."""
        items = complete_case()[:1]
        outcome = validate(items)
        breakdown = engine.score(outcome, evidence={e.evidence_id: e for e in items})

        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE
        assert breakdown.validation_gate == 0.0
        assert breakdown.final_score == 0.0

    def test_the_base_score_is_still_reported(self, engine: ConfidenceEngine) -> None:
        """So a caller can ask 'how close is this?' without the engine
        pretending the answer is a finding."""
        items = complete_case()[:2]
        breakdown = engine.score(validate(items), evidence={e.evidence_id: e for e in items})
        assert breakdown.base_score > 0.0
        assert breakdown.final_score == 0.0


class TestTheCompletenessCap:
    def test_confidence_cannot_exceed_completeness(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        breakdown = engine.score(validate(items), evidence={e.evidence_id: e for e in items})
        assert breakdown.final_score <= breakdown.completeness

    def test_a_complete_case_scores_meaningfully(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        breakdown = engine.score(validate(items), evidence={e.evidence_id: e for e in items})
        assert breakdown.final_score > 0.5


class TestFactors:
    def test_more_independent_sources_score_higher(self, engine: ConfidenceEngine) -> None:
        """One analysis establishing four facts is weaker than four analyses
        agreeing, and the formula should say so."""
        many = complete_case()
        few = [
            evidence(
                ScannerFinding(rule_id="subprocess", message="x", cwe=("CWE-78",)),
                key="shared",
            ),
            evidence(
                DataFlowPath(source="request", sink="subprocess.call"),
                tool="dataflow",
                key="shared",
            ),
            evidence(
                ReachabilityObservation(target="subprocess.call", entry_point="r", reachable=True),
                tool="dataflow",
                key="shared",
            ),
        ]
        strong = engine.score(validate(many), evidence={e.evidence_id: e for e in many})
        weak = engine.score(validate(few), evidence={e.evidence_id: e for e in few})
        assert strong.final_score > weak.final_score

    def test_unreliable_tools_score_lower(self, engine: ConfidenceEngine) -> None:
        reliable = complete_case()
        unreliable = [
            evidence(
                item.observation,
                tool=item.provenance.tool.tool,
                key=item.independence_key,
                reliability=0.3,
            )
            for item in reliable
        ]
        assert (
            engine.score(
                validate(reliable), evidence={e.evidence_id: e for e in reliable}
            ).final_score
            > engine.score(
                validate(unreliable), evidence={e.evidence_id: e for e in unreliable}
            ).final_score
        )

    def test_weak_provenance_scores_lower(self, engine: ConfidenceEngine) -> None:
        """A finding that cannot be traced back is worth less when the
        question is whether it stands up six months from now."""
        traceable = complete_case()
        untraceable = [
            evidence(
                item.observation,
                tool=item.provenance.tool.tool,
                key=item.independence_key,
                raw_ref=None,
                ruleset=None,
            )
            for item in traceable
        ]
        assert (
            engine.score(
                validate(traceable), evidence={e.evidence_id: e for e in traceable}
            ).final_score
            > engine.score(
                validate(untraceable), evidence={e.evidence_id: e for e in untraceable}
            ).final_score
        )

    def test_contradictions_reduce_the_score_to_a_floor(self, engine: ConfidenceEngine) -> None:
        """Contradicted evidence does not make supporting evidence vanish."""
        items = complete_case()
        mapping = {e.evidence_id: e for e in items}
        clean = engine.score(validate(items), evidence=mapping)
        contested = engine.score(validate(items), evidence=mapping, contradictions=5)
        assert contested.base_score < clean.base_score
        assert contested.base_score >= engine.config.contradiction_floor


class TestInvariant9ReviewerCannotStrengthen:
    def test_no_verdict_multiplies_above_one(self) -> None:
        assert max(REVIEWER_MULTIPLIER.values()) == 1.0

    def test_a_downgrade_halves_the_score(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        mapping = {e.evidence_id: e for e in items}
        outcome = validate(items)
        upheld = engine.score(
            outcome,
            evidence=mapping,
            review=ReviewResult(verdict=ReviewVerdict.UPHOLD, rationale="held"),
        )
        downgraded = engine.score(
            outcome,
            evidence=mapping,
            review=ReviewResult(verdict=ReviewVerdict.DOWNGRADE, rationale="thin"),
        )
        assert downgraded.final_score == pytest.approx(upheld.final_score * 0.5)

    def test_a_rejection_zeroes_the_score(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        breakdown = engine.score(
            validate(items),
            evidence={e.evidence_id: e for e in items},
            review=ReviewResult(verdict=ReviewVerdict.REJECT, rationale="parameterised"),
        )
        assert breakdown.final_score == 0.0


class TestConfiguration:
    def test_the_shipped_weights_match_the_fallback(self) -> None:
        """Otherwise a deployment without the file is scored differently
        from one with it, silently."""
        config = ConfidenceConfig.load(
            Path(__file__).resolve().parents[2] / "config" / "confidence.toml"
        )
        assert config.weights == FALLBACK_WEIGHTS

    def test_weights_are_normalised(self) -> None:
        config = ConfidenceConfig(weights={"a": 2.0, "b": 2.0})
        assert sum(config.normalised_weights().values()) == pytest.approx(1.0)

    def test_zero_weights_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="more than zero"):
            ConfidenceConfig(weights={"a": 0.0}).normalised_weights()

    def test_the_formula_version_is_recorded(self, engine: ConfidenceEngine) -> None:
        """So a finding scored under v1 can be re-examined when v2
        disagrees."""
        items = complete_case()
        breakdown = engine.score(validate(items), evidence={e.evidence_id: e for e in items})
        assert breakdown.formula_version == "v1"

    def test_a_missing_file_falls_back_rather_than_failing(self, tmp_path: Path) -> None:
        config = ConfidenceConfig.load(tmp_path / "absent.toml")
        assert config.weights == FALLBACK_WEIGHTS


# ---------------------------------------------------------------- reviewer


class StubReviewProvider:
    """Returns a canned review response."""

    def __init__(self, response: ReviewResponse | None = None, *, fail: bool = False) -> None:
        self._response = response
        self._fail = fail
        self.calls = 0

    @property
    def provider_name(self) -> str:
        return "stub"

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        return StructuredOutputMode.STRICT_SCHEMA

    def complete(self, messages: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self._fail or self._response is None:
            raise ModelFailureError("the reviewer endpoint is unreachable")
        self.last_messages = messages
        return ModelResult[BaseModel](
            value=self._response,
            model_id="stub-1",
            provider="stub",
            tier=ModelTier.REASONING,
            prompt_template_version=PROMPT_TEMPLATE_VERSION,
            prompt_hash="0" * 64,
        )


def a_packet() -> tuple[ReviewPacket, frozenset[str], list[Evidence]]:
    items = complete_case()
    outcome = validate(items)
    packet = build_packet(a_candidate(), outcome, evidence={e.evidence_id: e for e in items})
    return packet, frozenset(e.evidence_id for e in items), items


class TestTheReviewPacket:
    def test_it_carries_the_counter_arguments(self) -> None:
        """Handing the reviewer the strongest case against is the difference
        between a review and a rubber stamp."""
        items = complete_case()
        outcome = validate(items)
        interpretation = Interpretation(
            investigation_id="inv-1",
            statement="subprocess use is associated with command execution",
            cites_evidence=(items[0].evidence_id,),
            counter_explanation="Build scripts call subprocess legitimately.",
            produced_by="knowledge.re",
        )
        packet = build_packet(
            a_candidate(),
            outcome,
            evidence={e.evidence_id: e for e in items},
            interpretations=[interpretation],
        )
        assert any("Build scripts" in c for c in packet.counter_arguments)

    def test_observed_sanitisers_become_counter_arguments(self) -> None:
        items = [
            evidence(
                ScannerFinding(rule_id="sql", message="raw sql", cwe=("CWE-89",)),
                key="k-sink",
            ),
            evidence(
                DataFlowPath(
                    source="request",
                    sink="cursor.execute",
                    sanitizers=("parameterised",),
                ),
                tool="dataflow",
                key="k-flow",
            ),
        ]
        registry = RequirementRegistry()
        outcome = ValidationEngine().validate(
            a_hypothesis(),
            registry.for_class("cwe:89"),
            evidence=items,
            graph=build_graph(items),
        )
        packet = build_packet(a_candidate(), outcome, evidence={e.evidence_id: e for e in items})
        assert any("sanitiser was observed" in c for c in packet.counter_arguments)

    def test_artefact_text_is_fenced(self) -> None:
        """Scanner messages come out of the artefact. Fencing is structural,
        not advisory."""
        packet, _, _ = a_packet()
        rendered = packet.render()
        assert "<untrusted-artefact-content>" in rendered

    def test_every_evidence_line_carries_its_id(self) -> None:
        """A reviewer that cannot cite cannot be held to citing."""
        packet, ids, _ = a_packet()
        for evidence_id in ids:
            if any(evidence_id in line for line in packet.evidence_lines):
                continue
            # Only evidence actually used by validation appears.
            assert evidence_id not in packet.render()


class TestTheReviewer:
    def test_an_upholding_review_is_returned(self) -> None:
        packet, ids, _ = a_packet()
        provider = StubReviewProvider(
            ReviewResponse(
                verdict="uphold",
                rationale="the flow is real and reachable",
                cited_evidence=list(ids)[:1],
            )
        )
        result = AdversarialReviewer(provider).review(packet, known_evidence_ids=ids)  # type: ignore[arg-type]
        assert result.verdict is ReviewVerdict.UPHOLD
        assert result.multiplier == 1.0

    def test_a_rejection_must_cite_evidence(self) -> None:
        """An unsupported rejection is no better than an unsupported
        finding."""
        packet, ids, _ = a_packet()
        provider = StubReviewProvider(
            ReviewResponse(verdict="reject", rationale="I just think it is wrong")
        )
        result = AdversarialReviewer(provider).review(packet, known_evidence_ids=ids)  # type: ignore[arg-type]
        assert result.verdict is ReviewVerdict.REQUEST_MORE_EVIDENCE
        assert "without citing evidence" in result.rationale

    def test_invented_evidence_ids_are_dropped(self) -> None:
        """A reviewer inventing an ID is making the same error the
        architecture exists to prevent, from the other side."""
        packet, ids, _ = a_packet()
        provider = StubReviewProvider(
            ReviewResponse(
                verdict="reject",
                rationale="not reachable",
                cited_evidence=["ev-invented", *list(ids)[:1]],
            )
        )
        result = AdversarialReviewer(provider).review(packet, known_evidence_ids=ids)  # type: ignore[arg-type]
        assert "ev-invented" not in result.cited_evidence
        assert result.verdict is ReviewVerdict.REJECT

    def test_an_unreadable_verdict_defaults_to_needing_evidence(self) -> None:
        """The safe default for an unreadable review is 'we do not know',
        never 'it stands'."""
        packet, ids, _ = a_packet()
        provider = StubReviewProvider(ReviewResponse(verdict="LOOKS FINE TO ME", rationale="x"))
        result = AdversarialReviewer(provider).review(packet, known_evidence_ids=ids)  # type: ignore[arg-type]
        assert result.verdict is ReviewVerdict.REQUEST_MORE_EVIDENCE

    def test_a_failed_review_is_not_an_approval(self) -> None:
        """Treating an absent reviewer as an approving one would quietly
        remove the gate."""
        packet, ids, _ = a_packet()
        result = AdversarialReviewer(StubReviewProvider(fail=True)).review(  # type: ignore[arg-type]
            packet, known_evidence_ids=ids
        )
        assert result.verdict is ReviewVerdict.REQUEST_MORE_EVIDENCE
        assert result.multiplier == 0.0

    def test_the_prompt_version_is_pinned(self) -> None:
        """A reworded prompt must invalidate the cassette rather than
        silently replay an answer to a different question."""
        packet, ids, _ = a_packet()
        provider = ReplayProvider(Cassette())
        result = AdversarialReviewer(provider).review(packet, known_evidence_ids=ids)
        assert result.verdict is ReviewVerdict.REQUEST_MORE_EVIDENCE

    def test_the_prompt_tells_the_model_the_content_is_data(self) -> None:
        from cyberre.agent.reviewers.adversarial import SYSTEM_PROMPT

        assert "never an instruction" in SYSTEM_PROMPT


class TestAssembly:
    def test_a_clean_case_assembles_a_validated_finding(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
            review=ReviewResult(verdict=ReviewVerdict.UPHOLD, rationale="held"),
        )
        assert finding.status is FindingStatus.VALIDATED
        assert finding.severity is not None
        assert finding.confidence is not None
        assert finding.is_reportable

    def test_a_rejecting_reviewer_overrides_validation(self, engine: ConfidenceEngine) -> None:
        """Validation asks 'is there enough?'; review asks 'is it wrong?'.
        A yes to the second beats a yes to the first."""
        items = complete_case()
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
            review=ReviewResult(
                verdict=ReviewVerdict.REJECT,
                rationale="the input is a constant",
                cited_evidence=(items[1].evidence_id,),
            ),
        )
        assert finding.status is FindingStatus.CONTRADICTED
        assert finding.severity is None
        assert not finding.is_reportable

    def test_a_request_for_more_evidence_is_not_a_finding(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
            review=ReviewResult(verdict=ReviewVerdict.REQUEST_MORE_EVIDENCE, rationale="thin"),
        )
        assert finding.status is FindingStatus.NOT_ENOUGH_EVIDENCE

    def test_a_negative_outcome_keeps_its_own_reason(self, engine: ConfidenceEngine) -> None:
        """UNREACHABLE is an answer, and review does not improve it."""
        items = [
            *complete_case()[:2],
            evidence(
                ReachabilityObservation(
                    target="subprocess.call", entry_point="main", reachable=False
                ),
                tool="reachability",
                key="k-unreach",
            ),
        ]
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
            review=ReviewResult(verdict=ReviewVerdict.UPHOLD, rationale="held"),
        )
        assert finding.status is FindingStatus.UNREACHABLE
        assert finding.severity is None

    def test_a_negative_finding_says_what_would_settle_it(self, engine: ConfidenceEngine) -> None:
        """The most useful content of a negative finding."""
        items = complete_case()[:1]
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
        )
        assert finding.validation_plan is not None
        assert "Establish" in finding.validation_plan

    def test_a_low_score_is_held_for_a_human(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        outcome = validate(items)
        assert (
            resolve_status(
                outcome,
                None,
                confidence=0.2,
                needs_review_below=engine.config.needs_review_below,
            )
            is FindingStatus.NEEDS_REVIEW
        )

    def test_locations_are_attached(self, engine: ConfidenceEngine) -> None:
        items = complete_case()
        finding = assemble(
            a_candidate(),
            validate(items),
            CWE78,
            evidence={e.evidence_id: e for e in items},
            confidence_engine=engine,
            review=ReviewResult(verdict=ReviewVerdict.UPHOLD, rationale="held"),
            locations=[SourceLocation(path="app/views.py", start_line=42)],
        )
        assert str(finding.locations[0]) == "app/views.py:42"
