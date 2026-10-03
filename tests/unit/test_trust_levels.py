"""The trust lattice is the mechanism behind invariants 1, 2, 5, 7 and 8.

These tests check both directions: that legal promotions are permitted, and -
more importantly - that the specific promotions the architecture forbids are
actually refused.
"""

from __future__ import annotations

import itertools

import pytest
from cyberre.core.trust.levels import (
    LEGAL_PROMOTIONS,
    Actor,
    IllegalPromotionError,
    TrustLevel,
    is_legal,
    may_satisfy_requirement,
    promote,
)

pytestmark = pytest.mark.unit


class TestLegalPromotions:
    def test_normaliser_turns_tool_output_into_evidence(self) -> None:
        assert (
            promote(TrustLevel.TOOL_OUTPUT, TrustLevel.NORMALIZED_EVIDENCE, Actor.NORMALIZER)
            is TrustLevel.NORMALIZED_EVIDENCE
        )

    def test_validation_engine_produces_findings(self) -> None:
        assert (
            promote(TrustLevel.HYPOTHESIS, TrustLevel.VALIDATED_FINDING, Actor.VALIDATION_ENGINE)
            is TrustLevel.VALIDATED_FINDING
        )

    def test_model_may_interpret_and_hypothesise(self) -> None:
        assert is_legal(TrustLevel.NORMALIZED_EVIDENCE, TrustLevel.INTERPRETATION, Actor.MODEL)
        assert is_legal(TrustLevel.INTERPRETATION, TrustLevel.HYPOTHESIS, Actor.MODEL)

    def test_knowledge_lookup_may_interpret(self) -> None:
        assert is_legal(TrustLevel.DERIVED_EVIDENCE, TrustLevel.INTERPRETATION, Actor.KNOWLEDGE)


class TestInvariant1ModelOutputIsNotAFinding:
    """A model may reason. It may not conclude."""

    @pytest.mark.parametrize(
        "source",
        [
            TrustLevel.NORMALIZED_EVIDENCE,
            TrustLevel.DERIVED_EVIDENCE,
            TrustLevel.INTERPRETATION,
            TrustLevel.HYPOTHESIS,
        ],
    )
    def test_model_cannot_produce_a_validated_finding(self, source: TrustLevel) -> None:
        with pytest.raises(IllegalPromotionError):
            promote(source, TrustLevel.VALIDATED_FINDING, Actor.MODEL)

    def test_only_the_validation_engine_may_produce_a_finding(self) -> None:
        for actor in Actor:
            legal = is_legal(TrustLevel.HYPOTHESIS, TrustLevel.VALIDATED_FINDING, actor)
            assert legal is (actor is Actor.VALIDATION_ENGINE), (
                f"{actor.name} must not be able to create a finding"
            )


class TestInvariant2AgentClaimsAreInert:
    """A coding agent is an evidence source, never a truth authority."""

    @pytest.mark.parametrize("target", list(TrustLevel))
    def test_agent_claim_promotes_to_nothing(self, target: TrustLevel) -> None:
        for actor in Actor:
            assert not is_legal(TrustLevel.AGENT_CLAIM, target, actor), (
                f"AGENT_CLAIM must not promote to {target.name} via {actor.name}"
            )

    def test_agent_claim_cannot_satisfy_a_validation_requirement(self) -> None:
        assert not may_satisfy_requirement(TrustLevel.AGENT_CLAIM)

    def test_a_coding_agent_cannot_create_evidence_directly(self) -> None:
        with pytest.raises(IllegalPromotionError):
            promote(
                TrustLevel.TOOL_OUTPUT,
                TrustLevel.NORMALIZED_EVIDENCE,
                Actor.CODING_AGENT,
            )


class TestInvariant6ProvenanceCannotBeSkipped:
    def test_tool_output_must_pass_through_normalisation(self) -> None:
        for target in (TrustLevel.DERIVED_EVIDENCE, TrustLevel.INTERPRETATION):
            for actor in Actor:
                assert not is_legal(TrustLevel.TOOL_OUTPUT, target, actor)

    def test_raw_artefact_cannot_become_evidence_directly(self) -> None:
        for actor in Actor:
            assert not is_legal(TrustLevel.RAW_ARTEFACT, TrustLevel.NORMALIZED_EVIDENCE, actor)


class TestInvariant8ValidationPrecedesFindings:
    def test_interpretation_cannot_shortcut_to_a_finding(self) -> None:
        for actor in Actor:
            assert not is_legal(TrustLevel.INTERPRETATION, TrustLevel.VALIDATED_FINDING, actor)


class TestLatticeShape:
    """Properties that must hold however the table is edited."""

    def test_no_self_promotion_except_derivation_chains(self) -> None:
        for (source, target), actors in LEGAL_PROMOTIONS.items():
            if source is target:
                assert source is TrustLevel.DERIVED_EVIDENCE, (
                    f"{source.name} -> itself is only meaningful for derivation chains"
                )
                assert actors == frozenset({Actor.TRANSFORM})

    def test_no_demotion_is_declared_legal(self) -> None:
        for source, target in LEGAL_PROMOTIONS:
            if source is TrustLevel.DERIVED_EVIDENCE and target is TrustLevel.DERIVED_EVIDENCE:
                continue
            assert target > source, f"{source.name} -> {target.name} is not a promotion"

    def test_every_pair_outside_the_table_is_refused(self) -> None:
        for source, target, actor in itertools.product(TrustLevel, TrustLevel, Actor):
            if (source, target) in LEGAL_PROMOTIONS:
                continue
            with pytest.raises(IllegalPromotionError):
                promote(source, target, actor)

    def test_only_evidence_levels_may_satisfy_requirements(self) -> None:
        satisfying = {level for level in TrustLevel if may_satisfy_requirement(level)}
        assert satisfying == {
            TrustLevel.NORMALIZED_EVIDENCE,
            TrustLevel.DERIVED_EVIDENCE,
        }


class TestErrorMessage:
    def test_names_the_actor_and_the_permitted_actors(self) -> None:
        with pytest.raises(IllegalPromotionError) as exc:
            promote(TrustLevel.HYPOTHESIS, TrustLevel.VALIDATED_FINDING, Actor.MODEL)
        message = str(exc.value)
        assert "MODEL" in message
        assert "VALIDATION_ENGINE" in message

    def test_names_the_transition_when_it_is_not_legal_at_all(self) -> None:
        with pytest.raises(IllegalPromotionError) as exc:
            promote(TrustLevel.AGENT_CLAIM, TrustLevel.VALIDATED_FINDING, Actor.MODEL)
        assert "not a legal transition" in str(exc.value)
