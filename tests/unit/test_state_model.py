"""Investigation state, hypotheses and artefacts.

The state-size guard is the notable one: it is what stops payloads from
creeping into the checkpointed object, which would defeat the context
discipline from the other direction.
"""

from __future__ import annotations

import pytest
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import ArtefactType, Depth, HypothesisStatus, InvestigationStatus
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.state import (
    MAX_STATE_BYTES,
    InvestigationState,
    Objective,
    ReasoningBudget,
    UnresolvedQuestion,
)
from pydantic import ValidationError

pytestmark = pytest.mark.unit


class TestStateSizeGuard:
    def test_a_fresh_state_is_well_under_the_limit(self, state: InvestigationState) -> None:
        state.check_size()
        assert state.serialised_size() < 4096

    def test_a_state_carrying_a_payload_is_rejected(self, state: InvestigationState) -> None:
        """Simulates evidence IDs replaced by inlined content."""
        bloated = state.evolve(evidence_ids=tuple("x" * 1000 for _ in range(400)))
        with pytest.raises(ValueError, match="over the"):
            bloated.check_size()

    def test_the_error_says_where_payloads_belong(self, state: InvestigationState) -> None:
        bloated = state.evolve(evidence_ids=tuple("x" * 2000 for _ in range(200)))
        with pytest.raises(ValueError, match="object store"):
            bloated.check_size()

    def test_limit_is_explicit_and_overridable_for_tests(self, state: InvestigationState) -> None:
        assert MAX_STATE_BYTES == 256 * 1024
        with pytest.raises(ValueError):
            state.check_size(limit=10)


class TestPartialIsNotComplete:
    def test_completion_with_a_tool_failure_is_rejected(self, state: InvestigationState) -> None:
        """Reporting COMPLETE after losing a tool overstates coverage."""
        with pytest.raises(ValidationError, match="PARTIAL, not COMPLETE"):
            state.evolve(status=InvestigationStatus.COMPLETE, tool_failure_ids=("tf-1",))

    def test_partial_with_a_tool_failure_is_fine(self, state: InvestigationState) -> None:
        partial = state.evolve(status=InvestigationStatus.PARTIAL, tool_failure_ids=("tf-1",))
        assert partial.status is InvestigationStatus.PARTIAL

    def test_complete_without_failures_is_fine(self, state: InvestigationState) -> None:
        assert (
            state.evolve(status=InvestigationStatus.COMPLETE).status is InvestigationStatus.COMPLETE
        )


class TestEvolve:
    def test_evolve_returns_a_new_object(self, state: InvestigationState) -> None:
        evolved = state.evolve(depth=Depth.DEEP)
        assert evolved is not state
        assert state.depth is Depth.FAST
        assert evolved.depth is Depth.DEEP

    def test_evolve_refreshes_the_timestamp(self, state: InvestigationState) -> None:
        assert state.evolve(depth=Depth.STANDARD).updated_at >= state.updated_at

    def test_state_is_frozen(self, state: InvestigationState) -> None:
        with pytest.raises(ValidationError):
            state.depth = Depth.DEEP  # type: ignore[misc]

    def test_evolve_revalidates(self, state: InvestigationState) -> None:
        """Regression: ``model_copy(update=...)`` skips validators.

        ``evolve`` is the only mutation path, so building the new state
        without validation would let every model-level invariant be bypassed
        by ordinary use. Caught by the COMPLETE-with-failures test; pinned
        here so the cause is named rather than rediscovered.
        """
        with pytest.raises(ValidationError):
            state.evolve(depth="not-a-depth")


class TestBudget:
    def test_a_fresh_budget_is_not_exhausted(self) -> None:
        assert ReasoningBudget().exhausted is False

    def test_exhaustion_is_detected_per_dimension(self) -> None:
        assert ReasoningBudget(max_tool_calls=2, tool_calls_used=2).exhausted
        assert ReasoningBudget(max_model_calls=1, model_calls_used=1).exhausted
        assert ReasoningBudget(max_runtime_seconds=5, runtime_seconds_used=5.0).exhausted

    def test_remaining_never_goes_negative(self) -> None:
        budget = ReasoningBudget(max_tool_calls=2, tool_calls_used=5)
        assert budget.remaining_tool_calls() == 0

    def test_default_model_call_budget_matches_the_performance_target(self) -> None:
        """Architecture section 10 targets under six model calls for STANDARD."""
        assert ReasoningBudget().max_model_calls == 6


class TestHypothesis:
    def test_a_hypothesis_is_typed_to_a_class(self, hypothesis: Hypothesis) -> None:
        assert str(hypothesis.hypothesis_class) == "cwe:78"

    def test_confirmation_without_evidence_is_rejected(
        self, hypothesis_class: HypothesisClass
    ) -> None:
        with pytest.raises(ValidationError, match="supporting evidence"):
            Hypothesis(
                investigation_id="inv-1",
                statement="It is vulnerable.",
                hypothesis_class=hypothesis_class,
                status=HypothesisStatus.CONFIRMED,
                created_by="reasoner",
            )

    def test_evidence_cannot_both_support_and_contradict(
        self, hypothesis_class: HypothesisClass
    ) -> None:
        with pytest.raises(ValidationError, match="both support and contradict"):
            Hypothesis(
                investigation_id="inv-1",
                statement="x",
                hypothesis_class=hypothesis_class,
                supporting_evidence=("ev-1",),
                contradicting_evidence=("ev-1",),
                created_by="reasoner",
            )

    def test_unsatisfied_requirements_drive_the_next_action(
        self, hypothesis_class: HypothesisClass
    ) -> None:
        hypothesis = Hypothesis(
            investigation_id="inv-1",
            statement="x",
            hypothesis_class=hypothesis_class,
            unsatisfied_requirements=("reachability", "attacker_controlled_source"),
            created_by="reasoner",
        )
        assert "reachability" in hypothesis.unsatisfied_requirements


class TestArtefact:
    def test_artefacts_are_untrusted_by_default(self, artefact: Artefact) -> None:
        """The safe path must be the default one."""
        assert artefact.is_untrusted is True

    def test_identity_is_content_not_path(self, artefact: Artefact) -> None:
        assert artefact.sha256 == "a" * 64
        assert "path" not in Artefact.model_fields

    def test_a_malformed_hash_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Artefact(
                sha256="abc",
                size_bytes=1,
                artefact_type=ArtefactType.PE,
                display_name="x.exe",
            )

    def test_a_source_tree_is_not_stored_as_a_blob(self) -> None:
        with pytest.raises(ValidationError, match="analysed in place"):
            Artefact(
                sha256="a" * 64,
                size_bytes=1,
                artefact_type=ArtefactType.SOURCE_TREE,
                display_name="repo",
                object_store_ref="obj/x",
            )


class TestUnresolvedQuestionsSurvive:
    def test_a_question_records_why_it_is_unresolved(self, state: InvestigationState) -> None:
        """Hiding these would make a partial investigation look complete."""
        question = UnresolvedQuestion(
            question="Is handler() reachable from an HTTP route?",
            blocks_hypothesis="hy-1",
            why_unresolved="Call graph construction timed out.",
        )
        evolved = state.evolve(unresolved_questions=(question,))
        assert evolved.unresolved_questions[0].why_unresolved


class TestRoundTrip:
    def test_state_survives_serialisation(self, state: InvestigationState) -> None:
        restored = InvestigationState.model_validate_json(state.model_dump_json())
        assert restored == state

    def test_objective_requires_a_question(self) -> None:
        with pytest.raises(ValidationError):
            Objective(question="", normalised_intent="x")
