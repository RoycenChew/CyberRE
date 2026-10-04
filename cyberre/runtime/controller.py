"""The investigation controller.

A plain loop over pure decision functions (ADR-022). It owns orchestration
and nothing else: planning, policy, execution and storage all live elsewhere,
so this file can be read in one sitting and a reader can see every place an
investigation can end.

Checkpointing is a state save after every round. Resume reloads the state and
continues, which is the whole mechanism - there is no separate journal to
fall out of step with the records.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cyberre.agent.logic.planning import (
    InformationNeed,
    PlannedAction,
    plan_actions,
    unresolvable_needs,
)
from cyberre.agent.logic.sufficiency import StopReason, SufficiencyDecision, assess
from cyberre.core.contracts.capability import CapabilityRegistry, CapabilityResult
from cyberre.core.contracts.storage import EvidenceStore, InvestigationStore
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import InvestigationStatus
from cyberre.core.models.evidence import Evidence, ToolFailure
from cyberre.core.models.state import ExecutionRef, InvestigationState
from cyberre.core.policies.engine import PolicyDecision, PolicyEngine
from cyberre.core.profiles.model import AnalysisProfile

#: Loop guard. Reaching it means planning is cycling rather than converging,
#: so it is reported as a defect rather than as a normal ending.
MAX_ROUNDS = 12


@runtime_checkable
class CapabilityExecutor(Protocol):
    """Runs a capability against an artefact.

    The controller does not know how any capability works; it knows that
    running one yields evidence or raises. Keeping that boundary here is what
    lets the loop be tested with stub capabilities and no tools installed.
    """

    def execute(self, capability_id: str, artefact: Artefact) -> CapabilityResult: ...


@dataclass
class RoundRecord:
    """What happened in one round, for the audit trail and for tests."""

    number: int
    planned: tuple[PlannedAction, ...]
    executed: tuple[str, ...] = ()
    denied: tuple[PolicyDecision, ...] = ()
    failures: tuple[ToolFailure, ...] = ()
    evidence_count: int = 0
    decision: SufficiencyDecision | None = None


@dataclass
class InvestigationOutcome:
    """The result of a collection run.

    Deliberately not a report. Reasoning, validation and review are M10 and
    M11; until they exist the loop produces evidence and says plainly that
    it has done no more than that (ADR-002).
    """

    state: InvestigationState
    rounds: list[RoundRecord] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    failures: list[ToolFailure] = field(default_factory=list)
    stop_reason: StopReason | None = None

    @property
    def is_partial(self) -> bool:
        return self.state.status is InvestigationStatus.PARTIAL


class InvestigationController:
    """Drives evidence collection for one investigation."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        executor: CapabilityExecutor,
        policy: PolicyEngine,
        evidence_store: EvidenceStore,
        investigation_store: InvestigationStore,
        profile: AnalysisProfile | None = None,
        max_rounds: int = MAX_ROUNDS,
    ) -> None:
        self._registry = registry
        self._executor = executor
        self._policy = policy
        self._evidence_store = evidence_store
        self._investigation_store = investigation_store
        self._profile = profile
        self._max_rounds = max_rounds

    def run(
        self,
        state: InvestigationState,
        *,
        artefacts: Sequence[Artefact],
        needs: Sequence[InformationNeed] = (),
    ) -> InvestigationOutcome:
        """Collect evidence until a stopping condition is reached."""
        outcome = InvestigationOutcome(state=state)
        # Seeded from the checkpoint, not empty. On a resume the capabilities
        # that already produced evidence are in tool_history, and the planner
        # excludes them - which is what makes resuming cheap rather than a
        # restart that re-runs Ghidra over the same binary.
        satisfied: set[str] = {
            ref.identifier for ref in state.tool_history if ref.kind == "capability"
        }
        open_needs = list(needs)
        artefact_types = {artefact.artefact_type for artefact in artefacts}

        for artefact in artefacts:
            self._investigation_store.add_artefact(artefact)

        specs = list(self._registry.all_specs())
        round_number = 0

        while True:
            planned = plan_actions(
                specs,
                artefact_types=artefact_types,
                satisfied_capabilities=satisfied,
                needs=open_needs,
                profile=self._profile,
                depth=outcome.state.depth,
            )
            unresolvable = unresolvable_needs(specs, open_needs)

            decision = assess(
                planned=planned,
                open_needs=open_needs,
                unresolvable=unresolvable,
                budget=outcome.state.budget,
                round_number=round_number,
                max_rounds=self._max_rounds,
            )

            if not decision.should_continue:
                outcome.rounds.append(
                    RoundRecord(number=round_number, planned=tuple(planned), decision=decision)
                )
                outcome.stop_reason = decision.reason
                self._finish(outcome, decision)
                return outcome

            record = RoundRecord(number=round_number, planned=tuple(planned))
            self._run_round(record, planned, artefacts, satisfied, outcome)
            record.decision = decision
            outcome.rounds.append(record)

            open_needs = self._remaining_needs(open_needs, outcome.evidence)

            # Checkpoint after every round. Resume reloads this and
            # continues; there is no separate journal to fall out of step.
            self._investigation_store.save_state(outcome.state)
            round_number += 1

    # ----------------------------------------------------------- internals

    def _run_round(
        self,
        record: RoundRecord,
        planned: Sequence[PlannedAction],
        artefacts: Sequence[Artefact],
        satisfied: set[str],
        outcome: InvestigationOutcome,
    ) -> None:
        executed: list[str] = []
        denied: list[PolicyDecision] = []
        failures: list[ToolFailure] = []
        collected = 0

        for action in planned:
            spec = self._registry.get(action.capability_id)

            policy_decision = self._policy.evaluate(
                spec,
                investigation_id=outcome.state.investigation_id,
                budget=outcome.state.budget,
                rationale=action.rationale,
            )
            if not policy_decision.permits_execution:
                # A refusal is recorded, not retried. Repeating a denied
                # action would spend budget learning the same answer.
                denied.append(policy_decision)
                satisfied.add(action.capability_id)
                continue

            for artefact in self._applicable(spec, artefacts):
                try:
                    result = self._executor.execute(action.capability_id, artefact)
                except Exception as error:  # a tool failing is expected, not exceptional
                    failure = ToolFailure(
                        investigation_id=outcome.state.investigation_id,
                        capability_id=action.capability_id,
                        artefact_id=artefact.artefact_id,
                        reason=f"{type(error).__name__}: {error}",
                    )
                    # Never evidence. An investigation that lost a tool knows
                    # less; it has not observed something.
                    self._evidence_store.add_tool_failure(failure)
                    failures.append(failure)
                    outcome.failures.append(failure)
                    continue

                self._evidence_store.add_many(result.evidence)
                outcome.evidence.extend(result.evidence)
                collected += len(result.evidence)

                if result.partial:
                    # A tool that succeeded but could not see everything.
                    # Distinct from failure, and distinct from success - and
                    # it must be persisted like any other, or the gap is
                    # invisible in the record and the run looks complete.
                    partial_record = ToolFailure(
                        investigation_id=outcome.state.investigation_id,
                        capability_id=action.capability_id,
                        artefact_id=artefact.artefact_id,
                        reason="analysis was partial",
                        recoverable=True,
                    )
                    self._evidence_store.add_tool_failure(partial_record)
                    failures.append(partial_record)
                    outcome.failures.append(partial_record)

            executed.append(action.capability_id)
            satisfied.add(action.capability_id)
            outcome.state = self._charge(outcome.state, action)

        record.executed = tuple(executed)
        record.denied = tuple(denied)
        record.failures = tuple(failures)
        record.evidence_count = collected

        outcome.state = outcome.state.evolve(
            evidence_ids=tuple(e.evidence_id for e in outcome.evidence),
            tool_failure_ids=tuple(f.failure_id for f in outcome.failures),
            policy_decision_ids=(
                *outcome.state.policy_decision_ids,
                *(d.decision_id for d in denied),
            ),
            tool_history=(
                *outcome.state.tool_history,
                *(
                    ExecutionRef(
                        ref_id=f"{outcome.state.investigation_id}:{capability_id}",
                        kind="capability",
                        identifier=capability_id,
                        succeeded=True,
                    )
                    for capability_id in executed
                ),
            ),
        )

    @staticmethod
    def _applicable(spec: object, artefacts: Sequence[Artefact]) -> list[Artefact]:
        types = spec.artefact_types  # type: ignore[attr-defined]
        return [a for a in artefacts if a.artefact_type in types]

    @staticmethod
    def _charge(state: InvestigationState, action: PlannedAction) -> InvestigationState:
        budget = state.budget
        return state.evolve(
            budget=budget.model_copy(
                update={
                    "tool_calls_used": budget.tool_calls_used + 1,
                    "runtime_seconds_used": budget.runtime_seconds_used + action.estimated_seconds,
                }
            )
        )

    @staticmethod
    def _remaining_needs(
        needs: Sequence[InformationNeed], evidence: Sequence[Evidence]
    ) -> list[InformationNeed]:
        """Drop needs that the evidence now satisfies.

        Satisfaction here is only "evidence of the right kind exists". That
        is enough to stop the planner chasing it; whether it is enough to
        support a finding is validation's question, with a much higher bar
        (M10).
        """
        observed = {item.evidence_type for item in evidence}
        return [need for need in needs if not (need.satisfied_by & observed)]

    def _finish(self, outcome: InvestigationOutcome, decision: SufficiencyDecision) -> None:
        """Record the terminal status and the open questions."""
        from cyberre.core.models.state import UnresolvedQuestion

        questions = tuple(
            UnresolvedQuestion(
                question=f"need '{need_id}' was not satisfied",
                why_unresolved=decision.explanation,
            )
            for need_id in decision.open_needs
        )

        # Any recorded tool failure makes the result PARTIAL regardless of
        # why the loop stopped: the state model refuses COMPLETE alongside
        # failures, and that refusal is the point rather than an obstacle.
        status = (
            InvestigationStatus.PARTIAL
            if decision.is_partial or outcome.failures
            else InvestigationStatus.COMPLETE
        )

        outcome.state = outcome.state.evolve(
            status=status,
            unresolved_questions=(*outcome.state.unresolved_questions, *questions),
        )
        self._investigation_store.save_state(outcome.state)


def resume(
    controller: InvestigationController,
    investigation_id: str,
    *,
    store: InvestigationStore,
    artefacts: Sequence[Artefact],
    needs: Sequence[InformationNeed] = (),
) -> InvestigationOutcome:
    """Continue a checkpointed investigation.

    Reloads the saved state and runs again. Capabilities that already
    produced evidence are not re-run, because the planner excludes them -
    so resuming is cheap rather than a restart.
    """
    return controller.run(store.load_state(investigation_id), artefacts=artefacts, needs=needs)
