"""Deciding when to stop collecting evidence.

The decision is deliberately not the model's. A model asked "do you have
enough evidence?" will answer in proportion to how coherent its current story
feels, which is the opposite of what the question needs.

Stopping early produces an unsupported conclusion. Stopping late burns budget
on an answer that will not change. Both are failures, so the reason for
stopping is carried out of here and into the report rather than being
discarded.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from cyberre.agent.logic.planning import InformationNeed, PlannedAction
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.state import ReasoningBudget


class StopReason(StrEnum):
    """Why evidence collection ended.

    A closed set, so the reasons are countable in the benchmark - the ratio
    of NEEDS_CLOSED to BUDGET_EXHAUSTED across a corpus says whether the
    budgets are set sensibly.
    """

    NEEDS_CLOSED = "needs_closed"
    """Every open need was satisfied. The good ending."""

    NO_USEFUL_ACTION = "no_useful_action"
    """Capabilities remain but none would close an open need."""

    NEEDS_UNRESOLVABLE = "needs_unresolvable"
    """No registered capability can produce what is missing.

    Leads to NOT_ENOUGH_EVIDENCE, which is a successful outcome.
    """

    BUDGET_EXHAUSTED = "budget_exhausted"
    """Ends the investigation as PARTIAL, never as complete."""

    MAX_ROUNDS = "max_rounds"
    """A loop guard. Hitting it is a bug in planning, not a normal ending."""

    NOTHING_TO_DO = "nothing_to_do"
    """No applicable capability at all - usually an unsupported artefact."""


class SufficiencyDecision(DomainModel):
    """Whether to keep collecting, and why not if not."""

    should_continue: bool
    reason: StopReason | None = None
    explanation: NonEmptyStr
    open_needs: tuple[str, ...] = ()
    """Carried into the report. An investigation that stopped with open
    questions must say which ones; hiding them makes a partial result look
    complete."""

    @property
    def is_partial(self) -> bool:
        """Whether the result should be reported as PARTIAL."""
        return self.reason in {
            StopReason.BUDGET_EXHAUSTED,
            StopReason.MAX_ROUNDS,
        }


def assess(
    *,
    planned: Sequence[PlannedAction],
    open_needs: Sequence[InformationNeed],
    unresolvable: Sequence[str],
    budget: ReasoningBudget,
    round_number: int,
    max_rounds: int,
) -> SufficiencyDecision:
    """Decide whether to run another round of evidence collection.

    Checked in order of finality: budget first, because an exhausted budget
    ends the investigation whatever else is true, and the good endings last,
    so a genuinely complete investigation is not mislabelled by a guard that
    happened to fire at the same moment.
    """
    need_ids = tuple(need.need_id for need in open_needs)

    if budget.exhausted:
        return SufficiencyDecision(
            should_continue=False,
            reason=StopReason.BUDGET_EXHAUSTED,
            explanation=(
                f"the reasoning budget is exhausted after {budget.tool_calls_used} "
                f"tool calls and {budget.model_calls_used} model calls; "
                f"the result is partial"
            ),
            open_needs=need_ids,
        )

    if round_number >= max_rounds:
        return SufficiencyDecision(
            should_continue=False,
            reason=StopReason.MAX_ROUNDS,
            explanation=(
                f"stopped after {max_rounds} rounds without closing every need; "
                f"this is a planning defect rather than a normal ending"
            ),
            open_needs=need_ids,
        )

    if open_needs and len(unresolvable) == len(need_ids):
        return SufficiencyDecision(
            should_continue=False,
            reason=StopReason.NEEDS_UNRESOLVABLE,
            explanation=(
                "no registered capability can produce the missing evidence: "
                f"{', '.join(sorted(unresolvable))}"
            ),
            open_needs=need_ids,
        )

    if not planned:
        if not open_needs:
            return SufficiencyDecision(
                should_continue=False,
                reason=StopReason.NEEDS_CLOSED,
                explanation="every information need was satisfied",
            )
        return SufficiencyDecision(
            should_continue=False,
            reason=StopReason.NOTHING_TO_DO,
            explanation=(
                "no applicable capability remains, but needs are still open: "
                f"{', '.join(sorted(need_ids))}"
            ),
            open_needs=need_ids,
        )

    if open_needs and not any(action.closes_needs for action in planned):
        # Actions remain, but none of them would move the investigation
        # forward. Running them would spend budget to learn nothing relevant.
        return SufficiencyDecision(
            should_continue=False,
            reason=StopReason.NO_USEFUL_ACTION,
            explanation=(
                "capabilities remain but none would close an open need: "
                f"{', '.join(sorted(need_ids))}"
            ),
            open_needs=need_ids,
        )

    return SufficiencyDecision(
        should_continue=True,
        explanation=(
            f"round {round_number + 1}: {len(planned)} action(s) planned, "
            f"{len(need_ids)} need(s) open"
        ),
        open_needs=need_ids,
    )
