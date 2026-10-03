"""Investigation state: identifiers and decisions, never payloads.

The state is checkpointed after every step and is the thing a workflow engine
carries around. If raw tool output or decompiled code could live here, every
checkpoint would grow without bound and the "don't put raw output in the model
context" rule would be defeated from the other direction. So the state holds
IDs, and :meth:`InvestigationState.check_size` enforces that in bytes.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id, utcnow
from cyberre.core.models.enums import Depth, InvestigationStatus, ProfileId

#: Serialised ceiling for the state, in bytes. Exceeding it is a structural
#: error - something is being carried that belongs in the object store - so it
#: fails loudly rather than degrading quietly.
MAX_STATE_BYTES = 256 * 1024


class ReasoningBudget(DomainModel):
    """What an investigation is allowed to spend, and what it has spent.

    Exhaustion ends the investigation as ``PARTIAL``. It never causes the
    system to conclude early with less evidence and the same confidence.
    """

    max_tool_calls: int = Field(default=20, ge=1)
    max_model_calls: int = Field(default=6, ge=1)
    max_runtime_seconds: int = Field(default=600, ge=1)
    max_sandbox_seconds: int = Field(default=0, ge=0)
    max_evidence_items: int = Field(default=2000, ge=1)

    tool_calls_used: int = Field(default=0, ge=0)
    model_calls_used: int = Field(default=0, ge=0)
    runtime_seconds_used: float = Field(default=0.0, ge=0.0)

    @property
    def exhausted(self) -> bool:
        return (
            self.tool_calls_used >= self.max_tool_calls
            or self.model_calls_used >= self.max_model_calls
            or self.runtime_seconds_used >= self.max_runtime_seconds
        )

    def remaining_tool_calls(self) -> int:
        return max(0, self.max_tool_calls - self.tool_calls_used)

    def remaining_model_calls(self) -> int:
        return max(0, self.max_model_calls - self.model_calls_used)


class Scope(DomainModel):
    """What is in bounds for this investigation.

    Explicit rather than implied, because "analyse this repository" and
    "analyse this repository except its vendored dependencies and test
    fixtures" produce very different false-positive rates.
    """

    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    include_artefact_ids: tuple[str, ...] = ()
    notes: str | None = None


class Objective(DomainModel):
    """The normalised question, plus what would count as answering it."""

    question: NonEmptyStr
    normalised_intent: NonEmptyStr
    success_criteria: tuple[str, ...] = ()


class UnresolvedQuestion(DomainModel):
    """Something the investigation could not settle.

    Carried into the report. Hiding these would make a partial investigation
    look complete, which is the failure mode the status set exists to prevent.
    """

    question_id: str = Field(default_factory=lambda: new_id("uq"))
    question: NonEmptyStr
    blocks_hypothesis: str | None = None
    why_unresolved: NonEmptyStr


class ExecutionRef(DomainModel):
    """A pointer to a recorded tool or model execution.

    The record itself - arguments, output, usage - lives in storage. Only the
    reference belongs in the state.
    """

    ref_id: NonEmptyStr
    kind: NonEmptyStr
    identifier: NonEmptyStr
    """Capability ID or model ID."""

    succeeded: bool
    at: datetime = TimestampField


class InvestigationState(DomainModel):
    """Everything the controller needs to decide what to do next.

    Mutation is by :meth:`evolve`, which returns a new state - the object is
    frozen like every other domain model, so a checkpoint cannot be altered
    after the fact.
    """

    investigation_id: str = Field(default_factory=lambda: new_id("inv"))
    objective: Objective
    scope: Scope = Scope()
    profiles: tuple[ProfileId, ...] = ()

    depth: Depth = Depth.FAST
    budget: ReasoningBudget = ReasoningBudget()
    status: InvestigationStatus = InvestigationStatus.RUNNING

    artefact_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    agent_claim_ids: tuple[str, ...] = ()
    hypothesis_ids: tuple[str, ...] = ()
    candidate_finding_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    tool_failure_ids: tuple[str, ...] = ()

    unresolved_questions: tuple[UnresolvedQuestion, ...] = ()
    tool_history: tuple[ExecutionRef, ...] = ()
    model_history: tuple[ExecutionRef, ...] = ()
    policy_decision_ids: tuple[str, ...] = ()
    review_result_ids: tuple[str, ...] = ()

    report_id: str | None = None
    started_at: datetime = TimestampField
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _completion_requires_no_losses(self) -> InvestigationState:
        """An investigation that lost a tool is PARTIAL, not COMPLETE.

        Reporting COMPLETE after a failed capability overstates coverage, and
        coverage is exactly what a security assessment is judged on.
        """
        if self.status is InvestigationStatus.COMPLETE and self.tool_failure_ids:
            raise ValueError(
                "an investigation with recorded tool failures is PARTIAL, not COMPLETE; "
                f"failures: {list(self.tool_failure_ids)}"
            )
        return self

    def evolve(self, **changes: object) -> InvestigationState:
        """Return a new, re-validated state with `changes` applied.

        Deliberately rebuilds through ``model_validate`` rather than using
        ``model_copy(update=...)``. ``model_copy`` skips validators, and since
        this is the only mutation path, that would let a state be evolved into
        a configuration the validators exist to forbid - COMPLETE with a
        recorded tool failure, for instance. A guard that the normal code path
        bypasses is not a guard.
        """
        data = self.model_dump()
        data.update(changes)
        data["updated_at"] = utcnow()
        return InvestigationState.model_validate(data)

    def serialised_size(self) -> int:
        return len(self.model_dump_json().encode("utf-8"))

    def check_size(self, limit: int = MAX_STATE_BYTES) -> None:
        """Raise if the state has grown beyond `limit`.

        A breach means something is carrying a payload instead of a reference.
        Called at each checkpoint so the regression is caught where it is
        introduced rather than in production on a large binary.
        """
        size = self.serialised_size()
        if size > limit:
            raise ValueError(
                f"investigation state is {size} bytes, over the {limit}-byte limit. "
                f"State holds identifiers and decisions; payloads belong in the "
                f"object store, referenced by ID."
            )
