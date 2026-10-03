"""The human approval boundary.

A core domain service, not a workflow-engine feature (ADR-014). If approval
lived in the graph, replacing the graph would remove the gate - and the gate
is the last thing standing between an autonomous loop and a destructive
action.

The default approver denies. An approval gateway with nobody attached must
refuse, not wave things through; a deployment that forgot to wire an approver
should stall, loudly, rather than proceed.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id
from cyberre.core.models.enums import RiskLevel


class ApprovalOutcome(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    """Nobody has answered yet. The investigation waits; it does not assume."""

    UNAVAILABLE = "unavailable"
    """No approver is reachable. Treated exactly as a denial."""


class ApprovalRequest(DomainModel):
    """A request for a human to authorise something risky."""

    request_id: str = Field(default_factory=lambda: new_id("ap"))
    investigation_id: NonEmptyStr
    capability_id: NonEmptyStr
    risk_level: RiskLevel
    rationale: NonEmptyStr
    """Why the investigation wants this. The approver is deciding on behalf of
    the organisation and needs the reason, not just the request."""

    artefact_id: str | None = None
    reversible: bool = True
    requested_at: datetime = TimestampField


class ApprovalDecision(DomainModel):
    """The answer, kept for the audit trail whichever way it went."""

    request_id: NonEmptyStr
    outcome: ApprovalOutcome
    approver: str | None = None
    reason: str | None = None
    decided_at: datetime = TimestampField

    @property
    def permits_execution(self) -> bool:
        """Only an explicit approval permits execution.

        PENDING and UNAVAILABLE are both negative here. Treating "no answer
        yet" as permission is how an approval gate becomes decorative.
        """
        return self.outcome is ApprovalOutcome.APPROVED


@runtime_checkable
class Approver(Protocol):
    """Something that can answer an approval request.

    A console prompt, a ticket queue, a chat integration. The gateway does not
    care which, only that an answer is explicit.
    """

    def decide(self, request: ApprovalRequest) -> ApprovalDecision: ...


class DenyingApprover:
    """The default. Refuses everything, with a reason.

    Deliberately not a placeholder to be replaced before production - it is
    the correct behaviour when no approver is configured, and a deployment
    that hits it learns immediately rather than silently self-authorising.
    """

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            outcome=ApprovalOutcome.UNAVAILABLE,
            reason=(
                "no approver is configured, so the request cannot be authorised; "
                "configure one or lower the policy ceiling"
            ),
        )


class ApprovalGateway:
    """Routes risky actions to a human and records the answer.

    Every request and decision is kept, approvals and refusals alike. A log of
    only the approvals cannot answer "what did we decline, and why?", which is
    the question an audit actually asks.
    """

    def __init__(self, approver: Approver | None = None) -> None:
        self._approver: Approver = approver if approver is not None else DenyingApprover()
        self._requests: list[ApprovalRequest] = []
        self._decisions: list[ApprovalDecision] = []

    def request(self, request: ApprovalRequest) -> ApprovalDecision:
        """Ask for authorisation and record both sides of the exchange.

        An approver that raises is treated as unavailable rather than being
        allowed to propagate: a crashing approver must deny, not abort the
        investigation in a state where someone might retry without the gate.
        """
        self._requests.append(request)
        try:
            decision = self._approver.decide(request)
        except Exception as error:  # a failing approver denies, it does not abort
            decision = ApprovalDecision(
                request_id=request.request_id,
                outcome=ApprovalOutcome.UNAVAILABLE,
                reason=f"approver raised {type(error).__name__}: {error}",
            )

        if decision.request_id != request.request_id:
            # An answer to a different question is not an answer.
            decision = ApprovalDecision(
                request_id=request.request_id,
                outcome=ApprovalOutcome.UNAVAILABLE,
                reason="approver returned a decision for a different request",
            )

        self._decisions.append(decision)
        return decision

    @property
    def history(self) -> tuple[tuple[ApprovalRequest, ApprovalDecision], ...]:
        return tuple(zip(self._requests, self._decisions, strict=True))

    def decisions_for(self, investigation_id: str) -> tuple[ApprovalDecision, ...]:
        return tuple(
            decision
            for request, decision in self.history
            if request.investigation_id == investigation_id
        )
