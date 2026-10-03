"""The policy engine: the single gate every capability execution passes.

Fail-closed throughout. Anything the engine cannot positively establish as
permitted is denied, and every denial names the term that caused it.

The engine decides; it does not execute. Keeping the decision separate from
the action means the decision can be recorded, replayed and audited without
re-running anything.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from cyberre.core.contracts.capability import CapabilitySpec
from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id
from cyberre.core.models.enums import RISK_ORDER, RiskLevel
from cyberre.core.models.state import ReasoningBudget
from cyberre.core.policies.approval import (
    ApprovalDecision,
    ApprovalGateway,
    ApprovalRequest,
)
from cyberre.core.policies.permissions import (
    PermissionTerm,
    PolicyContext,
    restricting_terms,
)

#: Risk levels that no preset permits and that require a policy written for
#: the specific engagement. Named here so the rule is in one place rather than
#: implied by the absence of a constant.
REQUIRES_EXPLICIT_POLICY = frozenset({RiskLevel.L4_MODIFYING, RiskLevel.L5_EXTERNAL_TARGET})


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"
    """Permitted in principle, but a human must say so first."""


class DenialReason(StrEnum):
    """Why something was refused. A closed set, so denials are countable."""

    FORBIDDEN_CAPABILITY = "forbidden_capability"
    NOT_IN_ALLOW_LIST = "not_in_allow_list"
    RISK_CEILING = "risk_ceiling"
    REQUIRES_EXPLICIT_POLICY = "requires_explicit_policy"
    NETWORK_NOT_PERMITTED = "network_not_permitted"
    SANDBOX_NOT_PERMITTED = "sandbox_not_permitted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_UNAVAILABLE = "approval_unavailable"


class PolicyDecision(DomainModel):
    """A recorded authorisation decision.

    Persisted with the investigation. "Why did this run?" and "why did this
    not run?" are both audit questions, and both are answered from here.
    """

    decision_id: str = Field(default_factory=lambda: new_id("pd"))
    investigation_id: NonEmptyStr
    capability_id: NonEmptyStr
    risk_level: RiskLevel
    outcome: PolicyOutcome
    reason: NonEmptyStr
    denial_reason: DenialReason | None = None
    restricting_terms: tuple[PermissionTerm, ...] = ()
    approval: ApprovalDecision | None = None
    decided_at: datetime = TimestampField

    @property
    def permits_execution(self) -> bool:
        """Only ALLOW permits execution.

        REQUIRES_APPROVAL is not permission; it is a request for permission.
        """
        return self.outcome is PolicyOutcome.ALLOW


class PolicyEngine:
    """Evaluates whether a capability may run.

    Checks are ordered cheapest and most absolute first: an explicit
    prohibition beats everything, and there is no point consulting a human
    about something policy forbids outright.
    """

    def __init__(
        self,
        context: PolicyContext,
        *,
        approval_gateway: ApprovalGateway | None = None,
    ) -> None:
        self._context = context
        self._effective = context.effective()
        self._gateway = approval_gateway if approval_gateway is not None else ApprovalGateway()

    @property
    def effective_permissions(self) -> object:
        return self._effective

    def evaluate(
        self,
        spec: CapabilitySpec,
        *,
        investigation_id: str,
        budget: ReasoningBudget | None = None,
        rationale: str = "investigation step",
        artefact_id: str | None = None,
    ) -> PolicyDecision:
        """Decide whether `spec` may execute now."""
        deny = self._denial_for(spec, investigation_id, budget)
        if deny is not None:
            return deny

        if self._effective.needs_approval_for(spec.risk_level):
            return self._seek_approval(
                spec,
                investigation_id=investigation_id,
                rationale=rationale,
                artefact_id=artefact_id,
            )

        return PolicyDecision(
            investigation_id=investigation_id,
            capability_id=spec.capability_id,
            risk_level=spec.risk_level,
            outcome=PolicyOutcome.ALLOW,
            reason=(
                f"permitted: risk {spec.risk_level.value} is within the effective "
                f"ceiling {self._effective.max_risk_level.value}"
            ),
        )

    # ----------------------------------------------------------- internals

    def _denial_for(
        self,
        spec: CapabilitySpec,
        investigation_id: str,
        budget: ReasoningBudget | None,
    ) -> PolicyDecision | None:
        def denied(
            reason: DenialReason,
            message: str,
            terms: tuple[PermissionTerm, ...] = (),
        ) -> PolicyDecision:
            return PolicyDecision(
                investigation_id=investigation_id,
                capability_id=spec.capability_id,
                risk_level=spec.risk_level,
                outcome=PolicyOutcome.DENY,
                reason=message,
                denial_reason=reason,
                restricting_terms=terms,
            )

        offending = restricting_terms(self._context.terms(), spec.capability_id, spec.risk_level)

        if spec.capability_id in self._effective.forbidden_capabilities:
            return denied(
                DenialReason.FORBIDDEN_CAPABILITY,
                f"'{spec.capability_id}' is explicitly forbidden",
                offending,
            )

        if not self._effective.permits_capability(spec.capability_id):
            return denied(
                DenialReason.NOT_IN_ALLOW_LIST,
                f"'{spec.capability_id}' is not in the effective allow-list",
                offending,
            )

        if spec.risk_level in REQUIRES_EXPLICIT_POLICY and not self._explicitly_allowed(spec):
            return denied(
                DenialReason.REQUIRES_EXPLICIT_POLICY,
                (
                    f"risk {spec.risk_level.value} requires a policy naming this "
                    f"capability explicitly; a risk ceiling alone does not authorise "
                    f"destructive or external-target operations"
                ),
                offending,
            )

        if not self._effective.permits_risk(spec.risk_level):
            return denied(
                DenialReason.RISK_CEILING,
                (
                    f"risk {spec.risk_level.value} exceeds the effective ceiling "
                    f"{self._effective.max_risk_level.value}"
                ),
                offending,
            )

        if spec.requires_network and not self._effective.allow_network:
            return denied(
                DenialReason.NETWORK_NOT_PERMITTED,
                f"'{spec.capability_id}' requires network access, which policy withholds",
                offending,
            )

        if spec.requires_sandbox and not self._effective.allow_sandbox:
            return denied(
                DenialReason.SANDBOX_NOT_PERMITTED,
                f"'{spec.capability_id}' requires a sandbox, which policy withholds",
                offending,
            )

        if budget is not None and budget.exhausted:
            # Not a security denial, but it belongs on the same gate: an
            # investigation that has spent its budget stops rather than
            # quietly continuing.
            return denied(
                DenialReason.BUDGET_EXHAUSTED,
                "the reasoning budget is exhausted; the investigation ends as PARTIAL",
            )

        return None

    def _explicitly_allowed(self, spec: CapabilitySpec) -> bool:
        """Whether some term names this capability in an allow-list.

        Levels 4 and 5 need a decision made about *them*, not a ceiling raised
        high enough to cover them by accident.
        """
        return any(
            term.allowed_capabilities is not None
            and spec.capability_id in term.allowed_capabilities
            for term in self._context.terms()
        )

    def _seek_approval(
        self,
        spec: CapabilitySpec,
        *,
        investigation_id: str,
        rationale: str,
        artefact_id: str | None,
    ) -> PolicyDecision:
        decision = self._gateway.request(
            ApprovalRequest(
                investigation_id=investigation_id,
                capability_id=spec.capability_id,
                risk_level=spec.risk_level,
                rationale=rationale,
                artefact_id=artefact_id,
                reversible=RISK_ORDER[spec.risk_level] < RISK_ORDER[RiskLevel.L4_MODIFYING],
            )
        )

        if decision.permits_execution:
            return PolicyDecision(
                investigation_id=investigation_id,
                capability_id=spec.capability_id,
                risk_level=spec.risk_level,
                outcome=PolicyOutcome.ALLOW,
                reason=f"approved by {decision.approver or 'an approver'}",
                approval=decision,
            )

        reason = (
            DenialReason.APPROVAL_DENIED
            if decision.outcome.value == "denied"
            else DenialReason.APPROVAL_UNAVAILABLE
        )
        return PolicyDecision(
            investigation_id=investigation_id,
            capability_id=spec.capability_id,
            risk_level=spec.risk_level,
            outcome=PolicyOutcome.DENY,
            reason=decision.reason or f"approval not granted ({decision.outcome.value})",
            denial_reason=reason,
            approval=decision,
        )
