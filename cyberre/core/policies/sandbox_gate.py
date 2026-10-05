"""The gate in front of dynamic analysis.

Three things must all hold before anything untrusted executes, and they
are checked in this order because each is cheaper and more absolute than
the last:

1. The provider's isolation grade meets what the work requires (ADR-024).
2. A human has authorised it, where policy says one must (ADR-014).
3. The provider's self-test actually passes (invariant 11).

Any failure refuses. There is no override flag, and adding one would
defeat the only part of this system that stands between a hostile sample
and the host.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from cyberre.core.contracts.sandbox import (
    REQUIRED_GRADE,
    ExecutionIntent,
    IsolationGrade,
    SandboxPolicy,
    SandboxProvider,
    SandboxSelfTest,
    grade_at_least,
)
from cyberre.core.models.base import DomainModel, NonEmptyStr, TimestampField, new_id
from cyberre.core.models.enums import RiskLevel
from cyberre.core.policies.approval import ApprovalGateway, ApprovalRequest


class SandboxDecision(DomainModel):
    """Whether dynamic analysis may proceed, and why not if not."""

    decision_id: str = Field(default_factory=lambda: new_id("sb"))
    investigation_id: NonEmptyStr
    intent: ExecutionIntent
    provider: NonEmptyStr
    available_grade: IsolationGrade
    required_grade: IsolationGrade
    permitted: bool
    reason: NonEmptyStr
    self_test: SandboxSelfTest | None = None
    decided_at: datetime = TimestampField

    @property
    def refused_for_isolation(self) -> bool:
        return not self.permitted and not grade_at_least(self.available_grade, self.required_grade)


class SandboxGate:
    """Decides whether a sandbox may be used for a given intent."""

    def __init__(
        self, provider: SandboxProvider, *, approval_gateway: ApprovalGateway | None = None
    ) -> None:
        self._provider = provider
        self._gateway = approval_gateway if approval_gateway is not None else ApprovalGateway()

    def evaluate(
        self,
        *,
        investigation_id: str,
        intent: ExecutionIntent,
        policy: SandboxPolicy,
        rationale: str,
        artefact_id: str | None = None,
        require_approval: bool = True,
    ) -> SandboxDecision:
        """Decide, without running anything."""
        required = REQUIRED_GRADE[intent]
        available = self._provider.isolation_grade

        def refuse(reason: str, self_test: SandboxSelfTest | None = None) -> SandboxDecision:
            return SandboxDecision(
                investigation_id=investigation_id,
                intent=intent,
                provider=self._provider.provider_name,
                available_grade=available,
                required_grade=required,
                permitted=False,
                reason=reason,
                self_test=self_test,
            )

        if not grade_at_least(available, required):
            # Checked first and refused outright. An approval cannot
            # authorise a boundary that does not exist, and asking a human
            # to approve one invites them to.
            return refuse(
                f"{self._provider.provider_name} provides {available.value} isolation "
                f"and {intent.value} requires {required.value}. No approval can "
                f"substitute for a boundary that is not there."
            )

        if require_approval:
            decision = self._gateway.request(
                ApprovalRequest(
                    investigation_id=investigation_id,
                    capability_id=f"sandbox.{intent.value}",
                    risk_level=(
                        RiskLevel.L3_NETWORKED_LAB
                        if policy.network_enabled
                        else RiskLevel.L2_SANDBOX
                    ),
                    rationale=rationale,
                    artefact_id=artefact_id,
                    reversible=False,
                )
            )
            if not decision.permits_execution:
                return refuse(decision.reason or f"approval not granted ({decision.outcome.value})")

        # Last, because it is the most expensive: it starts containers.
        self_test = self._provider.self_test(policy)
        if not self_test.passed:
            failures = ", ".join(check.name for check in self_test.failures())
            return refuse(
                f"the sandbox self-test failed ({failures}); a boundary that cannot "
                f"demonstrate it holds is not one",
                self_test,
            )

        return SandboxDecision(
            investigation_id=investigation_id,
            intent=intent,
            provider=self._provider.provider_name,
            available_grade=available,
            required_grade=required,
            permitted=True,
            reason=(
                f"{available.value} isolation meets the {required.value} required "
                f"for {intent.value}, and the self-test passed"
            ),
            self_test=self_test,
        )
