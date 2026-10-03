"""Invariant 3, end to end: a profile cannot grant permission.

M4 proved the intersection cannot be widened. These tests prove the profile
layer actually goes through it - that a profile's policy request reaches the
engine as a term that subtracts, and that no path exists from "the profile
asked" to "the capability ran".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.core.contracts.capability import CapabilityCost, CapabilitySpec
from cyberre.core.models.enums import ArtefactType, EvidenceType, ProfileId, RiskLevel
from cyberre.core.policies.approval import ApprovalGateway
from cyberre.core.policies.engine import DenialReason, PolicyEngine, PolicyOutcome
from cyberre.core.policies.permissions import (
    SANDBOXED_ANALYSIS,
    STATIC_ANALYSIS,
    PermissionSet,
    PermissionTerm,
    PolicyContext,
)
from cyberre.core.profiles.loader import ProfileRegistry
from cyberre.core.profiles.model import AnalysisProfile, ProfilePolicyRequest

pytestmark = pytest.mark.security

PROFILE_DIR = Path(__file__).resolve().parents[2] / "profiles"


@pytest.fixture(scope="module")
def registry() -> ProfileRegistry:
    return ProfileRegistry.from_directory(PROFILE_DIR)


def detonate_spec() -> CapabilitySpec:
    return CapabilitySpec(
        capability_id="sandbox.detonate",
        name="Detonate sample",
        description="Run an untrusted sample in a sandbox.",
        artefact_types=frozenset({ArtefactType.PE}),
        produces=frozenset({EvidenceType.SANDBOX_EVENT}),
        cost=CapabilityCost(seconds=60.0),
        reliability=0.7,
        risk_level=RiskLevel.L2_SANDBOX,
        requires_sandbox=True,
    )


def context_for(profile: AnalysisProfile, global_policy: PermissionSet) -> PolicyContext:
    """Wire a profile into the five-way intersection the way the runtime will."""
    return PolicyContext(
        global_policy=global_policy,
        profile_policy=profile.policy.as_permission_term(),
    )


class TestAProfileCannotWidenPolicy:
    def test_an_ambitious_profile_gains_nothing(self) -> None:
        greedy = AnalysisProfile(
            profile_id=ProfileId.MALWARE_ANALYSIS,
            name="Greedy",
            description="A profile that asks for everything.",
            policy=ProfilePolicyRequest(
                max_risk_level=RiskLevel.L5_EXTERNAL_TARGET,
                wants_sandbox=True,
                wants_network=True,
                approval_required_above=RiskLevel.L5_EXTERNAL_TARGET,
            ),
        )
        effective = context_for(greedy, STATIC_ANALYSIS).effective()

        assert effective.max_risk_level is RiskLevel.L1_LOCAL_STATIC
        assert effective.allow_sandbox is False
        assert effective.allow_network is False
        assert effective.approval_required_above is RiskLevel.L1_LOCAL_STATIC

    def test_the_capability_is_refused_at_the_engine(self) -> None:
        greedy = AnalysisProfile(
            profile_id=ProfileId.MALWARE_ANALYSIS,
            name="Greedy",
            description="x",
            policy=ProfilePolicyRequest(
                max_risk_level=RiskLevel.L5_EXTERNAL_TARGET, wants_sandbox=True
            ),
        )
        engine = PolicyEngine(context_for(greedy, STATIC_ANALYSIS))
        decision = engine.evaluate(detonate_spec(), investigation_id="inv-1")
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.permits_execution is False

    def test_a_profile_cannot_relax_the_approval_threshold_either(self) -> None:
        """Invariant 3 covers approval, not only the risk ceiling.

        The global policy requires a human above L1. A profile declaring it
        needs none until L2 does not thereby escape the gate - the
        intersection takes the stricter threshold, so the request still goes
        to an approver, and the default approver denies.
        """
        wants_sandbox = AnalysisProfile(
            profile_id=ProfileId.MALWARE_ANALYSIS,
            name="Sandbox user",
            description="x",
            policy=ProfilePolicyRequest(
                max_risk_level=RiskLevel.L2_SANDBOX,
                wants_sandbox=True,
                approval_required_above=RiskLevel.L2_SANDBOX,
            ),
        )
        context = context_for(wants_sandbox, SANDBOXED_ANALYSIS)
        assert context.effective().approval_required_above is RiskLevel.L1_LOCAL_STATIC

        unattended = PolicyEngine(context, approval_gateway=ApprovalGateway())
        refused = unattended.evaluate(detonate_spec(), investigation_id="inv-1")
        assert refused.outcome is PolicyOutcome.DENY
        assert refused.denial_reason is DenialReason.APPROVAL_UNAVAILABLE

    def test_a_profile_request_is_bounded_rather_than_ignored(self) -> None:
        """Requesting is not meaningless: within the global ceiling, and with
        a human present, the capability the profile needs does run."""

        class Approving:
            def decide(self, request: object) -> object:
                from cyberre.core.policies.approval import (
                    ApprovalDecision,
                    ApprovalOutcome,
                )

                return ApprovalDecision(
                    request_id=request.request_id,  # type: ignore[attr-defined]
                    outcome=ApprovalOutcome.APPROVED,
                    approver="analyst",
                )

        wants_sandbox = AnalysisProfile(
            profile_id=ProfileId.MALWARE_ANALYSIS,
            name="Sandbox user",
            description="x",
            policy=ProfilePolicyRequest(max_risk_level=RiskLevel.L2_SANDBOX, wants_sandbox=True),
        )
        engine = PolicyEngine(
            context_for(wants_sandbox, SANDBOXED_ANALYSIS),
            approval_gateway=ApprovalGateway(Approving()),  # type: ignore[arg-type]
        )
        decision = engine.evaluate(detonate_spec(), investigation_id="inv-1")
        assert decision.outcome is PolicyOutcome.ALLOW
        assert decision.approval is not None

    def test_the_profile_term_is_recorded_as_the_restriction(self) -> None:
        """A denial must name what caused it, across five terms."""
        restrictive = AnalysisProfile(
            profile_id=ProfileId.SOURCE_SECURITY,
            name="Restrictive",
            description="x",
            policy=ProfilePolicyRequest(max_risk_level=RiskLevel.L0_READ_ONLY),
        )
        engine = PolicyEngine(context_for(restrictive, SANDBOXED_ANALYSIS))
        decision = engine.evaluate(detonate_spec(), investigation_id="inv-1")
        assert decision.denial_reason is DenialReason.RISK_CEILING
        assert PermissionTerm.PROFILE in decision.restricting_terms


class TestShippedProfilesUnderGlobalPolicy:
    def test_malware_analysis_cannot_detonate_even_with_a_permissive_global(
        self, registry: ProfileRegistry
    ) -> None:
        """Two independent reasons it cannot: its own prohibition, and the
        fact that it never asks for the sandbox."""
        malware = registry.get(ProfileId.MALWARE_ANALYSIS)
        assert "sandbox.detonate" in malware.forbidden_capabilities

        context = PolicyContext(
            global_policy=SANDBOXED_ANALYSIS,
            profile_policy=malware.policy.as_permission_term().model_copy(
                update={"forbidden_capabilities": malware.forbidden_capabilities}
            ),
        )
        engine = PolicyEngine(context)
        decision = engine.evaluate(detonate_spec(), investigation_id="inv-1")
        assert decision.denial_reason is DenialReason.FORBIDDEN_CAPABILITY

    def test_no_shipped_profile_asks_for_network_access(self, registry: ProfileRegistry) -> None:
        for profile in registry.implemented():
            assert profile.policy.wants_network is False

    def test_every_shipped_profile_under_a_read_only_global_runs_nothing_risky(
        self, registry: ProfileRegistry
    ) -> None:
        """An operator can clamp the whole system from one place."""
        from cyberre.core.policies.permissions import READ_ONLY

        for profile in registry.implemented():
            effective = context_for(profile, READ_ONLY).effective()
            assert effective.max_risk_level is RiskLevel.L0_READ_ONLY
            assert effective.allow_sandbox is False
