"""Policy enforcement.

Marked `security` rather than `unit`: these are the controls standing between
an autonomous investigation loop and a destructive action, and they should be
findable as a group.

Invariants under test: 3 (profiles cannot grant permissions), 4 (global policy
overrides profile preferences), and the fail-closed rule that an unconfigured
deployment permits nothing rather than everything.
"""

from __future__ import annotations

import pytest
from cyberre.core.contracts.capability import CapabilityCost, CapabilitySpec
from cyberre.core.models.enums import ArtefactType, EvidenceType, RiskLevel
from cyberre.core.models.state import ReasoningBudget
from cyberre.core.policies.approval import (
    ApprovalDecision,
    ApprovalGateway,
    ApprovalOutcome,
    ApprovalRequest,
    DenyingApprover,
)
from cyberre.core.policies.engine import (
    DenialReason,
    PolicyDecision,
    PolicyEngine,
    PolicyOutcome,
)
from cyberre.core.policies.permissions import (
    NETWORKED_LAB,
    READ_ONLY,
    SANDBOXED_ANALYSIS,
    STATIC_ANALYSIS,
    PermissionSet,
    PermissionTerm,
    PolicyContext,
    effective_permissions,
)

pytestmark = pytest.mark.security


def spec(
    capability_id: str = "semgrep.scan",
    *,
    risk: RiskLevel = RiskLevel.L1_LOCAL_STATIC,
    network: bool = False,
    sandbox: bool = False,
    prerequisites: tuple[str, ...] = (),
) -> CapabilitySpec:
    return CapabilitySpec(
        capability_id=capability_id,
        name=capability_id,
        description="test capability",
        artefact_types=frozenset({ArtefactType.SOURCE_TREE}),
        produces=frozenset({EvidenceType.SCANNER_FINDING}),
        cost=CapabilityCost(seconds=1.0),
        reliability=0.8,
        risk_level=risk,
        requires_network=network,
        requires_sandbox=sandbox,
        prerequisites=prerequisites,
    )


class ApprovingApprover:
    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            outcome=ApprovalOutcome.APPROVED,
            approver="analyst",
        )


class RefusingApprover:
    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            outcome=ApprovalOutcome.DENIED,
            approver="analyst",
            reason="not authorised for this engagement",
        )


def decide(context: PolicyContext, capability: CapabilitySpec, **kwargs: object) -> PolicyDecision:
    engine = PolicyEngine(context, approval_gateway=kwargs.pop("gateway", None))  # type: ignore[arg-type]
    return engine.evaluate(capability, investigation_id="inv-1", **kwargs)  # type: ignore[arg-type]


class TestFailClosed:
    def test_an_unconfigured_policy_permits_only_static_analysis(self) -> None:
        """Forgetting to configure policy must not grant authority."""
        permissions = effective_permissions([])
        assert permissions.max_risk_level is RiskLevel.L1_LOCAL_STATIC
        assert permissions.allow_network is False
        assert permissions.allow_sandbox is False

    def test_a_read_only_policy_refuses_static_analysis(self) -> None:
        context = PolicyContext(global_policy=READ_ONLY)
        decision = decide(context, spec(risk=RiskLevel.L1_LOCAL_STATIC))
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.denial_reason is DenialReason.RISK_CEILING

    def test_requires_approval_is_not_permission(self) -> None:
        """A request for permission is not permission."""
        pending = PolicyDecision(
            investigation_id="inv-1",
            capability_id="x",
            risk_level=RiskLevel.L2_SANDBOX,
            outcome=PolicyOutcome.REQUIRES_APPROVAL,
            reason="awaiting a human",
        )
        assert pending.permits_execution is False


class TestInvariant3ProfilesCannotGrant:
    def test_a_profile_cannot_raise_the_risk_ceiling(self) -> None:
        """The case this invariant exists for: MALWARE_ANALYSIS wanting more."""
        context = PolicyContext(
            global_policy=STATIC_ANALYSIS,
            profile_policy=PermissionSet(
                term=PermissionTerm.PROFILE,
                max_risk_level=RiskLevel.L3_NETWORKED_LAB,
                allow_network=True,
                allow_sandbox=True,
            ),
        )
        effective = context.effective()
        assert effective.max_risk_level is RiskLevel.L1_LOCAL_STATIC
        assert effective.allow_network is False
        assert effective.allow_sandbox is False

    def test_a_profile_can_restrict_further(self) -> None:
        """Subtracting is always allowed; only widening is not."""
        context = PolicyContext(
            global_policy=SANDBOXED_ANALYSIS,
            profile_policy=PermissionSet(
                term=PermissionTerm.PROFILE,
                max_risk_level=RiskLevel.L0_READ_ONLY,
            ),
        )
        assert context.effective().max_risk_level is RiskLevel.L0_READ_ONLY

    def test_a_profile_prohibition_survives_the_intersection(self) -> None:
        context = PolicyContext(
            global_policy=STATIC_ANALYSIS,
            profile_policy=PermissionSet(
                term=PermissionTerm.PROFILE,
                forbidden_capabilities=frozenset({"semgrep.scan"}),
            ),
        )
        decision = decide(context, spec("semgrep.scan"))
        assert decision.denial_reason is DenialReason.FORBIDDEN_CAPABILITY

    def test_a_prohibition_from_any_term_wins(self) -> None:
        """Deny-lists union; one refusal is enough."""
        for term_name in ("environment_policy", "profile_policy", "user_policy"):
            context = PolicyContext(
                global_policy=STATIC_ANALYSIS,
                **{term_name: PermissionSet(forbidden_capabilities=frozenset({"semgrep.scan"}))},  # type: ignore[arg-type]
            )
            assert decide(context, spec()).outcome is PolicyOutcome.DENY


class TestAllowLists:
    def test_no_opinion_is_not_the_same_as_everything(self) -> None:
        open_term = PermissionSet(allowed_capabilities=None)
        closed_term = PermissionSet(allowed_capabilities=frozenset())
        assert open_term.permits_capability("anything") is True
        assert closed_term.permits_capability("anything") is False

    def test_allow_lists_intersect(self) -> None:
        a = PermissionSet(allowed_capabilities=frozenset({"x", "y"}))
        b = PermissionSet(allowed_capabilities=frozenset({"y", "z"}))
        assert a.intersect(b).allowed_capabilities == frozenset({"y"})

    def test_a_term_with_no_opinion_does_not_narrow(self) -> None:
        a = PermissionSet(allowed_capabilities=frozenset({"x"}))
        b = PermissionSet(allowed_capabilities=None)
        assert a.intersect(b).allowed_capabilities == frozenset({"x"})

    def test_a_capability_outside_the_allow_list_is_denied(self) -> None:
        context = PolicyContext(
            global_policy=STATIC_ANALYSIS.model_copy(
                update={"allowed_capabilities": frozenset({"ghidra.analyze"})}
            )
        )
        assert decide(context, spec("semgrep.scan")).denial_reason is (
            DenialReason.NOT_IN_ALLOW_LIST
        )


class TestRiskLevels:
    def test_levels_zero_to_two_run_under_policy(self) -> None:
        context = PolicyContext(global_policy=SANDBOXED_ANALYSIS)
        for risk in (RiskLevel.L0_READ_ONLY, RiskLevel.L1_LOCAL_STATIC):
            assert decide(context, spec(risk=risk)).outcome is PolicyOutcome.ALLOW

    def test_level_three_requires_a_human(self) -> None:
        context = PolicyContext(global_policy=NETWORKED_LAB)
        gateway = ApprovalGateway(ApprovingApprover())
        decision = decide(
            context,
            spec(risk=RiskLevel.L3_NETWORKED_LAB, network=True),
            gateway=gateway,
        )
        assert decision.outcome is PolicyOutcome.ALLOW
        assert decision.approval is not None
        assert decision.approval.approver == "analyst"

    def test_level_three_without_approval_is_denied(self) -> None:
        context = PolicyContext(global_policy=NETWORKED_LAB)
        decision = decide(
            context,
            spec(risk=RiskLevel.L3_NETWORKED_LAB, network=True),
            gateway=ApprovalGateway(RefusingApprover()),
        )
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.denial_reason is DenialReason.APPROVAL_DENIED

    @pytest.mark.parametrize("risk", [RiskLevel.L4_MODIFYING, RiskLevel.L5_EXTERNAL_TARGET])
    def test_levels_four_and_five_need_more_than_a_raised_ceiling(self, risk: RiskLevel) -> None:
        """A ceiling high enough to cover them by accident is not authorisation."""
        context = PolicyContext(
            global_policy=PermissionSet(
                max_risk_level=RiskLevel.L5_EXTERNAL_TARGET,
                approval_required_above=RiskLevel.L5_EXTERNAL_TARGET,
            )
        )
        decision = decide(context, spec("destructive.op", risk=risk))
        assert decision.outcome is PolicyOutcome.DENY
        assert decision.denial_reason is DenialReason.REQUIRES_EXPLICIT_POLICY

    @pytest.mark.parametrize("risk", [RiskLevel.L4_MODIFYING, RiskLevel.L5_EXTERNAL_TARGET])
    def test_levels_four_and_five_run_when_named_and_approved(self, risk: RiskLevel) -> None:
        """Possible, but it takes a policy written for this engagement."""
        context = PolicyContext(
            global_policy=PermissionSet(
                max_risk_level=RiskLevel.L5_EXTERNAL_TARGET,
                allowed_capabilities=frozenset({"destructive.op"}),
            )
        )
        decision = decide(
            context,
            spec("destructive.op", risk=risk),
            gateway=ApprovalGateway(ApprovingApprover()),
        )
        assert decision.outcome is PolicyOutcome.ALLOW

    def test_no_preset_reaches_level_four(self) -> None:
        for preset in (READ_ONLY, STATIC_ANALYSIS, SANDBOXED_ANALYSIS, NETWORKED_LAB):
            assert preset.max_risk_level is not RiskLevel.L4_MODIFYING
            assert preset.max_risk_level is not RiskLevel.L5_EXTERNAL_TARGET


class TestCapabilityRequirements:
    def test_network_is_refused_when_policy_withholds_it(self) -> None:
        context = PolicyContext(global_policy=SANDBOXED_ANALYSIS)
        decision = decide(context, spec("fetch.cve", network=True))
        assert decision.denial_reason is DenialReason.NETWORK_NOT_PERMITTED

    def test_sandbox_is_refused_when_policy_withholds_it(self) -> None:
        context = PolicyContext(global_policy=STATIC_ANALYSIS)
        decision = decide(
            context, spec("sandbox.detonate", risk=RiskLevel.L1_LOCAL_STATIC, sandbox=True)
        )
        assert decision.denial_reason is DenialReason.SANDBOX_NOT_PERMITTED


class TestBudget:
    def test_an_exhausted_budget_stops_execution(self) -> None:
        context = PolicyContext(global_policy=STATIC_ANALYSIS)
        decision = decide(
            context, spec(), budget=ReasoningBudget(max_tool_calls=1, tool_calls_used=1)
        )
        assert decision.denial_reason is DenialReason.BUDGET_EXHAUSTED
        assert "PARTIAL" in decision.reason

    def test_a_live_budget_does_not_block(self) -> None:
        context = PolicyContext(global_policy=STATIC_ANALYSIS)
        assert decide(context, spec(), budget=ReasoningBudget()).outcome is PolicyOutcome.ALLOW


class TestDecisionsAreExplainable:
    def test_a_denial_names_the_restricting_terms(self) -> None:
        context = PolicyContext(
            global_policy=STATIC_ANALYSIS,
            user_policy=PermissionSet(
                term=PermissionTerm.USER,
                forbidden_capabilities=frozenset({"semgrep.scan"}),
            ),
        )
        decision = decide(context, spec("semgrep.scan"))
        assert PermissionTerm.USER in decision.restricting_terms

    def test_every_denial_carries_a_reason_code(self) -> None:
        """A closed set, so denials are countable in the observability data."""
        context = PolicyContext(global_policy=READ_ONLY)
        decision = decide(context, spec(risk=RiskLevel.L2_SANDBOX))
        assert decision.denial_reason is not None
        assert decision.reason


class TestApprovalGateway:
    def test_the_default_approver_denies(self) -> None:
        """An approval gate with nobody attached must refuse."""
        gateway = ApprovalGateway()
        decision = gateway.request(
            ApprovalRequest(
                investigation_id="inv-1",
                capability_id="sandbox.detonate",
                risk_level=RiskLevel.L2_SANDBOX,
                rationale="suspected packer",
            )
        )
        assert decision.outcome is ApprovalOutcome.UNAVAILABLE
        assert decision.permits_execution is False

    def test_pending_is_not_permission(self) -> None:
        decision = ApprovalDecision(request_id="ap-1", outcome=ApprovalOutcome.PENDING)
        assert decision.permits_execution is False

    def test_a_crashing_approver_denies_rather_than_propagating(self) -> None:
        class ExplodingApprover:
            def decide(self, request: ApprovalRequest) -> ApprovalDecision:
                raise RuntimeError("ticket system unreachable")

        gateway = ApprovalGateway(ExplodingApprover())
        decision = gateway.request(
            ApprovalRequest(
                investigation_id="inv-1",
                capability_id="x",
                risk_level=RiskLevel.L3_NETWORKED_LAB,
                rationale="y",
            )
        )
        assert decision.outcome is ApprovalOutcome.UNAVAILABLE
        assert "ticket system unreachable" in (decision.reason or "")

    def test_an_answer_to_a_different_question_is_not_an_answer(self) -> None:
        class ConfusedApprover:
            def decide(self, request: ApprovalRequest) -> ApprovalDecision:
                return ApprovalDecision(
                    request_id="ap-somebody-else", outcome=ApprovalOutcome.APPROVED
                )

        gateway = ApprovalGateway(ConfusedApprover())
        decision = gateway.request(
            ApprovalRequest(
                investigation_id="inv-1",
                capability_id="x",
                risk_level=RiskLevel.L3_NETWORKED_LAB,
                rationale="y",
            )
        )
        assert decision.outcome is ApprovalOutcome.UNAVAILABLE

    def test_refusals_are_recorded_as_well_as_approvals(self) -> None:
        """'What did we decline, and why?' is the question an audit asks."""
        gateway = ApprovalGateway(RefusingApprover())
        gateway.request(
            ApprovalRequest(
                investigation_id="inv-1",
                capability_id="x",
                risk_level=RiskLevel.L3_NETWORKED_LAB,
                rationale="y",
            )
        )
        decisions = gateway.decisions_for("inv-1")
        assert len(decisions) == 1
        assert decisions[0].outcome is ApprovalOutcome.DENIED
        assert decisions[0].reason == "not authorised for this engagement"

    def test_the_denying_approver_explains_itself(self) -> None:
        decision = DenyingApprover().decide(
            ApprovalRequest(
                investigation_id="inv-1",
                capability_id="x",
                risk_level=RiskLevel.L2_SANDBOX,
                rationale="y",
            )
        )
        assert "no approver is configured" in (decision.reason or "")


class TestTheIdentityElementIsNotAHole:
    """`no_opinion` exists so unset terms do not clamp the ceiling. These
    tests pin the ways it could have become a way to grant authority."""

    def test_it_cannot_be_used_for_the_global_term(self) -> None:
        with pytest.raises(ValueError, match="must state what is permitted"):
            PermissionSet.no_opinion(PermissionTerm.GLOBAL)

    def test_an_empty_policy_set_is_still_restrictive(self) -> None:
        assert effective_permissions([]).max_risk_level is RiskLevel.L1_LOCAL_STATIC

    def test_subordinate_terms_alone_cannot_authorise(self) -> None:
        """Without a global policy there is no authority to narrow."""
        permissions = effective_permissions(
            [
                PermissionSet.no_opinion(PermissionTerm.ENVIRONMENT),
                PermissionSet.no_opinion(PermissionTerm.PROFILE),
            ]
        )
        context = PolicyContext(global_policy=STATIC_ANALYSIS)
        assert permissions.max_risk_level is RiskLevel.L5_EXTERNAL_TARGET
        # ...but a real context always intersects the global policy in.
        assert context.effective().max_risk_level is RiskLevel.L1_LOCAL_STATIC

    def test_a_terse_subordinate_term_clamps_and_that_is_documented(self) -> None:
        """The sharp edge: a term written only to forbid also carries L1."""
        context = PolicyContext(
            global_policy=NETWORKED_LAB,
            profile_policy=PermissionSet(forbidden_capabilities=frozenset({"x"})),
        )
        assert context.effective().max_risk_level is RiskLevel.L1_LOCAL_STATIC

    def test_building_from_no_opinion_avoids_the_clamp(self) -> None:
        context = PolicyContext(
            global_policy=NETWORKED_LAB,
            profile_policy=PermissionSet.no_opinion(PermissionTerm.PROFILE).model_copy(
                update={"forbidden_capabilities": frozenset({"x"})}
            ),
        )
        assert context.effective().max_risk_level is RiskLevel.L3_NETWORKED_LAB
        assert context.effective().permits_capability("x") is False
