"""The sandbox gate.

Invariant 11 says dynamic analysis cannot run when sandbox checks fail.
ADR-024 adds that it cannot run when the boundary is too weak for what is
being run, however well configured it is.

These are `security` tests because the gate is the only thing standing
between a hostile sample and the host, and because the failure mode is
silent: a container that looks like a malware sandbox invites the trust
it cannot support.
"""

from __future__ import annotations

import pytest
from cyberre.adapters.sandbox.docker import DockerEnvironment, DockerSandboxProvider
from cyberre.core.contracts.sandbox import (
    GRADE_ORDER,
    REQUIRED_GRADE,
    ExecutionIntent,
    IsolationGrade,
    SandboxPolicy,
    SandboxProvider,
    SandboxRun,
    SandboxSelfTest,
    SandboxUnavailableError,
    SelfTestCheck,
    grade_at_least,
)
from cyberre.core.policies.approval import (
    ApprovalDecision,
    ApprovalGateway,
    ApprovalOutcome,
    ApprovalRequest,
)
from cyberre.core.policies.sandbox_gate import SandboxGate

pytestmark = pytest.mark.security

POLICY = SandboxPolicy(image_digest="sha256:" + "0" * 64)


class StubProvider:
    """A provider with a chosen grade and self-test outcome."""

    def __init__(self, grade: IsolationGrade, *, self_test_passes: bool = True) -> None:
        self._grade = grade
        self._passes = self_test_passes
        self.self_tested = False
        self.ran = False

    @property
    def provider_name(self) -> str:
        return f"stub-{self._grade.value}"

    @property
    def isolation_grade(self) -> IsolationGrade:
        return self._grade

    def self_test(self, policy: SandboxPolicy) -> SandboxSelfTest:
        self.self_tested = True
        return SandboxSelfTest(
            checks=(SelfTestCheck(name="network_isolated", passed=self._passes),)
        )

    def run(self, artefact_ref: str, *, policy: SandboxPolicy) -> SandboxRun:
        self.ran = True
        raise AssertionError("unreachable in these tests")


class Approving:
    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=request.request_id,
            outcome=ApprovalOutcome.APPROVED,
            approver="analyst",
        )


def evaluate(
    provider: StubProvider,
    intent: ExecutionIntent,
    *,
    approve: bool = True,
    require_approval: bool = True,
) -> object:
    gateway = ApprovalGateway(Approving()) if approve else ApprovalGateway()
    return SandboxGate(provider, approval_gateway=gateway).evaluate(  # type: ignore[arg-type]
        investigation_id="inv-1",
        intent=intent,
        policy=POLICY,
        rationale="suspected packer",
        require_approval=require_approval,
    )


class TestTheGradeLadder:
    def test_grades_are_ordered_by_strength_not_alphabetically(self) -> None:
        """A StrEnum sorts `container` above `vmi`, which would invert the
        entire policy."""
        ordered = sorted(IsolationGrade, key=lambda g: GRADE_ORDER[g])
        assert ordered == [
            IsolationGrade.NONE,
            IsolationGrade.CONTAINER,
            IsolationGrade.USERSPACE_KERNEL,
            IsolationGrade.HYPERVISOR,
            IsolationGrade.VMI,
        ]

    def test_comparison_respects_the_ladder(self) -> None:
        assert grade_at_least(IsolationGrade.VMI, IsolationGrade.HYPERVISOR)
        assert not grade_at_least(IsolationGrade.CONTAINER, IsolationGrade.HYPERVISOR)

    def test_detonation_needs_a_hypervisor(self) -> None:
        assert REQUIRED_GRADE[ExecutionIntent.UNTRUSTED_SAMPLE] is (IsolationGrade.HYPERVISOR)

    def test_evasive_samples_need_introspection(self) -> None:
        """An in-guest agent is what an evasive sample is looking for."""
        assert REQUIRED_GRADE[ExecutionIntent.SUSPECTED_EVASIVE] is IsolationGrade.VMI

    def test_running_a_tool_needs_less_than_running_a_sample(self) -> None:
        assert (
            GRADE_ORDER[REQUIRED_GRADE[ExecutionIntent.ANALYSIS_TOOL]]
            < GRADE_ORDER[REQUIRED_GRADE[ExecutionIntent.UNTRUSTED_SAMPLE]]
        )


class TestAWeakBoundaryRefuses:
    def test_a_container_cannot_detonate_a_sample(self) -> None:
        decision = evaluate(
            StubProvider(IsolationGrade.CONTAINER), ExecutionIntent.UNTRUSTED_SAMPLE
        )
        assert decision.permitted is False
        assert decision.refused_for_isolation is True

    def test_a_hypervisor_cannot_handle_a_suspected_evasive_sample(self) -> None:
        decision = evaluate(
            StubProvider(IsolationGrade.HYPERVISOR), ExecutionIntent.SUSPECTED_EVASIVE
        )
        assert decision.permitted is False

    def test_grade_is_checked_before_approval_is_sought(self) -> None:
        """Asking a human to approve a boundary that does not exist
        invites them to."""
        gateway = ApprovalGateway(Approving())
        decision = SandboxGate(
            StubProvider(IsolationGrade.NONE),  # type: ignore[arg-type]
            approval_gateway=gateway,
        ).evaluate(
            investigation_id="inv-1",
            intent=ExecutionIntent.UNTRUSTED_SAMPLE,
            policy=POLICY,
            rationale="x",
        )
        assert decision.permitted is False
        assert gateway.history == (), "no approval should have been requested"

    def test_the_refusal_says_what_would_be_needed(self) -> None:
        decision = evaluate(
            StubProvider(IsolationGrade.CONTAINER), ExecutionIntent.UNTRUSTED_SAMPLE
        )
        assert "hypervisor" in decision.reason
        assert "container" in decision.reason

    def test_an_insufficient_grade_does_not_even_self_test(self) -> None:
        """The self-test starts containers; there is no point."""
        provider = StubProvider(IsolationGrade.CONTAINER)
        evaluate(provider, ExecutionIntent.UNTRUSTED_SAMPLE)
        assert provider.self_tested is False


class TestApprovalAndSelfTest:
    def test_a_sufficient_grade_still_needs_approval(self) -> None:
        decision = evaluate(
            StubProvider(IsolationGrade.HYPERVISOR),
            ExecutionIntent.UNTRUSTED_SAMPLE,
            approve=False,
        )
        assert decision.permitted is False

    def test_a_failing_self_test_refuses(self) -> None:
        """Invariant 11. A boundary that cannot demonstrate it holds is
        not one."""
        decision = evaluate(
            StubProvider(IsolationGrade.HYPERVISOR, self_test_passes=False),
            ExecutionIntent.UNTRUSTED_SAMPLE,
        )
        assert decision.permitted is False
        assert "self-test failed" in decision.reason

    def test_everything_aligned_permits(self) -> None:
        decision = evaluate(
            StubProvider(IsolationGrade.HYPERVISOR), ExecutionIntent.UNTRUSTED_SAMPLE
        )
        assert decision.permitted is True
        assert decision.self_test is not None

    def test_the_decision_is_recorded_either_way(self) -> None:
        """'Why was this refused?' is an audit question."""
        refused = evaluate(StubProvider(IsolationGrade.NONE), ExecutionIntent.UNTRUSTED_SAMPLE)
        assert refused.decision_id
        assert refused.available_grade is IsolationGrade.NONE
        assert refused.required_grade is IsolationGrade.HYPERVISOR


class TestTheDockerProvider:
    def test_a_wsl2_backend_grades_as_no_boundary(self) -> None:
        """Published techniques break Docker Desktop's WSL2 VM isolation
        and reach the Windows host, so no flag can talk it up."""
        provider = DockerSandboxProvider(
            environment=DockerEnvironment(
                available=True,
                os_type="linux",
                operating_system="Docker Desktop",
                detail="docker-desktop",
            )
        )
        assert provider.environment.is_wsl2_backend is True
        assert provider.isolation_grade is IsolationGrade.NONE

    def test_a_native_linux_daemon_grades_as_a_container(self) -> None:
        provider = DockerSandboxProvider(
            environment=DockerEnvironment(
                available=True,
                os_type="linux",
                operating_system="Ubuntu 24.04",
                detail="builder-01",
            )
        )
        assert provider.isolation_grade is IsolationGrade.CONTAINER

    def test_an_unavailable_daemon_grades_as_no_boundary(self) -> None:
        provider = DockerSandboxProvider(
            environment=DockerEnvironment(available=False, detail="not running")
        )
        assert provider.isolation_grade is IsolationGrade.NONE

    def test_it_refuses_to_detonate_on_any_host(self) -> None:
        """Container isolation shares the host kernel. A container that
        looks like a malware sandbox is worse than none."""
        provider = DockerSandboxProvider(
            environment=DockerEnvironment(
                available=True, os_type="linux", operating_system="Ubuntu 24.04"
            )
        )
        with pytest.raises(SandboxUnavailableError, match="does not detonate"):
            provider.run("obj/sample", policy=POLICY)

    def test_the_refusal_names_what_would_work(self) -> None:
        provider = DockerSandboxProvider(environment=DockerEnvironment(available=False))
        with pytest.raises(SandboxUnavailableError) as error:
            provider.run("obj/sample", policy=POLICY)
        message = str(error.value)
        assert "CAPE" in message or "Firecracker" in message
        assert "DRAKVUF" in message

    def test_an_unavailable_daemon_fails_its_self_test(self) -> None:
        provider = DockerSandboxProvider(
            environment=DockerEnvironment(available=False, detail="not running")
        )
        result = provider.self_test(POLICY)
        assert result.passed is False

    def test_it_satisfies_the_provider_protocol(self) -> None:
        provider = DockerSandboxProvider(environment=DockerEnvironment(available=False))
        assert isinstance(provider, SandboxProvider)


class TestThisHost:
    def test_this_machine_cannot_detonate_a_sample(self) -> None:
        """Recorded as a test rather than only in a document.

        Firecracker, gVisor and Kata are Linux-only and the first two need
        KVM; Docker Desktop here runs the WSL2 backend. If this ever stops
        being true - a Linux host, a real hypervisor provider - the test
        fails and the limitation gets revisited deliberately.
        """
        from cyberre.adapters.sandbox.docker import inspect_docker

        provider = DockerSandboxProvider(environment=inspect_docker())
        decision = SandboxGate(provider).evaluate(  # type: ignore[arg-type]
            investigation_id="inv-1",
            intent=ExecutionIntent.UNTRUSTED_SAMPLE,
            policy=POLICY,
            rationale="suspected malware",
        )
        assert decision.permitted is False
        assert decision.refused_for_isolation is True
