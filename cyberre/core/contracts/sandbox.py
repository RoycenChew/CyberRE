"""Sandbox contract.

The important part of this file is :class:`SandboxSelfTest`. Dynamic analysis
is the one place where a configuration mistake lets hostile code run with more
access than intended, so the contract requires a provider to *prove* its
isolation before it will be used, and failure refuses the run (invariant 11).
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr


class IsolationGrade(StrEnum):
    """How strong a sandbox's boundary actually is (ADR-024).

    Ordered by :data:`GRADE_ORDER`, because the policy engine compares
    them. The names describe the mechanism rather than a vendor, so a new
    provider slots into the ladder on its merits.
    """

    NONE = "none"
    """Not a security boundary.

    Docker Desktop on a WSL2 backend reports this: published techniques
    break its VM isolation and reach the Windows host. A bare subprocess
    reports it too. Nothing untrusted may be executed here.
    """

    CONTAINER = "container"
    """Namespaces and cgroups over a shared host kernel.

    A kernel exploit escapes. Appropriate for running analysis tooling
    against a sample, not for running the sample.
    """

    USERSPACE_KERNEL = "userspace_kernel"
    """Syscalls served by a userspace kernel, as gVisor does.

    The host kernel is largely out of reach, but the interceptor is
    software and is itself a target.
    """

    HYPERVISOR = "hypervisor"
    """A separate guest kernel behind a virtual machine monitor.

    Firecracker, Kata, CAPE on KVM. Escaping means breaking the VMM and
    then the hypervisor.
    """

    VMI = "vmi"
    """Hypervisor isolation with agentless introspection, as DRAKVUF does.

    Nothing runs inside the guest for the sample to detect, which is what
    makes it hold up against evasive malware where an agent-based sandbox
    reports behaviour the sample only performs when unobserved.
    """


#: Ordering for comparison. A StrEnum sorts alphabetically, which would
#: rank `container` above `vmi` and quietly invert the whole policy.
GRADE_ORDER: dict[IsolationGrade, int] = {
    IsolationGrade.NONE: 0,
    IsolationGrade.CONTAINER: 1,
    IsolationGrade.USERSPACE_KERNEL: 2,
    IsolationGrade.HYPERVISOR: 3,
    IsolationGrade.VMI: 4,
}


def grade_at_least(available: IsolationGrade, required: IsolationGrade) -> bool:
    return GRADE_ORDER[available] >= GRADE_ORDER[required]


class ExecutionIntent(StrEnum):
    """What is being run, which decides the grade required.

    Running a scanner over a sample and running the sample are different
    risks, and collapsing them would force either an impossible bar on
    ordinary tooling or an unsafe one on malware.
    """

    ANALYSIS_TOOL = "analysis_tool"
    """A trusted tool reading an untrusted artefact."""

    UNTRUSTED_SAMPLE = "untrusted_sample"
    """The artefact itself, executed."""

    SUSPECTED_EVASIVE = "suspected_evasive"
    """A sample showing anti-analysis behaviour.

    Needs introspection rather than an in-guest agent, because an agent is
    exactly what it is looking for - and a sample that detects the box
    produces a confidently wrong result rather than no result.
    """


#: The minimum grade each intent requires. Deliberately strict: sandbox
#: evasion is among the most common techniques in current malware, so a
#: boundary that is merely probably adequate is not.
REQUIRED_GRADE: dict[ExecutionIntent, IsolationGrade] = {
    ExecutionIntent.ANALYSIS_TOOL: IsolationGrade.CONTAINER,
    ExecutionIntent.UNTRUSTED_SAMPLE: IsolationGrade.HYPERVISOR,
    ExecutionIntent.SUSPECTED_EVASIVE: IsolationGrade.VMI,
}


class SandboxLimits(DomainModel):
    """Resource ceilings. All are enforced, none are advisory."""

    memory_mb: int = Field(default=2048, ge=64)
    cpus: float = Field(default=1.0, gt=0.0)
    pids: int = Field(default=256, ge=1)
    wall_clock_seconds: int = Field(default=120, ge=1)
    disk_mb: int = Field(default=512, ge=16)


class SandboxPolicy(DomainModel):
    """How a sandbox must be configured.

    Every default here is the restrictive one. Enabling network access is an
    explicit act requiring approval, rather than something a careless caller
    can omit their way into.
    """

    network_enabled: bool = False
    read_only_filesystem: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    run_as_non_root: bool = True
    mount_docker_socket: bool = False
    limits: SandboxLimits = SandboxLimits()
    image_digest: NonEmptyStr
    """Pinned by digest, never by tag. A tag can be repointed underneath us,
    which would silently change what a reproducible run actually ran."""


class SelfTestCheck(DomainModel):
    name: NonEmptyStr
    passed: bool
    detail: str | None = None


class SandboxSelfTest(DomainModel):
    """The result of verifying isolation before any untrusted execution."""

    checks: tuple[SelfTestCheck, ...]

    @property
    def passed(self) -> bool:
        """All checks must pass. There is no partial credit and no override."""
        return bool(self.checks) and all(check.passed for check in self.checks)

    def failures(self) -> Sequence[SelfTestCheck]:
        return [check for check in self.checks if not check.passed]


class SandboxUnavailableError(Exception):
    """Isolation could not be established, so nothing was executed.

    Fail-closed. A sandbox that cannot prove it is a sandbox is a host.
    """


class SandboxRun(DomainModel):
    exit_code: int
    telemetry_ref: str
    duration_seconds: float = Field(ge=0.0)
    timed_out: bool = False
    image_digest: NonEmptyStr


class InsufficientIsolationError(Exception):
    """The available boundary is weaker than the work requires.

    Raised instead of running with a warning. A sandbox that is not strong
    enough for what is being put in it is worse than none, because its
    presence invites trust.
    """

    def __init__(
        self,
        *,
        provider: str,
        available: IsolationGrade,
        required: IsolationGrade,
        intent: ExecutionIntent,
    ) -> None:
        self.available = available
        self.required = required
        super().__init__(
            f"{provider} provides {available.value} isolation; "
            f"{intent.value} requires at least {required.value}. "
            f"Refusing to execute. See docs/adr/ADR-024-sandbox-isolation-grades.md "
            f"for what each grade means and which tools provide it."
        )


@runtime_checkable
class SandboxProvider(Protocol):
    """Isolated execution for untrusted artefacts."""

    @property
    def provider_name(self) -> str: ...

    @property
    def isolation_grade(self) -> IsolationGrade:
        """What this provider's boundary is actually worth (ADR-024).

        Reported by the provider after inspecting its own environment,
        not declared by configuration. A Docker provider on a WSL2
        backend reports NONE however it was set up.
        """
        ...

    def self_test(self, policy: SandboxPolicy) -> SandboxSelfTest:
        """Verify that `policy` is actually enforced by this provider.

        Must genuinely attempt the things it claims to prevent - egress, a
        write to a read-only path, a privilege escalation - rather than
        reporting the configuration back.
        """
        ...

    def run(self, artefact_ref: str, *, policy: SandboxPolicy) -> SandboxRun:
        """Execute an artefact under `policy`.

        Raises:
            SandboxUnavailableError: if :meth:`self_test` does not pass. The
                implementation must call it; a caller forgetting to is not an
                acceptable way for isolation to be skipped.
        """
        ...
