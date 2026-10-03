"""Sandbox contract.

The important part of this file is :class:`SandboxSelfTest`. Dynamic analysis
is the one place where a configuration mistake lets hostile code run with more
access than intended, so the contract requires a provider to *prove* its
isolation before it will be used, and failure refuses the run (invariant 11).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr


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


@runtime_checkable
class SandboxProvider(Protocol):
    """Isolated execution for untrusted artefacts."""

    @property
    def provider_name(self) -> str: ...

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
