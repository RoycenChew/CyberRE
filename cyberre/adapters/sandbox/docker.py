"""Docker sandbox provider.

The weakest provider in the ladder and the one most likely to be
misused, so most of this file is about establishing what it is *not*
good for.

Two things it does that a configuration-reading sandbox does not:

* **It grades itself from its environment.** A Docker daemon behind
  Docker Desktop's WSL2 backend reports `NONE`, because published
  techniques break that VM boundary and reach the Windows host. No
  configuration flag can talk it up.
* **Its self-test attempts the escapes.** It tries to reach the network,
  write a read-only path, and raise privileges, and reports what actually
  happened. A self-test that echoes back the flags it was passed tests
  the caller's spelling.

Suitable for running analysis tooling against an untrusted artefact.
Not suitable for detonating one - that needs `HYPERVISOR`, which means
CAPE, Firecracker, Kata or QEMU/KVM on a Linux host (ADR-024).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from cyberre.core.contracts.sandbox import (
    IsolationGrade,
    SandboxPolicy,
    SandboxRun,
    SandboxSelfTest,
    SandboxUnavailableError,
    SelfTestCheck,
)

#: A tiny image with a shell, pinned by digest. A tag could be repointed
#: underneath us, which would silently change what a reproducible run ran.
DEFAULT_IMAGE = "alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"

#: How long the self-test probes may take. Short: each is one command,
#: and a hanging probe must not stall the investigation.
PROBE_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class DockerEnvironment:
    """What the local Docker daemon actually is."""

    available: bool
    os_type: str = ""
    operating_system: str = ""
    server_version: str = ""
    security_options: tuple[str, ...] = ()
    detail: str = ""

    @property
    def is_wsl2_backend(self) -> bool:
        """Whether this is Docker Desktop over WSL2.

        Detected rather than configured. The WSL2 VM is not a hardened
        boundary - there are published escapes from it to the Windows
        host - so a provider sitting on it cannot honestly claim one.
        """
        haystack = f"{self.operating_system} {self.detail}".lower()
        return "docker desktop" in haystack or "wsl" in haystack

    @property
    def rootless(self) -> bool:
        return any("rootless" in option for option in self.security_options)


def inspect_docker() -> DockerEnvironment:
    """Ask the daemon what it is.

    Returns an unavailable environment rather than raising: a missing
    sandbox is a capability that cannot run, which the caller reports as
    a ToolFailure, not a crash.
    """
    binary = shutil.which("docker")
    if binary is None:
        return DockerEnvironment(available=False, detail="docker is not on PATH")

    try:
        completed = subprocess.run(  # fixed argv list, shell=False
            [binary, "info", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return DockerEnvironment(available=False, detail=f"docker info failed: {error}")

    if completed.returncode != 0:
        return DockerEnvironment(
            available=False,
            detail=(completed.stderr or completed.stdout).strip()[:200],
        )

    try:
        info = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        return DockerEnvironment(available=False, detail=f"unreadable docker info: {error}")

    return DockerEnvironment(
        available=True,
        os_type=str(info.get("OSType", "")),
        operating_system=str(info.get("OperatingSystem", "")),
        server_version=str(info.get("ServerVersion", "")),
        security_options=tuple(str(o) for o in info.get("SecurityOptions") or ()),
        detail=str(info.get("Name", "")),
    )


class DockerSandboxProvider:
    """Containerised execution, graded honestly."""

    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        environment: DockerEnvironment | None = None,
    ) -> None:
        self._image = image
        self._environment = environment if environment is not None else inspect_docker()
        self._binary = shutil.which("docker")

    @property
    def provider_name(self) -> str:
        return "docker"

    @property
    def environment(self) -> DockerEnvironment:
        return self._environment

    @property
    def isolation_grade(self) -> IsolationGrade:
        """What this boundary is worth here (ADR-024).

        `NONE` on a WSL2 backend, whatever the container flags say.
        `CONTAINER` on a native Linux daemon: namespaces and cgroups over
        a shared kernel, which a kernel exploit escapes.
        """
        if not self._environment.available:
            return IsolationGrade.NONE
        if self._environment.is_wsl2_backend:
            return IsolationGrade.NONE
        if self._environment.os_type != "linux":
            return IsolationGrade.NONE
        return IsolationGrade.CONTAINER

    # ------------------------------------------------------------ probing

    def _probe(self, policy: SandboxPolicy, command: list[str]) -> subprocess.CompletedProcess[str]:
        if self._binary is None:
            raise SandboxUnavailableError("docker is not on PATH")
        return subprocess.run(  # fixed argv list, shell=False
            [*self._run_arguments(policy), *command],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            check=False,
        )

    def _run_arguments(self, policy: SandboxPolicy) -> list[str]:
        assert self._binary is not None
        arguments = [
            self._binary,
            "run",
            "--rm",
            "--network",
            "bridge" if policy.network_enabled else "none",
            f"--memory={policy.limits.memory_mb}m",
            f"--cpus={policy.limits.cpus}",
            f"--pids-limit={policy.limits.pids}",
        ]
        if policy.read_only_filesystem:
            arguments.append("--read-only")
        if policy.drop_all_capabilities:
            arguments += ["--cap-drop", "ALL"]
        if policy.no_new_privileges:
            arguments += ["--security-opt", "no-new-privileges"]
        if policy.run_as_non_root:
            arguments += ["--user", "65534:65534"]
        arguments.append(policy.image_digest or self._image)
        return arguments

    def self_test(self, policy: SandboxPolicy) -> SandboxSelfTest:
        """Attempt the things the policy claims to prevent.

        Each check runs a command inside a container configured by the
        policy and reports what happened. A check that cannot be run is
        a failure, not a pass: an unverified boundary is an unknown one.
        """
        if not self._environment.available:
            return SandboxSelfTest(
                checks=(
                    SelfTestCheck(
                        name="daemon_available",
                        passed=False,
                        detail=self._environment.detail or "docker is not available",
                    ),
                )
            )

        checks: list[SelfTestCheck] = [
            SelfTestCheck(
                name="isolation_grade_sufficient",
                passed=self.isolation_grade is not IsolationGrade.NONE,
                detail=(
                    f"grade={self.isolation_grade.value}"
                    + (
                        "; Docker Desktop/WSL2 is not a security boundary"
                        if self._environment.is_wsl2_backend
                        else ""
                    )
                ),
            )
        ]

        probes: list[tuple[str, list[str], str]] = [
            (
                "network_isolated",
                ["sh", "-c", "wget -q -T 3 -O - http://1.1.1.1 >/dev/null 2>&1; echo $?"],
                "egress should fail",
            ),
            (
                "filesystem_read_only",
                ["sh", "-c", "touch /probe 2>/dev/null; echo $?"],
                "writing the root filesystem should fail",
            ),
            (
                "not_root",
                ["sh", "-c", "id -u"],
                "the process should not be uid 0",
            ),
            (
                "no_docker_socket",
                ["sh", "-c", "test -S /var/run/docker.sock; echo $?"],
                "the docker socket must not be mounted",
            ),
        ]

        for name, command, description in probes:
            try:
                completed = self._probe(policy, command)
            except (OSError, subprocess.TimeoutExpired, SandboxUnavailableError) as error:
                # Could not be verified, so it is not verified.
                checks.append(
                    SelfTestCheck(name=name, passed=False, detail=f"probe failed to run: {error}")
                )
                continue

            output = completed.stdout.strip().splitlines()
            last = output[-1] if output else ""
            passed = self._interpret(name, last, policy)
            checks.append(
                SelfTestCheck(
                    name=name,
                    passed=passed,
                    detail=f"{description}; probe returned '{last}'",
                )
            )

        return SandboxSelfTest(checks=tuple(checks))

    @staticmethod
    def _interpret(name: str, output: str, policy: SandboxPolicy) -> bool:
        if name == "network_isolated":
            if policy.network_enabled:
                return True  # egress is permitted by policy; nothing to assert
            return output not in {"0", ""}
        if name == "filesystem_read_only":
            return output != "0" if policy.read_only_filesystem else True
        if name == "not_root":
            return output not in {"0", ""} if policy.run_as_non_root else True
        if name == "no_docker_socket":
            return output != "0"
        return False

    def run(self, artefact_ref: str, *, policy: SandboxPolicy) -> SandboxRun:
        """Execute an artefact under `policy`.

        Not implemented. Detonating a sample needs `HYPERVISOR`
        isolation, and this provider cannot offer it on any host - a
        native Linux daemon reaches `CONTAINER` at best (ADR-024).

        Raising rather than offering a degraded execution is the whole
        point: a container that looks like a malware sandbox is more
        dangerous than no sandbox, because someone will trust it.
        """
        raise SandboxUnavailableError(
            "the Docker provider does not detonate samples. Container isolation "
            "shares the host kernel, so a kernel exploit escapes it. Detonation "
            "requires a HYPERVISOR-grade provider - CAPE, Firecracker, Kata or "
            "QEMU/KVM on a Linux host - or VMI-grade (DRAKVUF) for suspected "
            "evasive samples. See docs/adr/ADR-024-sandbox-isolation-grades.md."
        )
