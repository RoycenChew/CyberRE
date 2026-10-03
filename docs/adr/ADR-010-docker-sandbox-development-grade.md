# ADR-010: The Docker sandbox is development-grade, and says so

## Status
Accepted.

## Context
Container isolation is commonly described as sufficient for malware analysis. It
is not. A kernel exploit escapes a container. On Windows, Docker Desktop adds a
VM boundary, which helps, but the honest description is still "development
sandbox", not "hardened malware environment".

## Decision
Docker is the V1 `SandboxProvider`. A self-test asserts network isolation,
read-only filesystem, dropped capabilities, no privilege escalation, resource
limits and no Docker socket, before any untrusted execution. Any failed
assertion refuses the run; there is no override. The limitation is stated in
`SECURITY.md` and `THREAT_MODEL.md`. Firecracker or dedicated VMs implement the
same provider later.

## Consequences
The project does not claim enterprise malware-analysis readiness because
`docker run` works. Invariant 11 is enforced fail-closed.
