# ADR-024: Sandboxes are graded, and the grade gates detonation

## Status
Accepted. Extends ADR-010, which said the Docker sandbox is
development-grade; this says how that is enforced rather than documented.

## Context
Research into the current tooling produced one finding that changes the
design and one that constrains this machine.

**The tools form a clear hierarchy, and it is not a matter of taste.**

| Grade | Technology | Boundary | Notes |
|---|---|---|---|
| `VMI` | DRAKVUF on Xen | Hypervisor, agentless | Second-generation sandbox: no in-guest agent to detect, so it holds up against evasive and fileless malware where agent-based sandboxes do not. Needs dedicated hardware. |
| `HYPERVISOR` | CAPE, Firecracker, Kata, QEMU/KVM | Separate guest kernel | CAPE is the practical malware-analysis standard - it unpacks, extracts C2 configuration and secondary payloads, and runs YARA during detonation. Firecracker's VMM is ~50k lines of Rust against QEMU's ~1.4M of C, so the escape surface is small. All require Linux with KVM. |
| `USERSPACE_KERNEL` | gVisor | Syscalls intercepted by a Go kernel | No KVM needed. The Sentry is a smaller target than a kernel but is still software, not hardware, isolation. |
| `CONTAINER` | Docker with hardening | Shared host kernel | A kernel exploit escapes. Suitable for untrusted *analysis tooling*, not untrusted *samples*. |
| `NONE` | Docker Desktop on WSL2, bare process | Not a security boundary | Published escape techniques break Docker Desktop's WSL2 VM isolation and reach the Windows host. |

**This machine cannot host a malware sandbox.** Firecracker, gVisor and
Kata are Linux-only and the first two of those need KVM. Docker Desktop
here runs the WSL2 backend, which is the row the research names explicitly
as not a hardened boundary. Windows Sandbox is Hyper-V backed but ships
with networking enabled and is not an analysis environment.

Sandbox evasion is also now the fourth most common technique observed
across malware, so a weak sandbox does not merely risk escape - it
produces *wrong answers*, because the sample behaves differently when it
detects the box.

## Decision
Isolation strength becomes a typed, ordered value on the provider, and the
policy engine requires a minimum grade before an artefact may be detonated.
The requirement scales with what is being run: analysis tooling over a
sample needs `CONTAINER`, an untrusted sample needs `HYPERVISOR`, and
suspected evasive malware needs `VMI`.

A provider below the required grade **refuses**. It does not warn and
proceed. The self-test is a real attempt at egress, at writing a read-only
path and at privilege escalation - not a reading back of the configuration
that was requested.

`NONE` is a grade a provider can report. Docker on a WSL2 backend reports
it, and therefore cannot detonate anything.

## Consequences
CyberRE will not pretend to be a malware sandbox on a machine that cannot
be one. On this host, dynamic analysis of a real sample is refused with a
message naming the grade required and the grade available.

That is the point. The alternative - a Docker container on WSL2 that looks
like protection - is worse than no sandbox at all, because someone would
trust it.

The grades are an interface, not an implementation. `CAPESandboxProvider`,
`FirecrackerSandboxProvider` and `DrakvufSandboxProvider` satisfy the same
protocol and report higher grades; adding one is an adapter, and the policy
layer already knows what to do with it.
