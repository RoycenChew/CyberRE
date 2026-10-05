# Threat Model

## Assets

1. The host running CyberRE.
2. Customer artefacts under analysis (often proprietary source or incident data).
3. Investigation records - evidence, findings and their provenance.
4. Credentials: model provider keys, repository access, storage.
5. The integrity of findings. A platform that can be induced to emit a false
   finding, or to suppress a true one, has failed at its purpose.

## Adversaries

| Adversary | Capability | Primary mitigation |
|---|---|---|
| Malicious artefact author | Crafts a binary or repository submitted for analysis | Sandbox isolation, fenced untrusted content, typed action channel |
| Prompt-injection author | Embeds instructions in source, comments, strings or docs | Artefact content has no instruction authority; registry-validated actions; injection regression corpus |
| Supply-chain attacker | Compromises a CyberRE dependency | Pinned hashed dependencies, dependency and secret scanning, SBOM (M16) |
| Curious or careless operator | Runs analysis with excessive permissions | Five-way permission intersection, fail-closed policy, Approval Gateway |
| Model provider | Receives evidence packet content | Data-residency configuration, local-model option, redaction |

## Defended

- Untrusted artefact text cannot become a trusted instruction.
- A language model cannot create a finding; only validation can.
- A coding agent's claim cannot satisfy a validation requirement.
- A profile cannot widen policy; effective permissions are an intersection.
- Dynamic analysis cannot run when sandbox self-test fails.
- A sandbox weaker than the work requires refuses; it does not warn and proceed.
- Tool failures cannot silently become evidence.
- Evidence cannot lose provenance during normalisation.
- Derived evidence cannot masquerade as independent corroboration.

## Explicitly NOT defended (V1)

Stated plainly, because an unstated limitation reads as a claim.

1. **Container escape.** Still real, but no longer silent. Docker shares the
   host kernel, so a kernel exploit escapes it, and Docker Desktop's WSL2
   backend has published escapes to the Windows host. Rather than warn about
   this, M13 made isolation strength a typed, ordered grade that the policy
   engine checks: the Docker provider reports `CONTAINER` on a native Linux
   daemon and `NONE` on a WSL2 backend, detonation requires `HYPERVISOR`, and
   `DockerSandboxProvider.run()` raises on every host. The defence is a
   refusal, not hardening - CyberRE cannot detonate a sample until a
   `HYPERVISOR`-grade provider exists (ADR-024).
2. **Malicious model provider.** A provider that returns adversarially crafted
   output is constrained by validation and the typed action channel, but is not
   otherwise detected.
3. **Compromised host.** CyberRE assumes the machine it runs on is trustworthy.
4. **Multi-tenant isolation.** V1 is single-tenant. No tenant separation exists.
5. **Denial of service.** Budgets bound a single investigation; there is no
   protection against a deliberately expensive artefact beyond those budgets.
6. **Ghidra as an attack surface.** Ghidra parses hostile binaries and has had
   parser vulnerabilities. V1 runs headless analysis on the host. Running it
   inside the sandbox is tracked for a later milestone; it is an
   `ANALYSIS_TOOL` intent, so `CONTAINER` grade suffices and a native Linux
   host can already provide it.
7. **Sandbox evasion.** A sample that detects analysis and behaves differently
   produces a confidently wrong result rather than no result. This is why
   `SUSPECTED_EVASIVE` requires `VMI` grade - agentless introspection - which
   nothing in V1 provides. Until it does, the honest answer is UNKNOWN.

## Residual risks accepted for V1

- No dynamic analysis at all on this class of host (see 1 above). Accepted
  deliberately: a container that looks like a malware sandbox is more
  dangerous than none, because someone will trust it.
- Knowledge-layer seed is small; absence of a signature is not evidence of
  absence, and the confidence model must never treat it as such.
- Real-tool coverage depends on the nightly tier actually running.
