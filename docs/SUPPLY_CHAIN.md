# Supply Chain

CyberRE is a security product, so its own build is in scope. Full
implementation lands at M16; this records the policy now so dependencies are
added under it rather than retrofitted.

## Dependency classes

| Class | Meaning | Where declared |
|---|---|---|
| runtime | needed to run an investigation | `project.dependencies` |
| development | lint, types, tests | `optional-dependencies.dev` |
| optional | enables a capability when present | `optional-dependencies.<name>` |
| deferred | decided against for now, with an ADR | not declared |
| system | installed outside Python (Ghidra, JDK, Docker, Semgrep) | documented, never vendored |

M0 declares **no runtime dependencies**. Each is introduced by the milestone
that needs it, with a comment naming its purpose.

## Before adding a dependency

Answer in the pull request: is it necessary; is it maintained; is the licence
acceptable; could the standard library do it; does it create lock-in; does it
increase attack surface; does it materially improve CyberRE. Verify the package
name against the index before pinning - a typosquat in a security product is a
self-inflicted supply-chain compromise.

## Planned controls (M16)

Hash-pinned dependencies, `pip-audit` in CI, secret scanning on this
repository, CycloneDX SBOM per release, licence review gate, signed releases
and reproducible builds where practical.

## Credentials

No credential belongs in the repository, in CI logs, or in an issue. Git
authentication uses Git Credential Manager (browser OAuth) or SSH, never a
personal access token pasted into a file or a chat. An exposed credential is
revoked first and rotated second.
