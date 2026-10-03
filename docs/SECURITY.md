# Security

CyberRE analyses hostile input and is therefore itself an attack surface. This
document states the posture; [THREAT_MODEL.md](THREAT_MODEL.md) states what is
and is not defended against.

## Secrets

Never commit API keys, tokens, passwords or credentials. `.env` is git-ignored;
`.env.example` documents the variable names and holds no values.

If a credential is exposed - in a commit, a log, an issue or a chat transcript -
**revoke it first and rotate second**. Deleting the commit does not help: the
value is already out.

Secrets are redacted at three chokepoints by `SecretBoundary` (M4+):

1. anything entering model context,
2. anything entering logs or traces,
3. anything entering a report.

Redaction at the sink, not by developer discipline at each call site.

## Untrusted content

Artefact content - source, comments, README files, strings extracted from
binaries, scanner output, threat-intelligence text - is **data**. It never
reaches the model as a message. It reaches the model only inside a fenced block
within a compiled evidence packet, and the model's only actionable output
channel is a typed action validated against the capability registry. Free text
cannot invoke a capability.

Text that looks like an injection attempt is recorded as
`EvidenceType.SUSPECTED_INJECTION` - an observation *about* the artefact, which
is itself a useful security signal.

## Execution

Dynamic analysis (M13) is fail-closed. A sandbox self-test asserts network
isolation, filesystem restriction, capability dropping, privilege restriction
and resource limits before any untrusted code runs. If any assertion fails,
analysis is refused. There is no override flag.

Docker is the development sandbox. It is **not** a hardened enterprise malware
analysis environment, and the project does not claim otherwise. Stronger
isolation (Firecracker, dedicated VMs) slots in behind the same provider
interface.

## Model providers and data residency

CyberRE sends evidence packets - which may contain source code and decompiled
functions - to whichever model provider is configured. **Where that data goes is
a deployment decision with procurement consequences**, so it is configuration,
not code.

| Provider | Data leaves host | Suitable for |
|---|---|---|
| Local (Ollama, vLLM) | no | sensitive and regulated work |
| Commercial API | yes, to that vendor | per the customer's data policy |
| Subscription bridge (OpenCode et al.) | yes, via an unofficial path | **development only** - see ADR-018 |

A subscription bridge is a valid local development convenience and is not a
supported deployment target: it shares rate limits with interactive use, depends
on undocumented internals, and would make CyberRE depend on a coding agent,
violating invariants 12-14.

## Scope

Authorised defensive security analysis only. CyberRE does not implement
autonomous operations against third-party systems. Action risk levels 4 and 5
are blocked unless an explicit policy exists, and level 3 requires human
approval through the Approval Gateway.

## Reporting a vulnerability

Open a private security advisory on the repository. Please do not file a public
issue for an unpatched vulnerability.
