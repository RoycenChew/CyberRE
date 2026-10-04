# CyberRE

Evidence-first AI cybersecurity and reverse-engineering investigation platform.

CyberRE investigates source code, binaries, dependencies and configurations,
and produces security findings that are backed by traceable evidence. It is not
a chatbot with security tools attached. Deterministic tooling produces evidence;
a reasoning model interprets that evidence; a deterministic validation engine
decides whether a claim is allowed to become a finding.

## The one idea that matters

```
observation -> interpretation -> hypothesis -> validation -> finding
```

These are distinct, typed stages. A language model may produce interpretations
and hypotheses. It may not produce findings. Only the validation engine can
promote a hypothesis to a finding, and only when the evidence required for that
class of vulnerability is actually present and independent.

Consequences, each enforced by a test rather than by convention:

- **Confidence is computed, never spoken.** It is derived from evidence
  completeness, independence, tool reliability and reviewer outcome, and it is
  capped by completeness - a finding missing most of its required evidence
  cannot score highly however persuasive the prose.
- **"Unknown" is a success.** `NOT_ENOUGH_EVIDENCE`, `UNREACHABLE`,
  `NOT_APPLICABLE` and `CONTRADICTED` are first-class outcomes. Uncertainty is
  never coerced into a severity.
- **Artefact content is data, never instruction.** Source, strings, comments and
  tool output reach the model only inside a fenced evidence packet.
- **Everything is reproducible.** Artefact hashes, tool versions, ruleset
  hashes, model and prompt versions are recorded, and investigations replay.

## Status

Under active development, through **M12**. The architecture is frozen and
documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

What works today:

- The full investigation chain - evidence, interpretation, evidence packet,
  hypothesis, validation, adversarial review, confidence, report - runs end
  to end for both a source-security and a binary reverse-engineering case.
  Exercise it with `pytest -m evaluation`.
- The Ghidra integration is verified against a real Ghidra 12.1.2
  installation, not only against fixtures.
- `cyberre capabilities`, `cyberre profiles` and `cyberre knowledge`.

What does not work yet: `cyberre investigate` against a path on disk.
Artefact ingestion and capability registration are the remaining wiring. The
command says so rather than half-working.

## Development

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows;  source .venv/bin/activate on POSIX
pip install -e ".[dev]"

pytest                        # all tiers except realtool
pytest -m architecture        # dependency-direction gate
ruff check . && mypy          # lint and types
```

`pytest -m realtool` requires real external tools (Ghidra, Semgrep, Docker) and
is run nightly, not in the normal loop. Fixture tests prove our parsers; they
never stand in for real-tool behaviour.

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Frozen architecture, invariants, milestones |
| [TRUST_MODEL.md](docs/TRUST_MODEL.md) | Trust levels and legal promotions |
| [SECURITY.md](docs/SECURITY.md) | Security posture, secrets, data residency |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What CyberRE defends against, and what it does not |
| [AGENTS.md](AGENTS.md) | Rules for coding agents working in this repository |
| [docs/adr/](docs/adr/) | Architecture decision records |

## Scope

CyberRE is for **authorised defensive security analysis**: reverse engineering,
vulnerability research, dependency and configuration review, and malware
analysis in controlled environments. It does not perform autonomous operations
against third-party systems.
