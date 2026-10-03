# AGENTS.md - rules for coding agents in this repository

Read this before modifying anything. It applies to Claude Code, Codex, Pi and
any future engineering agent. The repository is the source of truth; a
conversation is not.

## What this project is

CyberRE is an evidence-first security investigation platform. The architecture
is **frozen** and documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Do not redesign it in passing. If a change requires an architectural decision,
write an ADR in `docs/adr/` and raise it rather than deciding silently.

## Two planes - do not confuse them

- **Investigation plane** (`cyberre/`) - the product. Analyses code and binaries.
- **Engineering plane** (`devplane/`) - contracts describing how coding agents
  contribute. You are in the engineering plane.

`cyberre/` must never import `devplane/`. CyberRE has to run with no coding
agent present (invariants 12-14). A test enforces this.

## Your output is a claim, not a finding

If you analyse code and conclude "this has SQL injection", that is an
`AgentClaim` - trust level 2. It cannot satisfy a validation requirement, and it
cannot become a finding. CyberRE must establish it independently through
deterministic tooling. Do not write code that lets an agent assertion shortcut
validation; that is invariant 2 and it is not negotiable.

## Hard rules

1. **Dependency direction.** `core` imports nothing from `adapters`, `agent`,
   `capabilities`, `knowledge`, `runtime`, `cli`, `api` or `devplane`.
   Run `pytest -m architecture`.
2. **Vendor confinement.** Ghidra, Docker, LangGraph, model SDKs, SQLAlchemy and
   friends are importable only inside their adapter. See
   `tests/architecture/boundaries.py` for the table.
3. **No relative imports.** Ruff enforces this.
4. **No secrets in code.** Ever. Env vars only; `.env` is git-ignored.
5. **Typed.** `mypy` is strict on `cyberre.core`.
6. **Tests with the change.** A behaviour change without a test is incomplete.
7. **No silent architecture changes.** New package, new dependency or new
   boundary means an ADR.
8. **Fixtures never substitute for real tools.** A fixture test proves a parser.
   Only the `realtool` tier proves the tool works.

## Adding a dependency

Answer in the PR: is it necessary; is it maintained; is the licence acceptable;
could the standard library do it; does it create lock-in; does it increase
attack surface. Add it to `pyproject.toml` with a comment naming its purpose.

## Workflow

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy
pytest -m architecture
pytest -m "not realtool"
```

All four must pass before you call work complete. Report failures honestly - a
milestone with failing tests is not done, and saying so is more useful than a
green summary that is not true.

## Test tiers

| Marker | Proves | Runs |
|---|---|---|
| `unit` | pure logic | always |
| `contract` | every implementation of a protocol behaves identically | always |
| `integration` | components together with real local storage | always |
| `fixture` | parsing of recorded tool output | always |
| `realtool` | the actual external tool behaves as assumed | nightly, release gate |
| `security`, `injection`, `sandbox` | security controls hold | always |
| `evaluation`, `regression` | detection quality has not regressed | always |
| `architecture` | structure and dependency direction | always |

## Commit style

Imperative subject, milestone prefix where relevant:
`M0: add import-boundary enforcement`. Explain *why* in the body when the
reason is not obvious from the diff.
