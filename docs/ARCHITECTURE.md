# CyberRE Architecture

**Status: frozen.** Changes require an ADR in [`adr/`](adr/).

Origin documents are preserved in [`prompts/`](prompts/): the master build
prompt and the original design document. Where they conflict with this file,
this file governs; the five recorded divergences are ADR-013 to ADR-017.

---

## 1. Principle

Deterministic tooling produces evidence. A model reasons over that evidence. A
deterministic engine decides whether a claim may become a finding.

```
observation -> interpretation -> hypothesis -> validation -> finding
```

Each arrow is a typed promotion through a chokepoint that can refuse. Remove any
chokepoint and a named invariant fails - which is what makes the invariant list
testable rather than decorative.

The optimisation target is **Time to Justified Conclusion**: not tokens, not
tool count, not agent count. A faster unsupported answer is worse than a slower
justified one, because an unsupported answer costs the analyst the verification
work anyway.

## 2. Layers and dependency direction

```
          knowledge/ (data + pure lookup)
                 ^
core/models -> core/contracts -> core/{trust,evidence,findings,policies,profiles}
                 ^                        ^
            adapters/*                 agent/logic
                 ^                        ^
                 +------- runtime/ -------+
                              ^
                          cli/   api/

devplane/ -> cyberre.core (types only).  cyberre/ never imports devplane/.
```

Vendor dependencies (Ghidra, Docker, model SDKs, LangGraph, SQLAlchemy, lief)
live only in their adapter. Enforced by `tests/architecture/`.

| Package | Owns | Must not |
|---|---|---|
| `core/contracts` | protocols: Capability, EvidenceStore, ObjectStore, ModelProvider, SandboxProvider, KnowledgeSource, ReportGenerator | import any adapter |
| `core/models` | Artefact, Evidence, Hypothesis, Finding, Provenance, InvestigationState, ToolFailure | hold logic beyond validation |
| `core/trust` | trust levels and the promotion chokepoint | be bypassable |
| `core/evidence` | graph, dedup, independence, contradiction, compiler | call a model directly |
| `core/findings` | requirement sets, validation, confidence formula | call a model |
| `core/policies` | risk levels, effective permissions, approval gateway, budget | be widened by a profile |
| `core/profiles` | AnalysisProfile model and resolution | grant authority |
| `agent/logic` | planning and decision functions (pure) | import a workflow engine |
| `agent/graph` | LangGraph nodes - thin wrappers | hold business rules |
| `adapters/*` | tool I/O and normalisation into core models | leak tool types upward |
| `devplane/` | coding-agent contracts, handoff, audit | be imported by `cyberre/` |

## 3. Investigation lifecycle

```
request -> intake -> scope + profile -> effective permissions
   -> strategy (depth, budget) -> +-> plan actions (information gain)
                                  |      v
                                  |   policy gate --deny--> recorded, replan
                                  |      |  approval? --> Approval Gateway
                                  |      v
                                  |   execute --fail--> ToolFailure (not evidence)
                                  |      v
                                  |   ingest -> interpret -> update hypotheses
                                  |      v
                                  |   sufficient? --no & budget--+
                                  v
                            compile context (the only path to the model)
                            -> reason (two-pass) -> candidate findings
                            -> VALIDATE -> REVIEW -> CONFIDENCE -> report
```

Budget exhaustion ends the investigation as `PARTIAL`. It does not fabricate a
conclusion.

## 4. Evidence

```
artefact --hash--> ObjectStore
capability --> raw output --> ObjectStore(raw_ref)
                 v
            normaliser + Provenance{tool, version, config_hash,
                                    artefact_hash, ruleset_hash, timestamp}
                       + independence_key = H(root observation)
                 v
             Evidence --> EvidenceStore --> EvidenceGraph
```

Evidence is immutable; a correction is new evidence with `supersedes`. Edge
kinds: `derived_from`, `supports`, `contradicts`, `depends_on`, `observed_in`,
`generated_by`, `validated_by`, `applies_to`.

Trust levels and legal promotions: [TRUST_MODEL.md](TRUST_MODEL.md).

## 5. Validation, review, confidence

Validation looks up a **requirement set** by hypothesis class and evaluates
deterministic predicates over the evidence graph. Outcomes include
`NOT_ENOUGH_EVIDENCE`, `CONTRADICTED`, `UNREACHABLE`, `NOT_APPLICABLE`,
`NEEDS_REVIEW`, `UNVALIDATED`, `VALIDATED`. Unknown is a success state.

A package-name match is never sufficient for a CVE. Product, version-in-range
and configuration conditions are each separate requirements.

The adversarial reviewer returns `UPHOLD | DOWNGRADE | REJECT |
REQUEST_MORE_EVIDENCE`, mapping to a multiplier in `{1.0, 0.5, 0.0}`. The
codomain has no value above 1.0, so the reviewer cannot raise confidence by
construction (invariant 9).

```
base = sum(w_i * f_i) over:
   evidence_completeness, evidence_independence, tool_reliability,
   source_corroboration, reachability_established, provenance_quality,
   contradiction_penalty

confidence = min(base, completeness) * reviewer_multiplier * validation_gate
             validation_gate = 1.0 if VALIDATED else 0.0
```

`min(base, completeness)` caps confidence at evidence completeness.
`validation_gate` makes invariant 1 arithmetic: an unvalidated hypothesis scores
exactly zero. The model emits no numbers at any point.

## 6. Permissions

```
global policy  INTERSECT  environment policy  INTERSECT  profile policy
               INTERSECT  capability policy   INTERSECT  user permissions
               = effective permissions
```

Intersection only. A profile may request and may forbid; it can never widen
(invariant 3). Risk levels 0-2 may be automatic subject to policy, level 3
requires human approval, levels 4-5 are blocked absent explicit policy. The
Approval Gateway is a core domain service, not a workflow-engine feature, so
replacing the runtime cannot remove it.

## 7. Analysis profiles

Declarative TOML, not agents (ADR-021). Fully implemented in V1: `BINARY_RE`,
`SOURCE_SECURITY`, `DEPENDENCY_SECURITY`, `MALWARE_ANALYSIS` (static only).
Declared but failing explicitly: `VULNERABILITY_RESEARCH`, `THREAT_HUNTING`,
`INCIDENT_INVESTIGATION`. Multiple active profiles union requirements and
intersect policy.

## 8. Reverse engineering

`binfmt` (format, architecture, sections, entropy, imports) then `ghidra`
(functions, decompilation, xrefs, call graph), interpreted through the RE
knowledge layer.

An imported API is an observation. The knowledge layer makes it an
interpretation. A finding requires the **API sequence plus a reachable path** -
a graph query, not a model judgement. `VirtualAllocEx` alone is not injection.

Ghidra runs as a subprocess: `analyzeHeadless` plus a versioned export script,
cached on `(sha256, ghidra_version, script_version, analysis_config)`.

## 9. Knowledge

Structured (`knowledge/re/`, `knowledge/threat/`) - versioned data files with
provenance, source reference, confidence and applicability conditions.
Deterministic lookup, no embeddings.

Semantic (`knowledge/semantic/`, M16) - long-form references. **May never
satisfy a validation requirement.** It can inform a hypothesis; it cannot
confirm one.

## 10. Performance

Time to Justified Conclusion is the metric. Design consequences:

- Planner emits an action **set**; independent capabilities run concurrently.
- Content-addressed caching at every layer (Ghidra projects, scanner results,
  knowledge lookups, model calls by prompt hash).
- Incremental re-analysis of changed files plus reverse-dependency closure.
- Lazy decompilation - never decompile a whole binary up front.
- Target under six model calls for a STANDARD investigation; routing, severity,
  CVSS, hashing and reachability are deterministic and cost nothing.
- Hard evidence-packet budget in the compiler.

Targets measured from M14: FAST under 30s, STANDARD under 3min (source) and
under 5min (binary, warm cache), DEEP under 20min.

## 11. Code quality

Typed, modular, documented, deterministic where possible. `mypy` strict on
`core`. Coverage floor 90% on `core`. Every protocol has at least two
implementations exercised by one shared contract suite - that is what makes
"replaceable" a tested claim. No god classes, no global mutable state, no
hard-coded paths, model names, provider logic or credentials.

## 12. Milestones

| M | Milestone | State |
|---|---|---|
| M0 | Foundation, CI, boundary rules | **complete** |
| M1 | Core contracts, typed models, trust model | **complete** |
| M2 | Evidence, provenance, evidence graph | **complete** |
| M3 | Storage, replay, deterministic fixtures | **complete** |
| M4 | Capability registry, policy engine, approval gateway | **complete** |
| M5 | Analysis profiles | **complete** |
| M6 | Ghidra adapter, fixtures, real-tool spec | **complete** (realtool tier unverified - Ghidra not installed) |
| M7 | RE knowledge layer | **complete** |
| M8 | Source security capabilities | **complete** (realtool tier unverified - Semgrep not installed) |
| M9 | Model gateway, LangGraph runtime | next - needs provider key for live use |
| M10 | Validation engine, requirement sets | |
| M11 | Adversarial reviewer, confidence engine | |
| M12 | **Dual vertical slice** - source + binary, through validation | needs Ghidra |
| M13 | Sandbox, dynamic analysis | |
| M14 | Evaluation, benchmark, FP/FN, injection regression | |
| M15 | Engineering plane foundation | |
| M16 | Enterprise hardening - observability, Postgres, API, SBOM | |

Validation (M10) and review (M11) precede the first demonstration (M12) by
design. Before M10 the system may produce only `CandidateFinding`, which the
report generator cannot render - the demo path is structurally unavailable
until something exists that can reject a finding (ADR-002).

## 13. Architecture invariants

1. Model output cannot directly become a finding.
2. An `AgentClaim` cannot satisfy a validation requirement.
3. Profiles cannot grant permissions.
4. Global policy overrides profile preferences.
5. Untrusted artefact text cannot become a trusted instruction.
6. Provenance cannot be lost during normalisation.
7. Derived evidence does not automatically count as independent.
8. Validation must precede a validated finding.
9. The reviewer cannot increase confidence beyond validated evidence.
10. Unknown is a valid final state.
11. Dynamic analysis cannot run when sandbox checks fail.
12. CyberRE core does not depend on Claude Code.
13. CyberRE core does not depend on Codex.
14. CyberRE core does not depend on Pi.
15. CyberRE core does not depend directly on LangGraph.
16. CyberRE core does not depend directly on Ghidra.
17. Storage is replaceable.
18. The model provider is replaceable.
19. Tool adapters are replaceable.
20. Investigations are replayable.
21. Source-security and binary-RE slices both have real acceptance tests.
22. False negatives are measured.
23. Security regression tests exist.
24. Supply-chain security is part of enterprise readiness.

Invariants 1-4, 6, 7, 9, 10 and 11 are enforced today by `cyberre/core/trust`,
`cyberre/core/policies`
and the domain models, with tests in `tests/unit/` and `tests/contract/`.
Invariants 12-19 are enforced by `tests/architecture/`. The remainder are
enforced by the milestone that introduces the component, and each milestone's
acceptance criteria name the test.

## 14. Deferred

CodeQL (ADR-007), MCP adapter, Binary Ninja and radare2 adapters, pgvector
semantic knowledge, PostgreSQL, REST API, Firecracker isolation, agent router
and worktree orchestration, cross-agent consensus, differential/regression
reverse engineering, MIPS and RISC-V knowledge, the three stub profiles.
