# Trust Model

Every object in CyberRE carries a trust level. Promotion between levels happens
at one chokepoint per transition, and illegal promotions raise rather than
silently succeed. This is the mechanism behind invariants 1, 2, 5, 7 and 8 -
without it, those invariants are prose, and prose is not a control.

## Levels

| Level | Object | Instruction authority | May satisfy a validation requirement |
|---|---|---|---|
| 0 | `RAW_ARTEFACT` | none | no |
| 1 | `TOOL_OUTPUT` | none | no |
| 2 | `AGENT_CLAIM` | none | **never** (invariant 2) |
| 3 | `NORMALIZED_EVIDENCE` | none | yes |
| 4 | `DERIVED_EVIDENCE` | none | yes, if independent |
| 5 | `INTERPRETATION` | none | no |
| 6 | `HYPOTHESIS` | none | n/a - it is the subject |
| 7 | `VALIDATED_FINDING` | none | n/a - it is the output |

No object at any level carries instruction authority. Authority exists only in
system policy and developer configuration.

## Legal promotions

| From | To | Performed by | Requires |
|---|---|---|---|
| `RAW_ARTEFACT` | `TOOL_OUTPUT` | capability execution | policy allows the capability |
| `TOOL_OUTPUT` | `NORMALIZED_EVIDENCE` | an adapter's normaliser | complete provenance |
| `NORMALIZED_EVIDENCE` | `DERIVED_EVIDENCE` | deterministic transform | inherits `independence_key` |
| evidence + knowledge | `INTERPRETATION` | knowledge lookup or model | cites evidence IDs |
| `INTERPRETATION` | `HYPOTHESIS` | model | typed to a hypothesis class |
| `HYPOTHESIS` | `VALIDATED_FINDING` | **validation engine only** | requirement set satisfied by independent evidence |

## Permanently blocked

- `AGENT_CLAIM` to anything above level 2 without independent corroboration.
  A coding agent saying "this looks like command injection" is a lead, not a
  finding, and it cannot satisfy a requirement on its own.
- `INTERPRETATION` directly to `VALIDATED_FINDING`. Interpretation is where a
  model is most useful and least accountable; it must pass through a hypothesis
  and then through validation.
- `TOOL_OUTPUT` to anything, skipping normalisation. Normalisation is where
  provenance is attached; skipping it loses the audit trail (invariant 6).
- Any model output to level 7. Invariant 1.

## Independence

`independence_key` is a stored field derived from the root observation, not a
property computed on demand. Three parsed views of one Semgrep hit share one
key and count as one source. Counting them as three is the standard way these
systems inflate confidence, so the check lives inside the counting function
rather than at each call site (invariant 7).

## Tool failure is not evidence

A failed capability produces a `ToolFailure`, a distinct type with no path into
the evidence graph. An investigation that lost a tool reports `PARTIAL`; it does
not quietly report success with less evidence.
