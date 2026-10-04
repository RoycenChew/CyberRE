# Reverse Engineering Knowledge Layer

Structured, versioned facts that turn observations into interpretations.
Deterministic lookup, no model, no embeddings (ADR-017, ADR-021).

## Where it sits

```
observation          imports VirtualAllocEx                    (evidence, L3)
    |  knowledge lookup
interpretation       VirtualAllocEx is an injection primitive   (L5)
    |  reasoner
hypothesis           this binary may perform process injection  (L6)
    |  validation: sequence present AND reachable path
finding              process injection is supported by evidence (L7)
```

The layer only ever produces the second step. It never asserts a behaviour,
because an import is not a call and a call is not a reachable path.

## Domains

| Directory key | Holds | Primary use |
|---|---|---|
| `formats` | PE, ELF, Mach-O structure and anomalies | Interpreting sections and entry points |
| `arch` | Calling conventions, prologues, register roles | Argument recovery, idiom recognition |
| `compilers` | MSVC, GCC, Go, Rust, .NET fingerprints | **Suppressing** findings that are really runtime |
| `apis` | Windows API semantics and danger classes | Turning an import into an interpretation |
| `behaviours` | Technique catalogue keyed to ATT&CK | Proposing hypothesis classes |
| `antianalysis` | Anti-debug, anti-VM, anti-disassembly | A signal, and a reason to discount dynamic results |
| `packing` | Packer and protector signatures | Lowering confidence in static findings |

The compiler table is the one most likely to be undervalued. Recognising that
a Go binary has an almost-empty import table by design, rather than because
of API hashing, is one of the highest-value false-positive reductions
available.

## Record schema

Every record carries, without exception:

- `id` - namespaced and stable
- `version` - bumped when the claim changes, so a finding that leaned on
  version 1 can be re-examined when version 2 disagrees
- `statement` - written for a reader, since it is rendered into reports
- `source_ref` - a citation. A knowledge base without them is opinions with
  extra steps, and a claim at confidence 0.9 or above is rejected if its
  citation is too short to check
- `confidence` - in *the claim itself*, not in any investigation. A documented
  API contract is near certain; a packer signature inferred from samples is not
- `applicability` - OS, architecture, format. Without it a knowledge base lies
  by omission: "LoadLibrary indicates dynamic resolution" is meaningless on
  Linux

And, where they apply:

- `companions` - the calls that together form a recognised sequence. **This is
  what stops a single scary import becoming a finding**: validation looks for
  the sequence, not the symbol
- `benign_explanation` - the innocent reading. Not optional politeness. Most
  uses of most dangerous APIs are legitimate, and a table that omits this
  trains the system toward false positives. It travels with the
  interpretation so the reviewer has the counter-argument to hand

## Current seed

54 records: 22 Windows APIs, 6 behaviours, 8 anti-analysis techniques,
5 packers, 5 compiler fingerprints, 8 format and architecture records.

Deliberately small. The schema matters more than the volume, and expansion is
a data change requiring no code (correction section 13).

## Adding a record

Append to the relevant file under `cyberre/knowledge/re/data/`. Cite a source
a reader can check. Give the innocent reading if there is one. Set confidence
honestly - a guess at 0.9 is worse than an accurate 0.6, because the
confidence engine will carry it through to a finding.

Knowledge data ships inside the package because it is reference material the
product depends on. Profiles live at the repository root because they are
deployment configuration an operator edits.

## Not here

Semantic retrieval over long-form research and advisories arrives at M16,
under `knowledge/semantic/`. It answers the same protocol with
`is_authoritative = False` and **may never satisfy a validation requirement**:
a passage that reads as relevant is not a fact that applies.
