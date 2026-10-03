# ADR-004: Ghidra via headless subprocess, with three test tiers

## Status
Accepted.

## Context
Ghidra can be driven in-process (pyghidra/JPype) or as a subprocess
(`analyzeHeadless` plus a script). In-process couples the Ghidra JVM lifetime to
our process, is fragile on Windows, and is hard to sandbox later. Separately, it
is tempting to treat recorded fixtures as proof the integration works. They are
not; they prove the parser works.

## Decision
Subprocess `analyzeHeadless` with a versioned Jython export script emitting one
JSON document. Results cached on
`(sha256, ghidra_version, script_version, analysis_config)`.

Three named test tiers, never conflated:

- `fixture` - recorded JSON through the parser. Always in CI.
- `integration` - adapter, storage and graph with a stub runner. Always in CI.
- `realtool` - live headless Ghidra. Nightly, and a release gate.

## Consequences
A release may not claim production readiness on fixture tests alone. Ghidra is
absent from the current development machine, so the `realtool` tier is written
but unexecuted until it is installed - tracked openly at each milestone rather
than allowed to look finished.
