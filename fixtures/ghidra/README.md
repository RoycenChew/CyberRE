# Ghidra export fixtures

Recorded `cyberre_export.py` output, used by the **fixture** test tier.

**These prove the parser. They do not prove Ghidra works.** Only the
`realtool` tier does that (ADR-004), and a release may not claim production
readiness on fixtures alone.

| Fixture | What it is | What it is for |
|---|---|---|
| `injector_pe.json` | A PE whose `inject()` calls OpenProcess, VirtualAllocEx, WriteProcessMemory and CreateRemoteThread, reachable from `main` | The positive case for `behaviour:process_injection`, and the binary half of the M12 acceptance test |
| `benign_allocator_pe.json` | A PE importing `VirtualAllocEx` for ordinary allocation into its own process | The false-positive trap. The import is present and the sequence is not, so the hypothesis must fail rather than produce a finding |
| `truncated_analysis.json` | An analysis Ghidra did not finish | Partial coverage must be reported as partial, never as a clean result |

## Provenance of these files

Hand-authored against the schema in `cyberre/adapters/ghidra/scripts/cyberre_export.py`
(`schema_version = 1`, `script_version = 1.0.0`), describing programs
constructed for this purpose. No third-party or live malware sample is
involved, and none should be added here.

They are hand-authored rather than captured because Ghidra is not installed
on the current development machine. When it is, these should be regenerated
from real analyses of equivalent self-compiled binaries and the difference
reviewed - a hand-written fixture encodes what we *expect* the tool to emit,
which is exactly the assumption the `realtool` tier exists to check.

## Adding a fixture

Keep the binaries self-compiled or benign and publicly documented. Record
here what the fixture represents and which test depends on it, so a fixture
whose purpose is forgotten can be removed rather than preserved out of
caution.
