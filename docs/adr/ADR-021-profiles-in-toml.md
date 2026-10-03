# ADR-021: Profiles are TOML, parsed with the standard library

## Status
Accepted. Changes the file format named in the frozen architecture (YAML).

## Context
Analysis profiles are declarative configuration: read at startup, never
written by the program, edited by humans. The architecture named YAML, which
would mean adding PyYAML.

Two things argue against it. The dependency policy asks whether the standard
library can do the job, and since Python 3.11 `tomllib` reads TOML with no
dependency at all. And this is a security product parsing configuration that
determines what it is permitted to execute - PyYAML's `load` has a history of
arbitrary code execution, and while `safe_load` is the answer, the safe
behaviour is the one that has to be remembered. `tomllib` has no unsafe mode
to remember not to use.

TOML is also the better fit for what a profile actually is: flat tables of
scalars and string lists, with no nesting deep enough for YAML's expressiveness
to earn its cost. The project already uses TOML for `pyproject.toml`, so a
contributor meets one config syntax rather than two.

## Decision
Profiles live in `profiles/*.toml` and are parsed with `tomllib`. No YAML
dependency.

## Consequences
One fewer dependency, and no unsafe parser mode anywhere near the files that
decide what CyberRE may run.

TOML is less comfortable than YAML for deeply nested structures. If a profile
ever needs that depth, it is a sign the profile has stopped being declarative
configuration and has started being a program - which ADR-008 says it must not
become. The awkwardness is a useful signal rather than a cost.
