# ADR-016: Evidence independence is a stored field

## Status
Accepted.

## Context
Three parsers over one Semgrep hit are one observation, not three corroborating
sources. Counting them as three is the standard way these systems inflate
confidence. An earlier draft computed independence as an on-demand graph query,
which depends on every caller remembering to ask.

## Decision
`independence_key` is derived from the root observation and stored on the
evidence record; derived evidence inherits it. The independence check lives
inside the counting function used by validation and confidence, not at call
sites.

## Consequences
Invariant 7 cannot be forgotten. The cost is that normalisers must derive the
key correctly, which is covered by adapter tests.
