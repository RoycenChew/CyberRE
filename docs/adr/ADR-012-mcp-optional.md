# ADR-012: MCP is optional and absent from V1

## Status
Accepted.

## Context
MCP is a reasonable way to expose capabilities to external clients. It is a poor
foundation to build a platform on, because it would make a protocol choice
load-bearing for the domain.

## Decision
No MCP in V1 and no code path that requires it. Capabilities are reached through
the typed registry. An MCP adapter may be added later as one more interface
alongside CLI and API.

## Consequences
No MCP ecosystem benefits yet. The core stays usable from plain Python, which is
what the CLI, the API and any future adapter all depend on.
