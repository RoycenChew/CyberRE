# ADR-006: OpenAI-compatible provider first; provider chosen by config

## Status
Accepted. Replaces an earlier decision to write an Anthropic adapter first.

## Context
The platform must not depend on one model vendor. The practical observation is
that most providers - DeepSeek, local runtimes (Ollama, vLLM), OpenAI, several
aggregators, and subscription bridges such as OpenCode - speak the same
OpenAI-compatible wire format. Writing one vendor adapter first would have been
narrower for the same effort.

## Decision
`ModelProvider` is the protocol. The first implementation is
`OpenAICompatibleProvider`, parameterised by `base_url`, credential and model
id. Provider and tier mapping live in `config/models.yaml`; changing provider is
a config edit. `ReplayProvider` serves recorded responses for deterministic CI.
An `AnthropicProvider` is added separately if wanted - different wire format.

Structured output degrades in a defined order: strict schema-constrained
decoding, then JSON mode with validation, then one bounded repair attempt, then
`ModelFailure`. Never a silent partial parse.

## Consequences
One adapter covers most of the market and invariant 18 is cheap to satisfy.
Capability varies across endpoints, so each adapter instance declares what it
supports rather than assuming.
