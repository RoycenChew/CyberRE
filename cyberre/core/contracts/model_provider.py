"""The model gateway contract.

Core states what it needs from a language model and nothing about who serves
it. Vendor SDKs live in ``cyberre.adapters.models`` and nowhere else, which an
architecture test enforces (invariant 18).
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, Field

from cyberre.core.models.base import DomainModel, NonEmptyStr

T = TypeVar("T", bound=BaseModel)


class ModelTier(StrEnum):
    """What a call is for, not which model serves it.

    Callers ask for a tier; configuration maps tiers to concrete models. This
    is what keeps model names out of the code (and lets the reviewer run on a
    different model from the reasoner without a code change).
    """

    FAST = "fast"
    """Classification, routing, extraction, summarisation."""

    REASONING = "reasoning"
    """Evidence correlation, hypothesis analysis, adversarial review."""

    SPECIALIST = "specialist"
    EMBEDDING = "embedding"


class MessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class Message(DomainModel):
    role: MessageRole
    content: NonEmptyStr


class StructuredOutputMode(StrEnum):
    """How strictly an endpoint can be made to honour a schema.

    Support varies widely across OpenAI-compatible endpoints, so an adapter
    declares what it has rather than assuming; the gateway degrades in a
    defined order and never accepts a silent partial parse (ADR-006).
    """

    STRICT_SCHEMA = "strict_schema"
    JSON_MODE = "json_mode"
    NONE = "none"


class ModelUsage(DomainModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)


class ModelResult[ResultT: BaseModel](DomainModel):
    """A parsed model response plus everything needed to reproduce it.

    `prompt_hash` and `prompt_template_version` are recorded because "the
    model said so" is not reproducible, while "model X at temperature Y given
    prompt digest Z said so" can be re-examined.
    """

    value: ResultT
    model_id: NonEmptyStr
    provider: NonEmptyStr
    tier: ModelTier
    parameters: dict[str, Any] = Field(default_factory=dict)
    prompt_template_version: NonEmptyStr
    prompt_hash: NonEmptyStr
    usage: ModelUsage = ModelUsage()


class ModelFailureError(Exception):
    """The provider did not return a usable, schema-valid result.

    Raised rather than returning a default. A reasoning step that silently
    yields an empty result would look like "no hypotheses found", which is a
    very different claim from "the model call failed".
    """


@runtime_checkable
class ModelProvider(Protocol):
    """A source of language-model completions."""

    @property
    def provider_name(self) -> str: ...

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        """What this endpoint can actually guarantee about schema conformance."""
        ...

    def complete(
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        tier: ModelTier,
        prompt_template_version: str,
        max_output_tokens: int = 4096,
        timeout_seconds: int = 120,
    ) -> ModelResult[T]:
        """Return a parsed, schema-valid result.

        Raises:
            ModelFailureError: on transport failure, or when the response
                cannot be parsed into `schema` after the adapter's bounded
                repair attempt.
        """
        ...
