"""Recording and replaying model responses.

Makes every test that involves reasoning deterministic and free, and makes an
investigation replayable end to end (invariant 20). Without it, the graph
tests would either call a live model - slow, costly, and different every run
- or mock the gateway, which proves only that the mock works.

Two modes:

* **Replay** serves recorded responses by prompt hash. A miss is an error,
  not a live call: a replay run that quietly reached the network would stop
  being a replay without saying so.
* **Record** wraps a real provider, passes calls through and saves them.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from cyberre.adapters.models.prompt import hash_prompt
from cyberre.core.contracts.model_provider import (
    Message,
    ModelFailureError,
    ModelProvider,
    ModelResult,
    ModelTier,
    ModelUsage,
    StructuredOutputMode,
)
from cyberre.core.models.base import DomainModel, NonEmptyStr

T = TypeVar("T", bound=BaseModel)


class RecordedCall(DomainModel):
    """One model call, keyed by what determined its response."""

    prompt_hash: NonEmptyStr
    schema_name: NonEmptyStr
    template_version: NonEmptyStr
    tier: ModelTier
    model_id: NonEmptyStr
    provider: NonEmptyStr
    response_json: NonEmptyStr
    """The validated response, stored as JSON rather than as a parsed object
    so a cassette stays readable and diffable in review."""

    usage: ModelUsage = ModelUsage()


class Cassette(DomainModel):
    """A set of recorded calls, saved as one file."""

    version: int = 1
    calls: tuple[RecordedCall, ...] = ()

    def index(self) -> dict[str, RecordedCall]:
        return {call.prompt_hash: call for call in self.calls}

    @classmethod
    def load(cls, path: Path) -> Cassette:
        try:
            return cls.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as error:
            raise ModelFailureError(f"cassette {path} could not be read: {error}") from error

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Sorted by hash so a re-record produces a reviewable diff rather
        # than a reordered file.
        ordered = Cassette(
            version=self.version, calls=tuple(sorted(self.calls, key=lambda c: c.prompt_hash))
        )
        path.write_text(
            json.dumps(json.loads(ordered.model_dump_json()), indent=2, sort_keys=True),
            encoding="utf-8",
        )


class ReplayProvider:
    """Serves recorded responses. Never reaches the network."""

    def __init__(self, cassette: Cassette, *, name: str = "replay") -> None:
        self._name = name
        self._calls = cassette.index()
        self._served: list[str] = []

    @classmethod
    def from_file(cls, path: Path, *, name: str = "replay") -> ReplayProvider:
        return cls(Cassette.load(path), name=name)

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        """A recording is already schema-valid by construction."""
        return StructuredOutputMode.STRICT_SCHEMA

    @property
    def served(self) -> tuple[str, ...]:
        """Prompt hashes served, in order. Lets a test assert how many model
        calls a flow actually made - the performance target is under six for
        a STANDARD investigation."""
        return tuple(self._served)

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
        prompt_hash = hash_prompt(
            messages, schema_name=schema.__name__, template_version=prompt_template_version
        )
        recorded = self._calls.get(prompt_hash)
        if recorded is None:
            # Deliberately an error. Falling back to a live call would make a
            # replay silently stop being one, and falling back to a default
            # would fabricate reasoning.
            raise ModelFailureError(
                f"no recorded response for prompt {prompt_hash[:12]} "
                f"(schema {schema.__name__}, template {prompt_template_version}). "
                f"Re-record the cassette if the prompt changed."
            )

        if recorded.schema_name != schema.__name__:
            raise ModelFailureError(
                f"recorded call {prompt_hash[:12]} holds a {recorded.schema_name}, "
                f"but a {schema.__name__} was requested"
            )

        self._served.append(prompt_hash)
        try:
            value = schema.model_validate_json(recorded.response_json)
        except ValidationError as error:
            raise ModelFailureError(
                f"recorded response for {prompt_hash[:12]} no longer matches "
                f"{schema.__name__}; the schema changed and the cassette is stale: {error}"
            ) from error

        return ModelResult(
            value=value,
            model_id=recorded.model_id,
            provider=self._name,
            tier=tier,
            parameters={"replayed": True},
            prompt_template_version=prompt_template_version,
            prompt_hash=prompt_hash,
            usage=recorded.usage,
        )


class RecordingProvider:
    """Wraps a real provider and records what it returns."""

    def __init__(self, inner: ModelProvider, *, path: Path) -> None:
        self._inner = inner
        self._path = path
        self._recorded: list[RecordedCall] = []

    @property
    def provider_name(self) -> str:
        return f"recording:{self._inner.provider_name}"

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        return self._inner.structured_output_mode

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
        result = self._inner.complete(
            messages,
            schema=schema,
            tier=tier,
            prompt_template_version=prompt_template_version,
            max_output_tokens=max_output_tokens,
            timeout_seconds=timeout_seconds,
        )
        self._recorded.append(
            RecordedCall(
                prompt_hash=result.prompt_hash,
                schema_name=schema.__name__,
                template_version=prompt_template_version,
                tier=tier,
                model_id=result.model_id,
                provider=result.provider,
                response_json=result.value.model_dump_json(),
                usage=result.usage,
            )
        )
        return result

    def save(self) -> Path:
        """Write the cassette. Call once the flow being recorded is done."""
        Cassette(calls=tuple(self._recorded)).save(self._path)
        return self._path
