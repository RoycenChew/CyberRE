"""A provider for any OpenAI-compatible chat-completions endpoint.

One adapter covers DeepSeek, local runtimes (Ollama, vLLM), OpenAI and most
aggregators, because they all speak the same wire format (ADR-006). Which one
is in use is configuration, not code.

Structured output degrades in a defined order, and the order matters: strict
schema-constrained decoding where the endpoint supports it, then JSON mode
with validation, then one bounded repair attempt, then failure. What it never
does is return a partially-parsed or empty result - a reasoning step that
silently yields nothing would read as "no hypotheses found", which is a very
different claim from "the model call failed".
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from cyberre.adapters.models.prompt import (
    extract_json_object,
    hash_prompt,
    json_schema_for,
    schema_instruction,
)
from cyberre.core.contracts.model_provider import (
    Message,
    MessageRole,
    ModelFailureError,
    ModelResult,
    ModelTier,
    ModelUsage,
    StructuredOutputMode,
)

T = TypeVar("T", bound=BaseModel)

#: Status codes worth retrying. A 400 means the request is wrong and will be
#: wrong again; retrying it wastes time and money.
RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True)
class EndpointConfig:
    """How to reach one endpoint, and what it can do.

    `structured_output` is declared rather than probed because support varies
    widely and a wrong guess surfaces as a confusing parse failure deep in a
    reasoning step. Declaring it keeps the failure at configuration time.
    """

    name: str
    base_url: str
    model: str
    api_key: str | None = None
    structured_output: StructuredOutputMode = StructuredOutputMode.JSON_MODE
    temperature: float = 0.0
    """Zero by default. Sampling variation in a security analysis means two
    runs over identical evidence can disagree, which breaks replay."""

    max_retries: int = 2
    connect_timeout: float = 10.0
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def completions_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/chat/completions"


class OpenAICompatibleProvider:
    """Chat completions over the OpenAI wire format."""

    def __init__(
        self,
        config: EndpointConfig,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._owns_client = client is None

    @property
    def provider_name(self) -> str:
        return self._config.name

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        return self._config.structured_output

    @property
    def config(self) -> EndpointConfig:
        return self._config

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def _http(self, timeout: float) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json", **self._config.headers}
            if self._config.api_key:
                headers["Authorization"] = f"Bearer {self._config.api_key}"
            self._client = httpx.Client(
                timeout=httpx.Timeout(timeout, connect=self._config.connect_timeout),
                headers=headers,
            )
        return self._client

    # ------------------------------------------------------------ protocol

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
        prepared = self._prepare(messages, schema)
        started = time.monotonic()

        payload = self._payload(prepared, schema, max_output_tokens)
        raw, usage = self._post(payload, timeout_seconds)

        try:
            value = self._parse(raw, schema)
        except ModelFailureError:
            # One bounded repair attempt. Models frequently produce valid
            # content in an invalid envelope, and a single corrective turn
            # recovers most of those. Two would be chasing a model that
            # cannot follow the schema, which is a configuration problem.
            repaired_messages = [
                *prepared,
                Message(role=MessageRole.ASSISTANT, content=raw[:2000] or "(empty)"),
                Message(
                    role=MessageRole.USER,
                    content=(
                        "That response was not valid JSON matching the required "
                        "schema. Reply with only the JSON object."
                    ),
                ),
            ]
            raw, repair_usage = self._post(
                self._payload(repaired_messages, schema, max_output_tokens), timeout_seconds
            )
            usage = ModelUsage(
                input_tokens=usage.input_tokens + repair_usage.input_tokens,
                output_tokens=usage.output_tokens + repair_usage.output_tokens,
            )
            value = self._parse(raw, schema)

        latency_ms = int((time.monotonic() - started) * 1000)
        return ModelResult(
            value=value,
            model_id=self._config.model,
            provider=self._config.name,
            tier=tier,
            parameters={
                "temperature": self._config.temperature,
                "max_tokens": max_output_tokens,
                "structured_output": self._config.structured_output.value,
            },
            prompt_template_version=prompt_template_version,
            prompt_hash=prompt_hash,
            usage=ModelUsage(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                latency_ms=latency_ms,
            ),
        )

    # ----------------------------------------------------------- internals

    def _prepare(self, messages: Sequence[Message], schema: type[BaseModel]) -> list[Message]:
        """Add a schema instruction when the endpoint cannot enforce one."""
        prepared = list(messages)
        if self._config.structured_output is not StructuredOutputMode.STRICT_SCHEMA:
            prepared.insert(0, Message(role=MessageRole.SYSTEM, content=schema_instruction(schema)))
        return prepared

    def _payload(
        self, messages: Sequence[Message], schema: type[BaseModel], max_tokens: int
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self._config.model,
            "messages": [{"role": m.role.value, "content": m.content} for m in messages],
            "temperature": self._config.temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }

        mode = self._config.structured_output
        if mode is StructuredOutputMode.STRICT_SCHEMA:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema.__name__,
                    "strict": True,
                    "schema": json_schema_for(schema),
                },
            }
        elif mode is StructuredOutputMode.JSON_MODE:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def _post(self, payload: dict[str, Any], timeout_seconds: int) -> tuple[str, ModelUsage]:
        client = self._http(float(timeout_seconds))
        last_error: str = "no attempt was made"

        for attempt in range(self._config.max_retries + 1):
            try:
                response = client.post(self._config.completions_url, json=payload)
            except httpx.TimeoutException as error:
                last_error = f"timeout after {timeout_seconds}s: {error}"
            except httpx.HTTPError as error:
                last_error = f"transport error: {error}"
            else:
                if response.status_code in RETRYABLE_STATUS:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                elif response.status_code >= 400:
                    # Not retryable: the request is wrong and will be wrong
                    # again.
                    raise ModelFailureError(
                        f"{self._config.name} rejected the request with HTTP "
                        f"{response.status_code}: {response.text[:300]}"
                    )
                else:
                    return self._read(response)

            if attempt < self._config.max_retries:
                time.sleep(min(2.0**attempt, 8.0))

        raise ModelFailureError(
            f"{self._config.name} did not respond after "
            f"{self._config.max_retries + 1} attempts: {last_error}"
        )

    @staticmethod
    def _read(response: httpx.Response) -> tuple[str, ModelUsage]:
        try:
            body = response.json()
        except ValueError as error:
            raise ModelFailureError(f"response body is not JSON: {error}") from error

        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ModelFailureError(f"response contains no choices: {str(body)[:300]}")

        first = choices[0]
        finish_reason = first.get("finish_reason")
        message = first.get("message") if isinstance(first, dict) else None
        content = message.get("content") if isinstance(message, dict) else None

        if finish_reason == "length":
            # Truncated output is almost always invalid JSON, and reporting
            # it as a parse failure would send the caller looking in the
            # wrong place.
            raise ModelFailureError(
                "the response was truncated by the token limit; raise "
                "max_output_tokens or reduce the evidence packet"
            )

        if not isinstance(content, str) or not content.strip():
            raise ModelFailureError("the response contained no content")

        raw_usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        usage = ModelUsage(
            input_tokens=int(raw_usage.get("prompt_tokens") or 0),
            output_tokens=int(raw_usage.get("completion_tokens") or 0),
        )
        return content, usage

    @staticmethod
    def _parse(raw: str, schema: type[T]) -> T:
        candidate = extract_json_object(raw)
        try:
            return schema.model_validate_json(candidate)
        except ValidationError as error:
            raise ModelFailureError(
                f"response did not match {schema.__name__}: {error.errors()[:3]}"
            ) from error
        except ValueError as error:
            raise ModelFailureError(f"response was not valid JSON: {error}") from error


def provider_from_mapping(data: dict[str, Any]) -> OpenAICompatibleProvider:
    """Build a provider from a configuration mapping.

    Used by the config loader so that switching from DeepSeek to a local
    model is an edit to one file (ADR-018).
    """
    mode = data.get("structured_output", StructuredOutputMode.JSON_MODE.value)
    return OpenAICompatibleProvider(
        EndpointConfig(
            name=str(data["name"]),
            base_url=str(data["base_url"]),
            model=str(data["model"]),
            api_key=data.get("api_key"),
            structured_output=StructuredOutputMode(mode),
            temperature=float(data.get("temperature", 0.0)),
            max_retries=int(data.get("max_retries", 2)),
        )
    )
