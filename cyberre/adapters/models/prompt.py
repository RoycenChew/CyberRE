"""Prompt hashing and schema preparation.

Shared by every provider so that two providers given the same request record
the same `prompt_hash`, which is what lets a replay match a recorded response
and what makes a model call reproducible in the manifest.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from pydantic import BaseModel

from cyberre.core.contracts.model_provider import Message
from cyberre.core.models.base import stable_digest


def hash_prompt(
    messages: Sequence[Message],
    *,
    schema_name: str,
    template_version: str,
) -> str:
    """A stable digest of everything that determines the response.

    The schema is included because the same messages under a different
    output schema are a different request, and the template version because
    a prompt rewrite changes the analysis even when the evidence has not.
    """
    parts = [template_version, schema_name]
    for message in messages:
        parts.append(f"{message.role.value}\x1e{message.content}")
    return stable_digest(*parts)


def json_schema_for(schema: type[BaseModel]) -> dict[str, object]:
    """A JSON Schema for `schema`, in the shape endpoints expect.

    Pydantic emits `$defs` and `$ref` for nested models, which several
    OpenAI-compatible servers reject. Keeping nested models out of reasoner
    schemas is the simpler fix than inlining references here, and the test
    suite asserts it.
    """
    return schema.model_json_schema()


def schema_instruction(schema: type[BaseModel]) -> str:
    """A system instruction describing the required output.

    Used when an endpoint cannot constrain decoding. It is a fallback and
    not a guarantee - the response is still validated, and a parse failure
    is still a failure rather than an empty result.
    """
    return (
        "Respond with a single JSON object and nothing else. No prose before "
        "or after it, and no markdown fence. The object must match this JSON "
        f"Schema:\n{json.dumps(json_schema_for(schema), sort_keys=True)}"
    )


def extract_json_object(text: str) -> str:
    """Pull the JSON object out of a response that may be wrapped.

    Models wrap JSON in markdown fences or add a sentence of preamble even
    when told not to. Recovering from that is worth doing, but it is
    recovery rather than acceptance: whatever is extracted is still
    validated against the schema.
    """
    stripped = text.strip()

    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 2:
            body = lines[1:]
            if body and body[-1].strip().startswith("```"):
                body = body[:-1]
            stripped = "\n".join(body).strip()

    start = stripped.find("{")
    if start == -1:
        return stripped

    # Scan for the matching brace rather than taking the last one, which
    # would swallow trailing commentary containing braces.
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(stripped)):
        character = stripped[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return stripped[start : index + 1]
    return stripped[start:]
