"""The model gateway: tiers, structured output, retries and replay.

Most of these use a stub transport rather than a live endpoint. The point is
not to test httpx but to pin the behaviours that decide whether a failed
model call is distinguishable from an empty analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from cyberre.adapters.models.gateway import ModelConfigError, ModelGateway, StaticGateway
from cyberre.adapters.models.openai_compatible import (
    EndpointConfig,
    OpenAICompatibleProvider,
)
from cyberre.adapters.models.prompt import extract_json_object, hash_prompt
from cyberre.adapters.models.replay import (
    Cassette,
    RecordedCall,
    RecordingProvider,
    ReplayProvider,
)
from cyberre.core.contracts.model_provider import (
    Message,
    MessageRole,
    ModelFailureError,
    ModelProvider,
    ModelTier,
    ModelUsage,
    StructuredOutputMode,
)
from pydantic import BaseModel

pytestmark = pytest.mark.unit


class Verdict(BaseModel):
    verdict: str
    rationale: str


MESSAGES = [Message(role=MessageRole.USER, content="Is this injectable?")]


def chat_response(content: str, *, finish: str = "stop") -> dict[str, Any]:
    return {
        "choices": [{"message": {"content": content}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
    }


def provider_with(
    handler: Any, *, mode: StructuredOutputMode = StructuredOutputMode.JSON_MODE
) -> OpenAICompatibleProvider:
    transport = httpx.MockTransport(handler)
    return OpenAICompatibleProvider(
        EndpointConfig(
            name="stub",
            base_url="https://stub.invalid/v1",
            model="stub-1",
            structured_output=mode,
            max_retries=2,
        ),
        client=httpx.Client(transport=transport),
    )


def complete(provider: ModelProvider) -> Any:
    return provider.complete(
        MESSAGES,
        schema=Verdict,
        tier=ModelTier.REASONING,
        prompt_template_version="v1",
    )


class TestPromptHashing:
    def test_identical_requests_hash_identically(self) -> None:
        a = hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1")
        b = hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1")
        assert a == b

    def test_a_template_change_changes_the_hash(self) -> None:
        """A prompt rewrite changes the analysis even when the evidence has not."""
        assert hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1") != hash_prompt(
            MESSAGES, schema_name="Verdict", template_version="v2"
        )

    def test_a_schema_change_changes_the_hash(self) -> None:
        assert hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1") != hash_prompt(
            MESSAGES, schema_name="Other", template_version="v1"
        )


class TestExtractingJson:
    def test_a_bare_object_passes_through(self) -> None:
        assert extract_json_object('{"a": 1}') == '{"a": 1}'

    def test_a_markdown_fence_is_stripped(self) -> None:
        assert json.loads(extract_json_object('```json\n{"a": 1}\n```')) == {"a": 1}

    def test_preamble_is_discarded(self) -> None:
        assert json.loads(extract_json_object('Sure!\n{"a": 1}')) == {"a": 1}

    def test_trailing_commentary_with_braces_is_not_swallowed(self) -> None:
        """Taking the last brace would consume the commentary too."""
        assert json.loads(extract_json_object('{"a": 1}\nNote: {this} is not JSON.')) == {"a": 1}

    def test_braces_inside_strings_do_not_confuse_the_scan(self) -> None:
        text = '{"a": "a } brace"}'
        assert json.loads(extract_json_object(text)) == {"a": "a } brace"}


class TestStructuredOutput:
    def test_a_valid_response_parses(self) -> None:
        provider = provider_with(
            lambda request: httpx.Response(
                200, json=chat_response('{"verdict": "no", "rationale": "parameterised"}')
            )
        )
        result = complete(provider)
        assert result.value.verdict == "no"
        assert result.usage.input_tokens == 100

    def test_a_wrapped_response_is_recovered(self) -> None:
        provider = provider_with(
            lambda request: httpx.Response(
                200,
                json=chat_response(
                    'Here you go:\n```json\n{"verdict": "yes", "rationale": "shell=True"}\n```'
                ),
            )
        )
        assert complete(provider).value.verdict == "yes"

    def test_strict_mode_sends_the_schema(self) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(200, json=chat_response('{"verdict": "no", "rationale": "x"}'))

        complete(provider_with(handler, mode=StructuredOutputMode.STRICT_SCHEMA))
        assert seen["response_format"]["type"] == "json_schema"
        assert seen["response_format"]["json_schema"]["strict"] is True

    def test_json_mode_adds_a_schema_instruction(self) -> None:
        """An endpoint that cannot constrain decoding is told what to emit."""
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(200, json=chat_response('{"verdict": "no", "rationale": "x"}'))

        complete(provider_with(handler, mode=StructuredOutputMode.JSON_MODE))
        assert seen["messages"][0]["role"] == "system"
        assert "JSON Schema" in seen["messages"][0]["content"]

    def test_temperature_defaults_to_zero(self) -> None:
        """Sampling variation means two runs over identical evidence can
        disagree, which breaks replay."""
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(json.loads(request.content))
            return httpx.Response(200, json=chat_response('{"verdict": "no", "rationale": "x"}'))

        complete(provider_with(handler))
        assert seen["temperature"] == 0.0


class TestBoundedRepair:
    def test_one_repair_attempt_recovers_a_bad_envelope(self) -> None:
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            if len(attempts) == 1:
                return httpx.Response(200, json=chat_response("I think it is injectable."))
            return httpx.Response(200, json=chat_response('{"verdict": "yes", "rationale": "ok"}'))

        result = complete(provider_with(handler))
        assert result.value.verdict == "yes"
        assert len(attempts) == 2

    def test_a_second_failure_is_not_retried_again(self) -> None:
        """Two repairs would be chasing a model that cannot follow the
        schema, which is a configuration problem rather than a transient."""
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            return httpx.Response(200, json=chat_response("still not JSON"))

        with pytest.raises(ModelFailureError, match=r"did not match Verdict|not valid JSON"):
            complete(provider_with(handler))
        assert len(attempts) == 2

    def test_repair_usage_is_accumulated(self) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(200, json=chat_response("nope"))
            return httpx.Response(200, json=chat_response('{"verdict": "no", "rationale": "x"}'))

        assert complete(provider_with(handler)).usage.input_tokens == 200


class TestFailuresAreNeverSilent:
    def test_a_truncated_response_says_so(self) -> None:
        """Reporting truncation as a parse failure would send the caller
        looking in the wrong place."""
        provider = provider_with(
            lambda request: httpx.Response(
                200, json=chat_response('{"verdict": "y', finish="length")
            )
        )
        with pytest.raises(ModelFailureError, match="truncated"):
            complete(provider)

    def test_an_empty_response_is_a_failure_not_an_empty_result(self) -> None:
        provider = provider_with(lambda request: httpx.Response(200, json=chat_response("   ")))
        with pytest.raises(ModelFailureError, match="no content"):
            complete(provider)

    def test_no_choices_is_a_failure(self) -> None:
        provider = provider_with(lambda request: httpx.Response(200, json={"choices": []}))
        with pytest.raises(ModelFailureError, match="no choices"):
            complete(provider)

    def test_a_non_json_body_is_a_failure(self) -> None:
        provider = provider_with(lambda request: httpx.Response(200, text="<html>"))
        with pytest.raises(ModelFailureError, match="not JSON"):
            complete(provider)


class TestRetries:
    def test_a_rate_limit_is_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _: None)
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            if len(attempts) < 3:
                return httpx.Response(429, text="slow down")
            return httpx.Response(200, json=chat_response('{"verdict": "no", "rationale": "x"}'))

        assert complete(provider_with(handler)).value.verdict == "no"
        assert len(attempts) == 3

    def test_a_bad_request_is_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It will be wrong again; retrying wastes time and money."""
        monkeypatch.setattr("time.sleep", lambda _: None)
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            return httpx.Response(400, text="bad model name")

        with pytest.raises(ModelFailureError, match="rejected the request"):
            complete(provider_with(handler))
        assert len(attempts) == 1

    def test_exhausted_retries_report_the_last_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("time.sleep", lambda _: None)
        provider = provider_with(lambda request: httpx.Response(503, text="down"))
        with pytest.raises(ModelFailureError, match="did not respond after 3 attempts"):
            complete(provider)


class TestReplay:
    def _cassette(self) -> Cassette:
        prompt_hash = hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1")
        return Cassette(
            calls=(
                RecordedCall(
                    prompt_hash=prompt_hash,
                    schema_name="Verdict",
                    template_version="v1",
                    tier=ModelTier.REASONING,
                    model_id="recorded-1",
                    provider="stub",
                    response_json='{"verdict": "no", "rationale": "parameterised"}',
                    usage=ModelUsage(input_tokens=10, output_tokens=5),
                ),
            )
        )

    def test_a_recorded_response_is_served(self) -> None:
        result = complete(ReplayProvider(self._cassette()))
        assert result.value.verdict == "no"
        assert result.model_id == "recorded-1"

    def test_a_miss_is_an_error_not_a_live_call(self) -> None:
        """Falling back would make a replay silently stop being one."""
        provider = ReplayProvider(Cassette())
        with pytest.raises(ModelFailureError, match="no recorded response"):
            complete(provider)

    def test_a_schema_change_misses_rather_than_mismatching(self) -> None:
        """The prompt hash covers the schema, so asking for a different one
        is a clean miss rather than a wrong answer."""

        class Different(BaseModel):
            decision: str

        provider = ReplayProvider(self._cassette())
        with pytest.raises(ModelFailureError, match="no recorded response"):
            provider.complete(
                MESSAGES,
                schema=Different,
                tier=ModelTier.REASONING,
                prompt_template_version="v1",
            )

    def test_a_hand_edited_cassette_is_caught(self) -> None:
        """Cassettes are committed files that people edit. If one is altered
        so its recorded schema no longer matches the request it answers, that
        must fail rather than deserialise into something that happens to
        validate."""
        prompt_hash = hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1")
        tampered = Cassette(
            calls=(
                RecordedCall(
                    prompt_hash=prompt_hash,
                    schema_name="SomethingElse",
                    template_version="v1",
                    tier=ModelTier.REASONING,
                    model_id="m",
                    provider="p",
                    response_json='{"verdict": "no", "rationale": "x"}',
                ),
            )
        )
        with pytest.raises(ModelFailureError, match="holds a SomethingElse"):
            complete(ReplayProvider(tampered))

    def test_a_cassette_whose_recorded_value_no_longer_validates_fails(self) -> None:
        prompt_hash = hash_prompt(MESSAGES, schema_name="Verdict", template_version="v1")
        stale = Cassette(
            calls=(
                RecordedCall(
                    prompt_hash=prompt_hash,
                    schema_name="Verdict",
                    template_version="v1",
                    tier=ModelTier.REASONING,
                    model_id="m",
                    provider="p",
                    response_json='{"verdict": "no"}',
                ),
            )
        )
        with pytest.raises(ModelFailureError, match="stale"):
            complete(ReplayProvider(stale))

    def test_served_calls_are_counted(self) -> None:
        """So a test can assert how many model calls a flow made - the
        performance target is under six for a STANDARD investigation."""
        provider = ReplayProvider(self._cassette())
        complete(provider)
        complete(provider)
        assert len(provider.served) == 2

    def test_replay_is_deterministic(self) -> None:
        first = complete(ReplayProvider(self._cassette())).value
        second = complete(ReplayProvider(self._cassette())).value
        assert first == second

    def test_recording_round_trips_through_a_file(self, tmp_path: Path) -> None:
        inner = provider_with(
            lambda request: httpx.Response(
                200, json=chat_response('{"verdict": "yes", "rationale": "shell"}')
            )
        )
        recorder = RecordingProvider(inner, path=tmp_path / "cassette.json")
        complete(recorder)
        path = recorder.save()

        replayed = complete(ReplayProvider.from_file(path))
        assert replayed.value.verdict == "yes"

    def test_a_cassette_is_sorted_for_review(self, tmp_path: Path) -> None:
        path = tmp_path / "c.json"
        Cassette(
            calls=(
                RecordedCall(
                    prompt_hash="ffff",
                    schema_name="Verdict",
                    template_version="v1",
                    tier=ModelTier.FAST,
                    model_id="m",
                    provider="p",
                    response_json="{}",
                ),
                RecordedCall(
                    prompt_hash="0000",
                    schema_name="Verdict",
                    template_version="v1",
                    tier=ModelTier.FAST,
                    model_id="m",
                    provider="p",
                    response_json="{}",
                ),
            )
        ).save(path)
        hashes = [c["prompt_hash"] for c in json.loads(path.read_text())["calls"]]
        assert hashes == sorted(hashes)


class TestGatewayConfiguration:
    def _document(self) -> dict[str, Any]:
        return {
            "providers": {
                "local": {"base_url": "http://localhost:11434/v1", "api_key_env": ""},
                "remote": {
                    "base_url": "https://api.example.invalid/v1",
                    "api_key_env": "EXAMPLE_KEY",
                },
            },
            "tiers": {
                "fast": {"provider": "local", "model": "small"},
                "reasoning": {"provider": "remote", "model": "large"},
            },
        }

    def test_tiers_resolve_to_providers(self) -> None:
        gateway = ModelGateway.from_mapping(self._document())
        assert gateway.describe() == {
            "fast": "local/small",
            "reasoning": "remote/large",
        }

    def test_tiers_can_use_different_providers(self) -> None:
        """A reviewer sharing the reasoner's blind spots is a weaker check."""
        gateway = ModelGateway.from_mapping(self._document())
        assert (
            gateway.describe()["fast"].split("/")[0]
            != (gateway.describe()["reasoning"].split("/")[0])
        )

    def test_a_local_provider_needs_no_credential(self) -> None:
        gateway = ModelGateway.from_mapping(self._document())
        assert gateway.provider_for(ModelTier.FAST).provider_name == "local"

    def test_a_missing_credential_fails_at_resolution(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovering it halfway through a deep investigation would waste
        everything done up to that point."""
        monkeypatch.delenv("EXAMPLE_KEY", raising=False)
        gateway = ModelGateway.from_mapping(self._document())
        with pytest.raises(ModelConfigError, match="EXAMPLE_KEY"):
            gateway.provider_for(ModelTier.REASONING)

    def test_a_tier_naming_an_unknown_provider_is_rejected(self) -> None:
        document = self._document()
        document["tiers"]["fast"]["provider"] = "ghost"
        with pytest.raises(ModelConfigError, match="not configured"):
            ModelGateway.from_mapping(document)

    def test_the_required_tiers_must_exist(self) -> None:
        document = self._document()
        del document["tiers"]["reasoning"]
        with pytest.raises(ModelConfigError, match="reasoning"):
            ModelGateway.from_mapping(document)

    def test_the_shipped_configuration_is_valid(self) -> None:
        gateway = ModelGateway.from_file(
            Path(__file__).resolve().parents[2] / "config" / "models.toml"
        )
        assert "fast" in gateway.describe()
        assert "reasoning" in gateway.describe()

    def test_credentials_are_never_read_from_the_file(self) -> None:
        """A config can be committed; a key cannot."""
        text = (Path(__file__).resolve().parents[2] / "config" / "models.toml").read_text(
            encoding="utf-8"
        )
        assert "api_key =" not in text
        assert "api_key_env" in text

    def test_a_static_gateway_serves_preconstructed_providers(self) -> None:
        replay = ReplayProvider(Cassette())
        gateway = StaticGateway({ModelTier.REASONING: replay})
        assert gateway.provider_for(ModelTier.REASONING) is replay
        with pytest.raises(ModelConfigError):
            gateway.provider_for(ModelTier.FAST)


class TestProtocolConformance:
    def test_both_providers_satisfy_the_protocol(self) -> None:
        assert isinstance(ReplayProvider(Cassette()), ModelProvider)
        assert isinstance(
            provider_with(lambda r: httpx.Response(200, json=chat_response("{}"))),
            ModelProvider,
        )
