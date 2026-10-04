"""The model gateway: tier to provider, resolved from configuration.

Callers ask for a *tier* - fast, reasoning, specialist - and never for a
model. That is what keeps model names out of the code, lets the reviewer run
on a different model from the reasoner without a code change, and makes
switching provider an edit to one file (ADR-006).

Credentials are read from the environment at resolution time and never from
the configuration file, so a config can be committed and a key cannot.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyberre.adapters.models.openai_compatible import (
    EndpointConfig,
    OpenAICompatibleProvider,
)
from cyberre.core.contracts.model_provider import ModelProvider, ModelTier, StructuredOutputMode

DEFAULT_CONFIG_PATH = Path("config") / "models.toml"


class ModelConfigError(ValueError):
    """The model configuration is unusable.

    Raised at startup rather than at the first model call. Discovering a
    missing API key halfway through a deep investigation wastes everything
    done up to that point.
    """


@dataclass(frozen=True)
class ProviderSpec:
    """One configured endpoint, before its credential is resolved."""

    name: str
    base_url: str
    api_key_env: str | None
    structured_output: StructuredOutputMode
    temperature: float
    max_retries: int

    def credential(self) -> str | None:
        # An empty string means the same as absent. TOML has no null, so a
        # local provider declares `api_key_env = ""`, and treating that as a
        # variable named "" would make every local deployment fail at
        # startup with a baffling message.
        if not self.api_key_env:
            return None  # a local runtime needs none
        key = os.environ.get(self.api_key_env)
        if not key:
            raise ModelConfigError(
                f"provider '{self.name}' needs {self.api_key_env}, which is not set. "
                f"Set it in .env, or point the tier at a local provider."
            )
        return key


class ModelGateway:
    """Resolves tiers to providers."""

    def __init__(
        self,
        providers: Mapping[str, ProviderSpec],
        tiers: Mapping[ModelTier, tuple[str, str]],
    ) -> None:
        self._providers = dict(providers)
        self._tiers = dict(tiers)
        self._instances: dict[ModelTier, ModelProvider] = {}

        for tier, (provider_name, _) in self._tiers.items():
            if provider_name not in self._providers:
                raise ModelConfigError(
                    f"tier '{tier.value}' names provider '{provider_name}', which is not configured"
                )

    @classmethod
    def from_file(cls, path: Path = DEFAULT_CONFIG_PATH) -> ModelGateway:
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as error:
            raise ModelConfigError(f"{path}: not valid TOML: {error}") from error
        except OSError as error:
            raise ModelConfigError(f"{path}: cannot be read: {error}") from error
        return cls.from_mapping(document)

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> ModelGateway:
        raw_providers = document.get("providers")
        if not isinstance(raw_providers, dict) or not raw_providers:
            raise ModelConfigError("configuration declares no providers")

        providers: dict[str, ProviderSpec] = {}
        for name, raw in raw_providers.items():
            if not isinstance(raw, dict):
                raise ModelConfigError(f"provider '{name}' must be a table")
            if "base_url" not in raw:
                raise ModelConfigError(f"provider '{name}' has no base_url")
            try:
                mode = StructuredOutputMode(
                    raw.get("structured_output", StructuredOutputMode.JSON_MODE.value)
                )
            except ValueError as error:
                raise ModelConfigError(
                    f"provider '{name}': unknown structured_output '{raw.get('structured_output')}'"
                ) from error
            providers[str(name)] = ProviderSpec(
                name=str(name),
                base_url=str(raw["base_url"]),
                api_key_env=raw.get("api_key_env"),
                structured_output=mode,
                temperature=float(raw.get("temperature", 0.0)),
                max_retries=int(raw.get("max_retries", 2)),
            )

        raw_tiers = document.get("tiers")
        if not isinstance(raw_tiers, dict):
            raise ModelConfigError("configuration declares no tiers")

        tiers: dict[ModelTier, tuple[str, str]] = {}
        for tier_name, raw in raw_tiers.items():
            try:
                tier = ModelTier(tier_name)
            except ValueError as error:
                raise ModelConfigError(f"unknown tier '{tier_name}'") from error
            if not isinstance(raw, dict) or "provider" not in raw or "model" not in raw:
                raise ModelConfigError(f"tier '{tier_name}' needs both a provider and a model")
            tiers[tier] = (str(raw["provider"]), str(raw["model"]))

        for required in (ModelTier.FAST, ModelTier.REASONING):
            if required not in tiers:
                raise ModelConfigError(
                    f"tier '{required.value}' must be configured; the investigation "
                    f"loop cannot run without it"
                )

        return cls(providers, tiers)

    def provider_for(self, tier: ModelTier) -> ModelProvider:
        """The provider serving `tier`, constructed once and reused."""
        if tier in self._instances:
            return self._instances[tier]

        if tier not in self._tiers:
            raise ModelConfigError(f"tier '{tier.value}' is not configured")

        provider_name, model = self._tiers[tier]
        spec = self._providers[provider_name]
        provider = OpenAICompatibleProvider(
            EndpointConfig(
                name=spec.name,
                base_url=spec.base_url,
                model=model,
                api_key=spec.credential(),
                structured_output=spec.structured_output,
                temperature=spec.temperature,
                max_retries=spec.max_retries,
            )
        )
        self._instances[tier] = provider
        return provider

    def describe(self) -> dict[str, str]:
        """Tier to ``provider/model``, for the reproducibility manifest.

        Recorded with every investigation: a finding produced by one model is
        not necessarily reproducible under another, and the manifest should
        say which one ran.
        """
        return {
            tier.value: f"{provider}/{model}"
            for tier, (provider, model) in sorted(
                self._tiers.items(), key=lambda item: item[0].value
            )
        }


class StaticGateway:
    """A gateway over already-constructed providers.

    Used by tests and by replay runs, where the provider is a cassette rather
    than an endpoint. Kept here so the rest of the system depends on one
    gateway interface.
    """

    def __init__(self, providers: Mapping[ModelTier, ModelProvider]) -> None:
        self._providers = dict(providers)

    def provider_for(self, tier: ModelTier) -> ModelProvider:
        if tier not in self._providers:
            raise ModelConfigError(f"tier '{tier.value}' is not configured")
        return self._providers[tier]

    def describe(self) -> dict[str, str]:
        return {
            tier.value: provider.provider_name
            for tier, provider in sorted(self._providers.items(), key=lambda item: item[0].value)
        }
