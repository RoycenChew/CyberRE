"""Minimal implementations proving each core protocol can actually be met.

A protocol nobody has implemented is a guess about what an adapter will need.
These stubs are the second implementation that makes "replaceable" meaningful
(invariants 17-19) and they keep the contracts honest: if a protocol drifts
into something awkward, this file is where it hurts first.

The full behavioural contract suites arrive with real storage at M3.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

import pytest
from cyberre.core.contracts.capability import (
    CapabilityCost,
    CapabilityRegistry,
    CapabilitySpec,
)
from cyberre.core.contracts.knowledge import KnowledgeSource
from cyberre.core.contracts.model_provider import (
    Message,
    ModelProvider,
    ModelResult,
    ModelTier,
    StructuredOutputMode,
)
from cyberre.core.contracts.sandbox import (
    IsolationGrade,
    SandboxPolicy,
    SandboxProvider,
    SandboxRun,
    SandboxSelfTest,
    SandboxUnavailableError,
    SelfTestCheck,
)
from cyberre.core.contracts.storage import EvidenceStore, ObjectStore
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.base import sha256_hex
from cyberre.core.models.enums import ArtefactType, EvidenceType, RiskLevel
from cyberre.core.models.evidence import AgentClaimRecord, Evidence, ToolFailure
from cyberre.core.models.observation import KnowledgeRecord
from pydantic import BaseModel

pytestmark = pytest.mark.contract


class InMemoryObjectStore:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def put(self, data: bytes, *, media_type: str | None = None) -> str:
        ref = sha256_hex(data)
        self._blobs[ref] = data
        return ref

    def get(self, ref: str) -> bytes:
        return self._blobs[ref]

    def exists(self, ref: str) -> bool:
        return ref in self._blobs


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}
        self._claims: list[AgentClaimRecord] = []
        self._failures: list[ToolFailure] = []

    def add_evidence(self, evidence: Evidence) -> None:
        self._evidence[evidence.evidence_id] = evidence

    def add_many(self, evidence: Iterable[Evidence]) -> None:
        for item in evidence:
            self.add_evidence(item)

    def get_evidence(self, evidence_id: str) -> Evidence:
        return self._evidence[evidence_id]

    def list_evidence(self, investigation_id: str) -> Sequence[Evidence]:
        return [e for e in self._evidence.values() if e.investigation_id == investigation_id]

    def add_agent_claim(self, claim: AgentClaimRecord) -> None:
        self._claims.append(claim)

    def list_agent_claims(self, investigation_id: str) -> Sequence[AgentClaimRecord]:
        return [c for c in self._claims if c.investigation_id == investigation_id]

    def add_tool_failure(self, failure: ToolFailure) -> None:
        self._failures.append(failure)

    def list_tool_failures(self, investigation_id: str) -> Sequence[ToolFailure]:
        return [f for f in self._failures if f.investigation_id == investigation_id]


class StaticRegistry:
    def __init__(self, specs: Sequence[CapabilitySpec]) -> None:
        self._specs = list(specs)

    def get(self, capability_id: str) -> CapabilitySpec:
        for spec in self._specs:
            if spec.capability_id == capability_id:
                return spec
        raise KeyError(capability_id)

    def all_specs(self) -> Sequence[CapabilitySpec]:
        return list(self._specs)

    def for_artefact_type(self, artefact_type: ArtefactType) -> Sequence[CapabilitySpec]:
        return [s for s in self._specs if artefact_type in s.artefact_types]

    def producing(self, evidence_type: EvidenceType) -> Sequence[CapabilitySpec]:
        return [s for s in self._specs if evidence_type in s.produces]


class EchoProvider:
    """A provider that returns a canned value - the shape ReplayProvider takes."""

    def __init__(self, value: BaseModel) -> None:
        self._value = value

    @property
    def provider_name(self) -> str:
        return "echo"

    @property
    def structured_output_mode(self) -> StructuredOutputMode:
        return StructuredOutputMode.STRICT_SCHEMA

    def complete(
        self,
        messages: Sequence[Message],
        *,
        schema: type[Any],
        tier: ModelTier,
        prompt_template_version: str,
        max_output_tokens: int = 4096,
        timeout_seconds: int = 120,
    ) -> ModelResult[Any]:
        return ModelResult(
            value=schema.model_validate(self._value.model_dump()),
            model_id="echo-1",
            provider="echo",
            tier=tier,
            prompt_template_version=prompt_template_version,
            prompt_hash="0" * 64,
        )


class RefusingSandbox:
    """A provider whose isolation cannot be established.

    Included because the interesting behaviour of the sandbox contract is the
    refusal, not the run.
    """

    @property
    def provider_name(self) -> str:
        return "refusing"

    @property
    def isolation_grade(self) -> IsolationGrade:
        return IsolationGrade.NONE

    def self_test(self, policy: SandboxPolicy) -> SandboxSelfTest:
        return SandboxSelfTest(
            checks=(
                SelfTestCheck(name="network_isolated", passed=True),
                SelfTestCheck(name="filesystem_read_only", passed=False, detail="write succeeded"),
            )
        )

    def run(self, artefact_ref: str, *, policy: SandboxPolicy) -> SandboxRun:
        test = self.self_test(policy)
        if not test.passed:
            raise SandboxUnavailableError(
                f"isolation not established: {[c.name for c in test.failures()]}"
            )
        raise AssertionError("unreachable in this stub")


class TinyKnowledge:
    def __init__(self, records: dict[str, KnowledgeRecord], *, authoritative: bool) -> None:
        self._records = records
        self._authoritative = authoritative

    @property
    def source_id(self) -> str:
        return "tiny"

    @property
    def version(self) -> str:
        return "1"

    @property
    def is_authoritative(self) -> bool:
        return self._authoritative

    def lookup(self, key: str) -> KnowledgeRecord | None:
        return self._records.get(key)

    def search(self, query: str, *, limit: int = 10) -> Sequence[KnowledgeRecord]:
        hits = [r for r in self._records.values() if query.lower() in r.statement.lower()]
        return hits[:limit]


SPEC = CapabilitySpec(
    capability_id="stub.analyze",
    name="Stub analysis",
    description="Does nothing, usefully.",
    artefact_types=frozenset({ArtefactType.PE}),
    produces=frozenset({EvidenceType.IMPORT}),
    cost=CapabilityCost(seconds=1.0),
    reliability=0.9,
    risk_level=RiskLevel.L1_LOCAL_STATIC,
)


class TestProtocolConformance:
    def test_object_store(self) -> None:
        store: ObjectStore = InMemoryObjectStore()
        ref = store.put(b"hello")
        assert store.exists(ref)
        assert store.get(ref) == b"hello"

    def test_object_store_raises_on_a_missing_object(self) -> None:
        """Never an empty read - that would look like a tool producing nothing."""
        store: ObjectStore = InMemoryObjectStore()
        with pytest.raises(KeyError):
            store.get("nope")

    def test_evidence_store(self, evidence: Evidence) -> None:
        store: EvidenceStore = InMemoryEvidenceStore()
        store.add_evidence(evidence)
        assert store.get_evidence(evidence.evidence_id) == evidence
        assert list(store.list_evidence("inv-1")) == [evidence]

    def test_claims_and_failures_are_kept_apart_from_evidence(self, evidence: Evidence) -> None:
        """Invariant 2 at the storage boundary: listing evidence returns evidence."""
        store: EvidenceStore = InMemoryEvidenceStore()
        store.add_evidence(evidence)
        store.add_agent_claim(
            AgentClaimRecord(
                investigation_id="inv-1", artefact_id="ar-1", agent="codex", statement="hm"
            )
        )
        store.add_tool_failure(
            ToolFailure(investigation_id="inv-1", capability_id="x", reason="boom")
        )

        assert len(store.list_evidence("inv-1")) == 1
        assert len(store.list_agent_claims("inv-1")) == 1
        assert len(store.list_tool_failures("inv-1")) == 1

    def test_capability_registry(self) -> None:
        registry: CapabilityRegistry = StaticRegistry([SPEC])
        assert registry.get("stub.analyze") is SPEC
        assert registry.for_artefact_type(ArtefactType.PE) == [SPEC]
        assert registry.for_artefact_type(ArtefactType.ELF) == []
        assert registry.producing(EvidenceType.IMPORT) == [SPEC]

    def test_model_provider(self) -> None:
        class Answer(BaseModel):
            verdict: str

        provider: ModelProvider = EchoProvider(Answer(verdict="ok"))
        result = provider.complete(
            [Message(role="user", content="hi")],  # type: ignore[arg-type]
            schema=Answer,
            tier=ModelTier.FAST,
            prompt_template_version="v1",
        )
        assert result.value.verdict == "ok"
        assert result.prompt_hash

    def test_sandbox_refuses_when_self_test_fails(self) -> None:
        """Invariant 11: no execution without proven isolation."""
        sandbox: SandboxProvider = RefusingSandbox()
        policy = SandboxPolicy(image_digest="sha256:" + "0" * 64)
        assert sandbox.self_test(policy).passed is False
        with pytest.raises(SandboxUnavailableError, match="filesystem_read_only"):
            sandbox.run("obj/x", policy=policy)

    def test_self_test_with_no_checks_does_not_pass(self) -> None:
        """An empty check list must not read as success."""
        assert SandboxSelfTest(checks=()).passed is False

    def test_knowledge_source_misses_return_none(self) -> None:
        source: KnowledgeSource = TinyKnowledge({}, authoritative=True)
        assert source.lookup("win.api.Nope") is None

    def test_semantic_sources_declare_themselves_non_authoritative(self) -> None:
        """Used by validation to refuse semantic evidence (ADR-017)."""
        semantic: KnowledgeSource = TinyKnowledge({}, authoritative=False)
        assert semantic.is_authoritative is False


class TestRuntimeCheckable:
    """The protocols are runtime-checkable, so wiring errors surface early."""

    def test_instances_satisfy_their_protocol(self) -> None:
        assert isinstance(InMemoryObjectStore(), ObjectStore)
        assert isinstance(InMemoryEvidenceStore(), EvidenceStore)
        assert isinstance(StaticRegistry([]), CapabilityRegistry)
        assert isinstance(RefusingSandbox(), SandboxProvider)
        assert isinstance(TinyKnowledge({}, authoritative=True), KnowledgeSource)

    def test_an_unrelated_object_does_not(self) -> None:
        assert not isinstance(Artefact, ObjectStore)
