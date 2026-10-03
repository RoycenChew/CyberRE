"""The capability registry.

The prerequisite logic is what keeps the planner honest: it cannot ask to
decompile a function in a binary nobody has analysed.
"""

from __future__ import annotations

import pytest
from cyberre.capabilities.registry import (
    DuplicateCapabilityError,
    InMemoryCapabilityRegistry,
)
from cyberre.core.contracts.capability import CapabilityCost, CapabilitySpec
from cyberre.core.models.enums import ArtefactType, EvidenceType, RiskLevel

pytestmark = pytest.mark.unit


def spec(
    capability_id: str,
    *,
    artefacts: frozenset[ArtefactType] = frozenset({ArtefactType.PE}),
    produces: frozenset[EvidenceType] = frozenset({EvidenceType.IMPORT}),
    prerequisites: tuple[str, ...] = (),
) -> CapabilitySpec:
    return CapabilitySpec(
        capability_id=capability_id,
        name=capability_id,
        description="test",
        artefact_types=artefacts,
        produces=produces,
        cost=CapabilityCost(seconds=1.0),
        reliability=0.9,
        risk_level=RiskLevel.L1_LOCAL_STATIC,
        prerequisites=prerequisites,
    )


@pytest.fixture
def registry() -> InMemoryCapabilityRegistry:
    return InMemoryCapabilityRegistry(
        [
            spec("ghidra.analyze_binary", produces=frozenset({EvidenceType.FUNCTION})),
            spec(
                "ghidra.decompile_function",
                produces=frozenset({EvidenceType.DECOMPILATION}),
                prerequisites=("ghidra.analyze_binary",),
            ),
            spec(
                "semgrep.scan",
                artefacts=frozenset({ArtefactType.SOURCE_TREE}),
                produces=frozenset({EvidenceType.SCANNER_FINDING}),
            ),
        ]
    )


class TestRegistration:
    def test_duplicate_ids_are_an_error(self, registry: InMemoryCapabilityRegistry) -> None:
        """Last-one-wins would silently change which tool runs."""
        with pytest.raises(DuplicateCapabilityError):
            registry.register(spec("semgrep.scan"))

    def test_unknown_ids_raise(self, registry: InMemoryCapabilityRegistry) -> None:
        with pytest.raises(KeyError):
            registry.get("nope.missing")

    def test_membership_and_size(self, registry: InMemoryCapabilityRegistry) -> None:
        assert "semgrep.scan" in registry
        assert len(registry) == 3


class TestPlannerQueries:
    def test_listing_is_sorted_not_insertion_ordered(
        self, registry: InMemoryCapabilityRegistry
    ) -> None:
        """Planning order must not depend on import order, or an investigation
        stops being reproducible."""
        ids = [s.capability_id for s in registry.all_specs()]
        assert ids == sorted(ids)

    def test_filtering_by_artefact_type(self, registry: InMemoryCapabilityRegistry) -> None:
        pe_only = {s.capability_id for s in registry.for_artefact_type(ArtefactType.PE)}
        assert pe_only == {"ghidra.analyze_binary", "ghidra.decompile_function"}

    def test_filtering_by_evidence_produced(self, registry: InMemoryCapabilityRegistry) -> None:
        """The planner's real question: what would tell me what I am missing?"""
        producers = registry.producing(EvidenceType.DECOMPILATION)
        assert [s.capability_id for s in producers] == ["ghidra.decompile_function"]

    def test_no_producer_is_an_empty_list_not_an_error(
        self, registry: InMemoryCapabilityRegistry
    ) -> None:
        assert registry.producing(EvidenceType.SANDBOX_EVENT) == []


class TestPrerequisites:
    def test_unmet_prerequisites_are_named(self, registry: InMemoryCapabilityRegistry) -> None:
        """Named rather than returned as a boolean, so the planner can
        schedule them instead of giving up."""
        unmet = registry.unmet_prerequisites("ghidra.decompile_function", satisfied=())
        assert unmet == ("ghidra.analyze_binary",)

    def test_a_satisfied_prerequisite_makes_it_runnable(
        self, registry: InMemoryCapabilityRegistry
    ) -> None:
        assert registry.is_runnable(
            "ghidra.decompile_function", satisfied={"ghidra.analyze_binary"}
        )

    def test_a_capability_without_prerequisites_is_always_runnable(
        self, registry: InMemoryCapabilityRegistry
    ) -> None:
        assert registry.is_runnable("semgrep.scan", satisfied=())
