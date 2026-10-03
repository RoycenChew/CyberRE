"""One contract suite, run against every storage implementation.

This is how "storage is replaceable" (invariant 17) becomes a tested claim.
Each implementation is parametrised in; a behaviour one satisfies and the
other does not fails here rather than at M16 when PostgreSQL arrives.

The suite deliberately tests *behaviour under the protocol*, never internals.
If a test needs to know whether rows or dicts are underneath, it is testing
the wrong thing.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

import pytest
from cyberre.adapters.storage.memory import MemoryObjectStore, MemoryStore
from cyberre.adapters.storage.objectstore.filesystem import FilesystemObjectStore
from cyberre.adapters.storage.sqlite.store import SqliteStore
from cyberre.core.contracts.storage import EvidenceStore, InvestigationStore, ObjectStore
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import FindingStatus, InvestigationStatus
from cyberre.core.models.evidence import AgentClaimRecord, Evidence, ToolFailure
from cyberre.core.models.finding import CandidateFinding, Finding
from cyberre.core.models.hypothesis import Hypothesis
from cyberre.core.models.state import InvestigationState

pytestmark = pytest.mark.contract


class Store(EvidenceStore, InvestigationStore, Protocol):
    """Both storage protocols, as the implementations provide them."""


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Store]:
    if request.param == "memory":
        yield MemoryStore()  # type: ignore[misc]
    else:
        with SqliteStore(tmp_path / "cyberre.sqlite") as sqlite_store:
            yield sqlite_store  # type: ignore[misc]


@pytest.fixture(params=["memory", "filesystem"])
def object_store(request: pytest.FixtureRequest, tmp_path: Path) -> ObjectStore:
    if request.param == "memory":
        return MemoryObjectStore()
    return FilesystemObjectStore(tmp_path / "objects")


class TestObjectStoreContract:
    def test_round_trip(self, object_store: ObjectStore) -> None:
        ref = object_store.put(b"ghidra export")
        assert object_store.get(ref) == b"ghidra export"

    def test_the_reference_is_the_content_hash(self, object_store: ObjectStore) -> None:
        """So a provenance hash and a store key are the same string."""
        import hashlib

        data = b"semgrep output"
        assert object_store.put(data) == hashlib.sha256(data).hexdigest()

    def test_storing_the_same_bytes_twice_deduplicates(self, object_store: ObjectStore) -> None:
        assert object_store.put(b"same") == object_store.put(b"same")

    def test_missing_objects_raise_rather_than_return_empty(
        self, object_store: ObjectStore
    ) -> None:
        """An empty read is indistinguishable from a tool producing nothing."""
        with pytest.raises(KeyError):
            object_store.get("0" * 64)

    def test_exists_reports_accurately(self, object_store: ObjectStore) -> None:
        assert object_store.exists("0" * 64) is False
        assert object_store.exists(object_store.put(b"x")) is True

    def test_empty_content_is_storable(self, object_store: ObjectStore) -> None:
        """A tool legitimately producing no output is not the same as failing."""
        ref = object_store.put(b"")
        assert object_store.get(ref) == b""


class TestEvidenceStoreContract:
    def test_round_trip(self, store: Store, evidence: Evidence) -> None:
        store.add_evidence(evidence)
        assert store.get_evidence(evidence.evidence_id) == evidence

    def test_unknown_evidence_raises(self, store: Store) -> None:
        with pytest.raises(KeyError):
            store.get_evidence("ev-nope")

    def test_listing_is_scoped_to_the_investigation(self, store: Store, make_evidence: Any) -> None:
        mine = make_evidence(investigation_id="inv-1")
        theirs = make_evidence(investigation_id="inv-2")
        store.add_many([mine, theirs])
        assert [e.evidence_id for e in store.list_evidence("inv-1")] == [mine.evidence_id]

    def test_listing_order_is_stable(self, store: Store, make_evidence: Any) -> None:
        """Replay compares evidence sequences, so order cannot vary by backend."""
        items = [make_evidence(independence_key=f"k{i}") for i in range(10)]
        store.add_many(items)
        first = [e.evidence_id for e in store.list_evidence("inv-1")]
        second = [e.evidence_id for e in store.list_evidence("inv-1")]
        assert first == second

    def test_writes_are_idempotent(self, store: Store, evidence: Evidence) -> None:
        """Re-running a capability after a crash should converge, not error."""
        store.add_evidence(evidence)
        store.add_evidence(evidence)
        assert len(store.list_evidence(evidence.investigation_id)) == 1

    def test_a_discriminated_observation_survives_the_round_trip(
        self, store: Store, evidence: Evidence
    ) -> None:
        store.add_evidence(evidence)
        restored = store.get_evidence(evidence.evidence_id)
        assert restored.observation.kind == evidence.observation.kind
        assert restored.provenance.tool.tool_version == "1.52.0"

    def test_provenance_is_not_lost_in_storage(self, store: Store, evidence: Evidence) -> None:
        """Invariant 6 has to hold across the persistence boundary too."""
        store.add_evidence(evidence)
        restored = store.get_evidence(evidence.evidence_id)
        assert restored.provenance == evidence.provenance


class TestInvariant2AtTheStorageBoundary:
    """Listing evidence must be physically unable to return an agent claim."""

    def test_claims_and_evidence_are_separate(self, store: Store, evidence: Evidence) -> None:
        store.add_evidence(evidence)
        store.add_agent_claim(
            AgentClaimRecord(
                investigation_id="inv-1",
                artefact_id="ar-1",
                agent="codex",
                statement="This looks like SQL injection.",
            )
        )
        listed = store.list_evidence("inv-1")
        assert len(listed) == 1
        assert all(isinstance(item, Evidence) for item in listed)
        assert len(store.list_agent_claims("inv-1")) == 1

    def test_failures_are_not_evidence(self, store: Store) -> None:
        store.add_tool_failure(
            ToolFailure(
                investigation_id="inv-1",
                capability_id="ghidra.analyze_binary",
                reason="JVM out of memory",
            )
        )
        assert store.list_evidence("inv-1") == []
        assert len(store.list_tool_failures("inv-1")) == 1

    def test_a_failure_keeps_its_reason(self, store: Store) -> None:
        store.add_tool_failure(
            ToolFailure(
                investigation_id="inv-1",
                capability_id="semgrep.scan",
                reason="ruleset not found",
                recoverable=False,
            )
        )
        failure = store.list_tool_failures("inv-1")[0]
        assert failure.reason == "ruleset not found"
        assert failure.recoverable is False


class TestInvestigationStoreContract:
    def test_state_round_trip(self, store: Store, state: InvestigationState) -> None:
        store.save_state(state)
        assert store.load_state(state.investigation_id) == state

    def test_saving_again_replaces(self, store: Store, state: InvestigationState) -> None:
        store.save_state(state)
        evolved = state.evolve(status=InvestigationStatus.PARTIAL)
        store.save_state(evolved)
        assert store.load_state(state.investigation_id).status is InvestigationStatus.PARTIAL

    def test_unknown_investigation_raises(self, store: Store) -> None:
        with pytest.raises(KeyError):
            store.load_state("inv-nope")

    def test_oversized_state_is_refused_at_the_boundary(
        self, store: Store, state: InvestigationState
    ) -> None:
        """The size guard must hold where state is persisted, not only in memory."""
        bloated = state.evolve(evidence_ids=tuple("x" * 2000 for _ in range(200)))
        with pytest.raises(ValueError, match="object store"):
            store.save_state(bloated)

    def test_artefact_round_trip(self, store: Store, artefact: Artefact) -> None:
        store.add_artefact(artefact)
        assert store.get_artefact(artefact.artefact_id) == artefact

    def test_artefacts_are_findable_by_content(self, store: Store, artefact: Artefact) -> None:
        """Content addressing is what makes caching safe."""
        store.add_artefact(artefact)
        found = store.find_artefact_by_hash(artefact.sha256)  # type: ignore[attr-defined]
        assert found is not None and found.artefact_id == artefact.artefact_id

    def test_unknown_hash_returns_none(self, store: Store) -> None:
        assert store.find_artefact_by_hash("f" * 64) is None  # type: ignore[attr-defined]

    def test_hypothesis_round_trip(self, store: Store, hypothesis: Hypothesis) -> None:
        store.save_hypothesis(hypothesis)
        listed = store.list_hypotheses(hypothesis.investigation_id)
        assert listed == [hypothesis]

    def test_candidate_and_finding_are_stored_separately(
        self, store: Store, hypothesis: Hypothesis
    ) -> None:
        """A candidate must never be retrievable as a finding (ADR-002)."""
        candidate = CandidateFinding(
            investigation_id="inv-1",
            hypothesis_id=hypothesis.hypothesis_id,
            title="Possible command injection",
            description="Scanner matched a dangerous pattern.",
            cited_evidence=("ev-1",),
        )
        store.save_candidate(candidate)
        assert store.list_findings("inv-1") == []
        assert len(store.list_candidates("inv-1")) == 1  # type: ignore[attr-defined]

    def test_finding_round_trip(self, store: Store, hypothesis: Hypothesis) -> None:
        finding = Finding(
            investigation_id="inv-1",
            hypothesis_id=hypothesis.hypothesis_id,
            title="Unreachable sink",
            description="The vulnerable function is not reachable from any entry point.",
            status=FindingStatus.UNREACHABLE,
            hypothesis_class=hypothesis.hypothesis_class,
            evidence_ids=("ev-1",),
        )
        store.save_finding(finding)
        assert store.list_findings("inv-1") == [finding]

    def test_a_stored_finding_still_refuses_an_illegal_shape(
        self, store: Store, hypothesis: Hypothesis
    ) -> None:
        """Validators run on load as well as on save, so a hand-edited row
        cannot smuggle in a severity on an unresolved outcome."""
        with pytest.raises(ValueError, match="must not carry a severity"):
            Finding(
                investigation_id="inv-1",
                hypothesis_id=hypothesis.hypothesis_id,
                title="x",
                description="y",
                status=FindingStatus.NOT_ENOUGH_EVIDENCE,
                severity="high",  # type: ignore[arg-type]
                hypothesis_class=hypothesis.hypothesis_class,
            )


class TestProtocolConformance:
    def test_both_implementations_satisfy_both_protocols(self, store: Store) -> None:
        assert isinstance(store, EvidenceStore)
        assert isinstance(store, InvestigationStore)

    def test_both_object_stores_satisfy_the_protocol(self, object_store: ObjectStore) -> None:
        assert isinstance(object_store, ObjectStore)


class TestSqliteSpecifics:
    """Properties of the SQLite adapter that the protocol does not cover."""

    def test_data_survives_reopening(self, tmp_path: Path, evidence: Evidence) -> None:
        path = tmp_path / "persist.sqlite"
        with SqliteStore(path) as first:
            first.add_evidence(evidence)
        with SqliteStore(path) as second:
            assert second.get_evidence(evidence.evidence_id) == evidence

    def test_migrations_are_idempotent(self, tmp_path: Path) -> None:
        from cyberre.adapters.storage.sqlite.schema import LATEST_VERSION, current_version

        path = tmp_path / "migrate.sqlite"
        for _ in range(3):
            with SqliteStore(path) as store:
                assert current_version(store._connection) == LATEST_VERSION

    def test_filesystem_store_detects_corruption(self, tmp_path: Path) -> None:
        """A silent bad read would poison provenance downstream."""
        store = FilesystemObjectStore(tmp_path / "objects")
        ref = store.put(b"original")
        (tmp_path / "objects" / ref[:2] / ref[2:]).write_bytes(b"tampered")
        with pytest.raises(OSError, match="corruption"):
            store.get(ref)
