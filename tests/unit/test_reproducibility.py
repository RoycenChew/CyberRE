"""Reproducibility: what must stay the same, and what is allowed to differ.

Invariant 20. The tests come in pairs - something that should *not* change the
digest, and something that should - because a digest that never changes is as
useless as one that always does.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.evidence.digest import (
    ReproducibilityManifest,
    build_manifest,
    evidence_digest,
    evidence_set_digest,
    finding_digest,
    finding_set_digest,
)
from cyberre.core.models.enums import FindingStatus
from cyberre.core.models.finding import ConfidenceBreakdown, Finding
from cyberre.core.models.hypothesis import HypothesisClass
from cyberre.core.models.observation import ScannerFinding
from cyberre.core.models.provenance import Provenance, ToolProvenance

pytestmark = pytest.mark.unit

CWE78 = HypothesisClass(taxonomy="cwe", identifier="78")


def a_finding(**overrides: Any) -> Finding:
    defaults: dict[str, Any] = {
        "investigation_id": "inv-1",
        "hypothesis_id": "hy-1",
        "title": "Command injection",
        "description": "Input reaches a shell.",
        "status": FindingStatus.VALIDATED,
        "hypothesis_class": CWE78,
        "evidence_ids": ("ev-1",),
        "confidence": ConfidenceBreakdown(
            factors={"c": 1.0},
            weights={"c": 1.0},
            base_score=0.8,
            completeness=1.0,
            reviewer_multiplier=1.0,
            validation_gate=1.0,
            final_score=0.8,
            formula_version="v1",
        ),
    }
    return Finding(**{**defaults, **overrides})


class TestVolatileFieldsDoNotChangeTheDigest:
    """Otherwise every rerun would look like a regression."""

    def test_generated_ids_are_excluded(self, make_evidence: Any) -> None:
        first = make_evidence()
        second = make_evidence()
        assert first.evidence_id != second.evidence_id
        assert evidence_digest(first) == evidence_digest(second)

    def test_collection_timestamps_are_excluded(
        self, make_evidence: Any, tool_provenance: ToolProvenance
    ) -> None:
        from datetime import UTC, datetime

        later = Provenance(
            tool=tool_provenance,
            artefact_sha256="a" * 64,
            raw_output_ref="obj/" + "d" * 64,
            collected_at=datetime(2030, 1, 1, tzinfo=UTC),
        )
        baseline = make_evidence()
        rerun = make_evidence(provenance=later)
        assert evidence_digest(baseline) == evidence_digest(rerun)

    def test_evidence_set_digest_ignores_ordering(self, make_evidence: Any) -> None:
        """Concurrent capabilities may finish in either order."""
        items = [make_evidence(independence_key=f"k{i}") for i in range(5)]
        assert evidence_set_digest(items) == evidence_set_digest(reversed(items))


class TestRealChangesDoChangeTheDigest:
    def test_a_different_observation_changes_it(self, make_evidence: Any) -> None:
        baseline = make_evidence()
        changed = make_evidence(
            observation=ScannerFinding(rule_id="other.rule", message="something else")
        )
        assert evidence_digest(baseline) != evidence_digest(changed)

    def test_a_tool_upgrade_changes_it(
        self, make_evidence: Any, tool_provenance: ToolProvenance
    ) -> None:
        """A newer scanner finding the same thing is not the same evidence."""
        upgraded = Provenance(
            tool=tool_provenance.model_copy(update={"tool_version": "2.0.0"}),
            artefact_sha256="a" * 64,
            raw_output_ref="obj/" + "d" * 64,
        )
        assert evidence_digest(make_evidence()) != evidence_digest(
            make_evidence(provenance=upgraded)
        )

    def test_a_ruleset_change_changes_it(
        self, make_evidence: Any, tool_provenance: ToolProvenance
    ) -> None:
        updated = Provenance(
            tool=tool_provenance.model_copy(update={"ruleset_version": "p/security@2025"}),
            artefact_sha256="a" * 64,
        )
        assert evidence_digest(make_evidence()) != evidence_digest(
            make_evidence(provenance=updated)
        )

    def test_a_different_artefact_changes_it(self, make_evidence: Any) -> None:
        assert evidence_digest(make_evidence()) != evidence_digest(
            make_evidence(artefact_sha256="b" * 64)
        )

    def test_losing_a_piece_of_evidence_changes_the_set(self, make_evidence: Any) -> None:
        items = [make_evidence(independence_key=f"k{i}") for i in range(3)]
        assert evidence_set_digest(items) != evidence_set_digest(items[:2])


class TestFindingDigest:
    def test_the_same_conclusion_digests_the_same(self) -> None:
        assert finding_digest(a_finding()) == finding_digest(a_finding())

    def test_a_different_status_changes_it(self) -> None:
        assert finding_digest(a_finding()) != finding_digest(
            a_finding(status=FindingStatus.NOT_ENOUGH_EVIDENCE, confidence=None)
        )

    def test_a_different_confidence_changes_it(self) -> None:
        """Reaching the same conclusion less confidently is not a reproduction."""
        weaker = a_finding(
            confidence=ConfidenceBreakdown(
                factors={"c": 0.5},
                weights={"c": 1.0},
                base_score=0.4,
                completeness=1.0,
                reviewer_multiplier=1.0,
                validation_gate=1.0,
                final_score=0.4,
                formula_version="v1",
            )
        )
        assert finding_digest(a_finding()) != finding_digest(weaker)

    def test_an_empty_set_has_a_stable_digest(self) -> None:
        assert finding_set_digest([]) == finding_set_digest([])


class TestManifest:
    def test_versions_are_read_from_provenance_not_supplied(self, make_evidence: Any) -> None:
        """The manifest records what ran, not what was believed to have run."""
        manifest = build_manifest(
            investigation_id="inv-1",
            evidence=[make_evidence()],
            cyberre_version="0.1.0",
        )
        assert manifest.tool_versions == {"semgrep": "1.52.0"}
        assert manifest.ruleset_versions == {"semgrep": "p/security-audit@2024-01-01"}
        assert manifest.artefact_hashes == ("a" * 64,)

    def test_a_rerun_matches(self, make_evidence: Any) -> None:
        def run() -> ReproducibilityManifest:
            return build_manifest(
                investigation_id="inv-1",
                evidence=[make_evidence(independence_key=f"k{i}") for i in range(4)],
                findings=[a_finding()],
                cyberre_version="0.1.0",
            )

        first, second = run(), run()
        assert first.matches(second)
        assert first.divergence(second) == ()

    def test_a_tool_upgrade_is_reported_as_divergence(
        self, make_evidence: Any, tool_provenance: ToolProvenance
    ) -> None:
        baseline = build_manifest(
            investigation_id="inv-1",
            evidence=[make_evidence()],
            cyberre_version="0.1.0",
        )
        upgraded_provenance = Provenance(
            tool=tool_provenance.model_copy(update={"tool_version": "2.0.0"}),
            artefact_sha256="a" * 64,
        )
        after = build_manifest(
            investigation_id="inv-1",
            evidence=[make_evidence(provenance=upgraded_provenance)],
            cyberre_version="0.1.0",
        )
        assert not baseline.matches(after)
        assert "tool_versions" in baseline.divergence(after)
        assert "evidence" in baseline.divergence(after)

    def test_identical_results_from_different_tools_do_not_count_as_a_match(
        self, make_evidence: Any
    ) -> None:
        """A coincidence worth knowing about, not a successful reproduction."""
        baseline = build_manifest(
            investigation_id="inv-1", evidence=[make_evidence()], cyberre_version="0.1.0"
        )
        tampered = baseline.model_copy(update={"tool_versions": {"semgrep": "9.9.9"}})
        assert not baseline.matches(tampered)

    def test_divergence_names_each_differing_part(self, make_evidence: Any) -> None:
        baseline = build_manifest(
            investigation_id="inv-1",
            evidence=[make_evidence()],
            cyberre_version="0.1.0",
            confidence_formula_version="v1",
        )
        retuned = baseline.model_copy(update={"confidence_formula_version": "v2"})
        assert baseline.divergence(retuned) == ("confidence_formula_version",)

    def test_manifest_round_trips(self, make_evidence: Any) -> None:
        manifest = build_manifest(
            investigation_id="inv-1", evidence=[make_evidence()], cyberre_version="0.1.0"
        )
        restored = ReproducibilityManifest.model_validate_json(manifest.model_dump_json())
        assert restored == manifest


class TestEndToEndReplay:
    def test_an_investigation_replayed_through_storage_reproduces(self, make_evidence: Any) -> None:
        """Invariant 20, across the persistence boundary."""
        from cyberre.adapters.storage.memory import MemoryStore
        from cyberre.adapters.storage.sqlite.store import SqliteStore

        items = [make_evidence(independence_key=f"k{i}") for i in range(6)]

        memory = MemoryStore()
        memory.add_many(items)
        sqlite = SqliteStore()
        sqlite.add_many(items)

        from_memory = evidence_set_digest(memory.list_evidence("inv-1"))
        from_sqlite = evidence_set_digest(sqlite.list_evidence("inv-1"))
        sqlite.close()

        assert from_memory == from_sqlite == evidence_set_digest(items)
