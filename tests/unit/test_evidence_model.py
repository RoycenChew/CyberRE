"""Evidence, agent claims and tool failures.

The theme is that the things the architecture forbids must be *unrepresentable*
rather than merely discouraged.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import (
    AgentClaimRecord,
    Evidence,
    ToolFailure,
    derive_independence_key,
)
from cyberre.core.models.location import SourceLocation
from cyberre.core.models.observation import ImportObservation
from cyberre.core.models.provenance import Provenance, ToolProvenance
from cyberre.core.trust.levels import TrustLevel, may_satisfy_requirement
from pydantic import ValidationError

pytestmark = pytest.mark.unit


class TestInvariant6ProvenanceIsMandatory:
    def test_evidence_cannot_be_built_without_provenance(self, make_evidence: Any) -> None:
        with pytest.raises(ValidationError):
            make_evidence(provenance=None)

    def test_provenance_requires_a_tool_version(self) -> None:
        with pytest.raises(ValidationError):
            ToolProvenance(tool="semgrep", tool_version="")

    def test_provenance_requires_an_artefact_hash(self, tool_provenance: ToolProvenance) -> None:
        with pytest.raises(ValidationError):
            Provenance(tool=tool_provenance, artefact_sha256="not-a-hash")

    def test_provenance_rejects_credential_shaped_environment_keys(
        self, tool_provenance: ToolProvenance
    ) -> None:
        """Provenance is durable and is rendered into reports."""
        with pytest.raises(ValidationError, match="credential-shaped"):
            Provenance(
                tool=tool_provenance,
                artefact_sha256="a" * 64,
                environment={"API_KEY": "sk-live-1234"},
            )

    def test_ordinary_environment_keys_are_fine(self, tool_provenance: ToolProvenance) -> None:
        prov = Provenance(
            tool=tool_provenance,
            artefact_sha256="a" * 64,
            environment={"os": "linux", "arch": "x86_64"},
        )
        assert prov.environment["arch"] == "x86_64"


class TestInvariant7Independence:
    def test_same_underlying_observation_yields_the_same_key(self) -> None:
        a = derive_independence_key("semgrep", "a" * 64, "app.py:10", "scanner_finding")
        b = derive_independence_key("semgrep", "a" * 64, "app.py:10", "scanner_finding")
        assert a == b

    def test_different_observations_yield_different_keys(self) -> None:
        a = derive_independence_key("semgrep", "a" * 64, "app.py:10", "scanner_finding")
        b = derive_independence_key("semgrep", "a" * 64, "app.py:11", "scanner_finding")
        assert a != b

    def test_key_components_cannot_be_confused_by_concatenation(self) -> None:
        """("ab", "c") and ("a", "bc") are different observations."""
        a = derive_independence_key("ab", "c" * 64, "x", "k")
        b = derive_independence_key("a", "bc" + "c" * 62, "x", "k")
        assert a != b

    def test_derived_evidence_must_declare_itself_derived(self, make_evidence: Any) -> None:
        """Otherwise a transform of one observation counts as corroboration."""
        with pytest.raises(ValidationError, match="DERIVED_EVIDENCE"):
            make_evidence(derived_from=("ev-1",))

    def test_derived_evidence_is_not_an_independent_source(self, make_evidence: Any) -> None:
        derived = make_evidence(derived_from=("ev-1",), trust_level=TrustLevel.DERIVED_EVIDENCE)
        assert derived.is_independent_source is False

    def test_normalised_evidence_is_an_independent_source(self, evidence: Evidence) -> None:
        assert evidence.is_independent_source is True


class TestTypeAndPayloadAgree:
    def test_mismatched_evidence_type_is_rejected(self, make_evidence: Any) -> None:
        """Relevance filtering and requirement matching both key off the type."""
        with pytest.raises(ValidationError, match="does not match"):
            make_evidence(evidence_type=EvidenceType.IMPORT)

    def test_matching_type_is_accepted(self, make_evidence: Any) -> None:
        ev = make_evidence(
            evidence_type=EvidenceType.IMPORT,
            observation=ImportObservation(library="kernel32.dll", symbol="VirtualAllocEx"),
            location=SourceLocation(path="x", start_line=1),
        )
        assert ev.evidence_type is EvidenceType.IMPORT


class TestEvidenceTrustLevel:
    def test_evidence_cannot_be_created_at_agent_claim_level(self, make_evidence: Any) -> None:
        with pytest.raises(ValidationError, match="AgentClaimRecord"):
            make_evidence(trust_level=TrustLevel.AGENT_CLAIM)

    def test_evidence_cannot_be_created_as_a_finding(self, make_evidence: Any) -> None:
        with pytest.raises(ValidationError):
            make_evidence(trust_level=TrustLevel.VALIDATED_FINDING)

    def test_evidence_levels_may_satisfy_requirements(self, evidence: Evidence) -> None:
        assert may_satisfy_requirement(evidence.trust_level)


class TestImmutability:
    def test_evidence_cannot_be_mutated(self, evidence: Evidence) -> None:
        """A correction is a new record; an editable audit trail is not one."""
        with pytest.raises(ValidationError):
            evidence.source_reliability = 1.0  # type: ignore[misc]

    def test_unexpected_fields_are_rejected(self, make_evidence: Any) -> None:
        with pytest.raises(ValidationError):
            make_evidence(confidence=0.99)


class TestInvariant2AgentClaims:
    def test_a_claim_is_always_unverified(self) -> None:
        with pytest.raises(ValidationError, match="always unverified"):
            AgentClaimRecord(
                investigation_id="inv-1",
                artefact_id="ar-1",
                agent="codex",
                statement="This is SQL injection.",
                is_unverified=False,
            )

    def test_a_claim_cannot_be_promoted_by_setting_its_level(self) -> None:
        with pytest.raises(ValidationError, match="always at trust level"):
            AgentClaimRecord(
                investigation_id="inv-1",
                artefact_id="ar-1",
                agent="codex",
                statement="This is SQL injection.",
                trust_level=TrustLevel.NORMALIZED_EVIDENCE,
            )

    def test_a_claim_cannot_satisfy_a_requirement(self) -> None:
        claim = AgentClaimRecord(
            investigation_id="inv-1",
            artefact_id="ar-1",
            agent="claude-code",
            statement="Looks like command injection to me.",
        )
        assert not may_satisfy_requirement(claim.trust_level)

    def test_a_claim_is_not_an_evidence_instance(self) -> None:
        """Separate types, so 'fetch the evidence' cannot return a claim."""
        claim = AgentClaimRecord(
            investigation_id="inv-1", artefact_id="ar-1", agent="pi", statement="x"
        )
        assert not isinstance(claim, Evidence)


class TestToolFailureIsNotEvidence:
    def test_failure_is_a_distinct_type(self) -> None:
        failure = ToolFailure(
            investigation_id="inv-1",
            capability_id="ghidra.analyze_binary",
            reason="unsupported architecture",
        )
        assert not isinstance(failure, Evidence)

    def test_failure_records_why(self) -> None:
        with pytest.raises(ValidationError):
            ToolFailure(investigation_id="inv-1", capability_id="x", reason="")


class TestRoundTrip:
    def test_evidence_survives_serialisation(self, evidence: Evidence) -> None:
        restored = Evidence.model_validate_json(evidence.model_dump_json())
        assert restored == evidence

    def test_discriminated_observation_restores_to_its_concrete_type(
        self, evidence: Evidence
    ) -> None:
        restored = Evidence.model_validate_json(evidence.model_dump_json())
        assert restored.observation.kind == "scanner_finding"
        assert restored.observation.rule_id == evidence.observation.rule_id  # type: ignore[union-attr]
