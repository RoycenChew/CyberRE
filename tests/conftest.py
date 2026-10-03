"""Builders for valid domain objects.

Each helper returns something that passes validation, so a test can change the
one field it cares about and the failure it provokes is unambiguous.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import ArtefactType, EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.location import SourceLocation
from cyberre.core.models.observation import ScannerFinding
from cyberre.core.models.provenance import Provenance, ToolProvenance
from cyberre.core.models.state import InvestigationState, Objective

SHA = "a" * 64
OTHER_SHA = "b" * 64


@pytest.fixture
def tool_provenance() -> ToolProvenance:
    return ToolProvenance(
        tool="semgrep",
        tool_version="1.52.0",
        ruleset_version="p/security-audit@2024-01-01",
        config_hash="c" * 64,
    )


@pytest.fixture
def provenance(tool_provenance: ToolProvenance) -> Provenance:
    return Provenance(
        tool=tool_provenance,
        artefact_sha256=SHA,
        raw_output_ref="obj/" + "d" * 64,
    )


@pytest.fixture
def scanner_observation() -> ScannerFinding:
    return ScannerFinding(
        rule_id="python.lang.security.dangerous-subprocess-use",
        message="subprocess call with shell=True",
        severity_reported="WARNING",
        cwe=("CWE-78",),
    )


@pytest.fixture
def source_location() -> SourceLocation:
    return SourceLocation(path="app/views.py", start_line=42, end_line=44)


@pytest.fixture
def evidence(
    provenance: Provenance,
    scanner_observation: ScannerFinding,
    source_location: SourceLocation,
) -> Evidence:
    return Evidence(
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=SHA,
        evidence_type=EvidenceType.SCANNER_FINDING,
        observation=scanner_observation,
        location=source_location,
        provenance=provenance,
        independence_key=derive_independence_key(
            "semgrep", SHA, str(source_location), "scanner_finding"
        ),
        source_reliability=0.8,
    )


@pytest.fixture
def make_evidence(
    provenance: Provenance,
    scanner_observation: ScannerFinding,
    source_location: SourceLocation,
) -> Any:
    def _make(**overrides: Any) -> Evidence:
        defaults: dict[str, Any] = {
            "investigation_id": "inv-1",
            "artefact_id": "ar-1",
            "artefact_sha256": SHA,
            "evidence_type": EvidenceType.SCANNER_FINDING,
            "observation": scanner_observation,
            "location": source_location,
            "provenance": provenance,
            "independence_key": "k" * 64,
        }
        return Evidence(**{**defaults, **overrides})

    return _make


@pytest.fixture
def artefact() -> Artefact:
    return Artefact(
        sha256=SHA,
        size_bytes=1024,
        artefact_type=ArtefactType.SOURCE_FILE,
        display_name="views.py",
    )


@pytest.fixture
def hypothesis_class() -> HypothesisClass:
    return HypothesisClass(taxonomy="cwe", identifier="78")


@pytest.fixture
def hypothesis(hypothesis_class: HypothesisClass) -> Hypothesis:
    return Hypothesis(
        investigation_id="inv-1",
        statement="User input reaches a shell command without sanitisation.",
        hypothesis_class=hypothesis_class,
        cites=("ev-1",),
        created_by="reasoner",
    )


@pytest.fixture
def objective() -> Objective:
    return Objective(
        question="Are there command injection vulnerabilities?",
        normalised_intent="find_command_injection",
        success_criteria=("every subprocess sink traced to its input source",),
    )


@pytest.fixture
def state(objective: Objective) -> InvestigationState:
    return InvestigationState(objective=objective)
