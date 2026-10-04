"""Parsing recorded Ghidra exports.

The **fixture** tier. These prove the parser handles the document contract;
they say nothing about whether Ghidra behaves as the contract assumes, which
is the `realtool` tier's job (ADR-004).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cyberre.adapters.ghidra.parser import (
    SUPPORTED_SCHEMA_VERSIONS,
    GhidraExportError,
    build_provenance,
    parse_export,
    validate_document,
)
from cyberre.adapters.ghidra.runner import EXPECTED_SCRIPT_VERSION
from cyberre.core.evidence.builder import build_graph
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence

pytestmark = pytest.mark.fixture

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ghidra"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def parse(name: str, **overrides: Any) -> Any:
    document = load(name)
    document.update(overrides)
    sha = str(document["binary"]["sha256"])
    return parse_export(
        document,
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=sha,
        provenance=build_provenance(
            document,
            artefact_sha256=sha,
            config_hash="cfg-1",
            raw_output_ref="obj/export",
            invocation_id="run-1",
        ),
        expected_script_version=EXPECTED_SCRIPT_VERSION,
    )


def of_type(evidence: list[Evidence], kind: EvidenceType) -> list[Evidence]:
    return [e for e in evidence if e.evidence_type is kind]


class TestContractEnforcement:
    def test_an_unsupported_schema_version_is_refused(self) -> None:
        """A newer document may contain fields we would silently ignore,
        which is how a capability quietly stops collecting something."""
        document = load("injector_pe.json")
        document["schema_version"] = max(SUPPORTED_SCHEMA_VERSIONS) + 1
        with pytest.raises(GhidraExportError, match="schema version"):
            validate_document(document, expected_script_version=EXPECTED_SCRIPT_VERSION)

    def test_a_mismatched_script_version_is_refused(self) -> None:
        """A cached export from an older script describes a different
        analysis; the cache key should have prevented this."""
        document = load("injector_pe.json")
        document["script_version"] = "0.9.0"
        with pytest.raises(GhidraExportError, match="script version"):
            validate_document(document, expected_script_version=EXPECTED_SCRIPT_VERSION)

    @pytest.mark.parametrize(
        "key", ["schema_version", "script_version", "ghidra_version", "binary"]
    )
    def test_missing_required_keys_are_refused(self, key: str) -> None:
        document = load("injector_pe.json")
        del document[key]
        with pytest.raises(GhidraExportError, match=key):
            validate_document(document, expected_script_version=EXPECTED_SCRIPT_VERSION)

    def test_a_malformed_list_is_an_error(self) -> None:
        with pytest.raises(GhidraExportError, match="must be a list"):
            parse("injector_pe.json", imports={"not": "a list"})

    def test_malformed_metadata_is_an_error_not_a_skip(self) -> None:
        """Lose the metadata and the rest is hard to interpret."""
        document = load("injector_pe.json")
        document["binary"] = "not an object"
        with pytest.raises(GhidraExportError, match="must be an object"):
            parse_export(
                document,
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256="a" * 64,
                provenance=build_provenance(
                    document,
                    artefact_sha256="a" * 64,
                    config_hash="c",
                    raw_output_ref=None,
                ),
                expected_script_version=EXPECTED_SCRIPT_VERSION,
            )


class TestProvenance:
    def test_ghidra_and_script_versions_are_recorded_separately(self) -> None:
        """An upgrade to either changes what the analysis found."""
        report = parse("injector_pe.json")
        tool = report.evidence[0].provenance.tool
        assert tool.tool == "ghidra"
        assert tool.tool_version == "12.1.2"
        assert tool.script_version == EXPECTED_SCRIPT_VERSION

    def test_every_piece_carries_the_artefact_hash(self) -> None:
        report = parse("injector_pe.json")
        assert {e.artefact_sha256 for e in report.evidence} == {
            load("injector_pe.json")["binary"]["sha256"]
        }

    def test_the_raw_export_is_referenced(self) -> None:
        report = parse("injector_pe.json")
        assert report.evidence[0].provenance.raw_output_ref == "obj/export"

    def test_evidence_from_distinct_locations_is_independent(self) -> None:
        report = parse("injector_pe.json")
        imports = of_type(report.evidence, EvidenceType.IMPORT)
        assert len({e.independence_key for e in imports}) == len(imports)


class TestObservations:
    def test_metadata_is_extracted(self) -> None:
        report = parse("injector_pe.json")
        metadata = of_type(report.evidence, EvidenceType.BINARY_METADATA)[0].observation
        assert metadata.architecture == "x86"  # type: ignore[union-attr]
        assert metadata.bits == 64  # type: ignore[union-attr]
        assert metadata.endianness == "little"  # type: ignore[union-attr]

    def test_imports_are_extracted_with_their_library(self) -> None:
        report = parse("injector_pe.json")
        symbols = {
            e.observation.symbol  # type: ignore[union-attr]
            for e in of_type(report.evidence, EvidenceType.IMPORT)
        }
        assert {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory"} <= symbols

    def test_sections_record_their_permissions(self) -> None:
        report = parse("injector_pe.json")
        sections = {
            e.observation.name: e.observation  # type: ignore[union-attr]
            for e in of_type(report.evidence, EvidenceType.SECTION)
        }
        assert sections[".text"].executable is True  # type: ignore[union-attr]
        assert sections[".data"].writable is True  # type: ignore[union-attr]

    def test_strings_are_marked_untrusted(self) -> None:
        """They come out of the artefact, so they must be fenced before they
        go anywhere near a model."""
        report = parse("injector_pe.json")
        strings = of_type(report.evidence, EvidenceType.STRING_MATCH)
        assert strings
        assert all(e.observation.is_untrusted_content for e in strings)  # type: ignore[union-attr]

    def test_thunks_are_marked_as_library_code(self) -> None:
        """The reviewer uses this to argue a finding is in imported code."""
        report = parse("injector_pe.json")
        functions = {
            e.observation.name: e.observation  # type: ignore[union-attr]
            for e in of_type(report.evidence, EvidenceType.FUNCTION)
        }
        assert functions["OpenProcess"].is_library is True  # type: ignore[union-attr]
        assert functions["inject"].is_library is False  # type: ignore[union-attr]

    def test_call_edges_are_less_reliable_than_structural_facts(self) -> None:
        """Indirect calls and dynamic resolution make call graphs incomplete
        rather than wrong; treating them as certain would over-conclude from
        an absent edge."""
        report = parse("injector_pe.json")
        imports = of_type(report.evidence, EvidenceType.IMPORT)[0]
        edges = of_type(report.evidence, EvidenceType.CALL_EDGE)[0]
        assert edges.source_reliability < imports.source_reliability


class TestPartialResults:
    def test_a_truncated_analysis_reports_partial(self) -> None:
        """Partial coverage must never read as a clean result."""
        report = parse("truncated_analysis.json")
        assert report.is_partial is True
        assert report.truncated["functions"] is True
        assert report.truncated["analysis"] is True

    def test_a_complete_analysis_does_not(self) -> None:
        assert parse("injector_pe.json").is_partial is False

    def test_unparseable_records_are_counted_not_discarded_silently(self) -> None:
        """One bad function in fifty thousand should not lose the rest."""
        document = load("injector_pe.json")
        document["functions"] = [*document["functions"], {"name": None}, "nonsense"]
        sha = str(document["binary"]["sha256"])
        report = parse_export(
            document,
            investigation_id="inv-1",
            artefact_id="ar-1",
            artefact_sha256=sha,
            provenance=build_provenance(
                document, artefact_sha256=sha, config_hash="c", raw_output_ref=None
            ),
            expected_script_version=EXPECTED_SCRIPT_VERSION,
        )
        assert report.skipped["functions"] == 2
        assert report.is_partial is True
        assert of_type(report.evidence, EvidenceType.FUNCTION)


class TestTheInjectionSequenceIsDiscoverable:
    """What M10 will validate `behaviour:process_injection` against.

    The point of these two cases together: the positive one has the sequence
    on a reachable path, the negative one has the scary import and nothing
    else. Import presence alone must not be enough.
    """

    def test_the_injector_has_a_reachable_path_through_the_full_sequence(self) -> None:
        report = parse("injector_pe.json")
        graph = build_graph(report.evidence)

        for api in (
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ):
            path = graph.find_path("fn:main", f"fn:{api}")
            assert path is not None, f"{api} should be reachable from main"
            assert path.evidence_ids(), "each hop should cite the evidence that saw it"

    def test_the_benign_allocator_has_the_import_but_not_the_sequence(self) -> None:
        report = parse("benign_allocator_pe.json")
        graph = build_graph(report.evidence)

        imports = {
            e.observation.symbol  # type: ignore[union-attr]
            for e in of_type(report.evidence, EvidenceType.IMPORT)
        }
        assert "VirtualAllocEx" in imports, "the scary import is present"

        assert graph.find_path("fn:main", "fn:VirtualAllocEx") is not None
        for absent in ("OpenProcess", "WriteProcessMemory", "CreateRemoteThread"):
            assert f"fn:{absent}" not in graph, (
                f"{absent} is absent, so the injection sequence is incomplete"
            )

    def test_the_two_binaries_are_distinguishable_by_evidence_alone(self) -> None:
        """No model involved - the difference is structural."""
        injector = build_graph(parse("injector_pe.json").evidence)
        benign = build_graph(parse("benign_allocator_pe.json").evidence)

        def has_full_sequence(graph: object) -> bool:
            return all(
                graph.find_path("fn:main", f"fn:{api}") is not None  # type: ignore[attr-defined]
                for api in (
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                )
                if f"fn:{api}" in graph  # type: ignore[operator]
            ) and all(
                f"fn:{api}" in graph  # type: ignore[operator]
                for api in (
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                )
            )

        assert has_full_sequence(injector) is True
        assert has_full_sequence(benign) is False
