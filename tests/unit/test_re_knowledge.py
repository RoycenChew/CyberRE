"""The RE knowledge layer: records, lookup, and deterministic interpretation.

The test that matters most is at the bottom: run the two Ghidra fixtures
through the interpreter and show that the injector and the benign allocator
produce different interpretations, with no model involved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cyberre.adapters.ghidra.parser import build_provenance, parse_export
from cyberre.adapters.ghidra.runner import EXPECTED_SCRIPT_VERSION
from cyberre.core.contracts.knowledge import KnowledgeSource
from cyberre.core.models.evidence import Evidence
from cyberre.core.trust.levels import TrustLevel, may_satisfy_requirement
from cyberre.knowledge.re.interpret import (
    interpret,
    interpret_behaviours,
    interpret_imports,
    interpret_toolchain,
)
from cyberre.knowledge.re.schema import (
    Applicability,
    DangerClass,
    KnowledgeDomain,
    KnowledgeEntry,
)
from cyberre.knowledge.re.source import (
    KnowledgeLoadError,
    StructuredKnowledgeSource,
    load_file,
)

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ghidra"


@pytest.fixture(scope="module")
def knowledge() -> StructuredKnowledgeSource:
    return StructuredKnowledgeSource.from_directory()


def evidence_from(name: str) -> list[Evidence]:
    document: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    sha = str(document["binary"]["sha256"])
    return parse_export(
        document,
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=sha,
        provenance=build_provenance(
            document, artefact_sha256=sha, config_hash="c", raw_output_ref=None
        ),
        expected_script_version=EXPECTED_SCRIPT_VERSION,
    ).evidence


class TestSeedData:
    def test_the_seed_set_loads(self, knowledge: StructuredKnowledgeSource) -> None:
        assert len(knowledge) >= 50

    def test_every_domain_is_populated(self, knowledge: StructuredKnowledgeSource) -> None:
        for domain in KnowledgeDomain:
            if domain is KnowledgeDomain.ARCH:
                continue  # architecture records live in the formats file
            assert knowledge.in_domain(domain), f"{domain.value} has no records"

    def test_every_record_cites_a_source(self, knowledge: StructuredKnowledgeSource) -> None:
        """A knowledge base without citations is opinions with extra steps."""
        for entry in knowledge.all_entries():
            assert len(entry.source_ref) >= 8, entry.id

    def test_dangerous_apis_record_their_innocent_reading(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """Most uses of most of these are legitimate. Omitting that trains
        the system toward false positives."""
        for entry in knowledge.all_entries():
            if entry.danger_class in {
                DangerClass.INJECTION_PRIMITIVE,
                DangerClass.CREDENTIAL_ACCESS,
                DangerClass.PERSISTENCE_PRIMITIVE,
            }:
                assert entry.benign_explanation, f"{entry.id} has no benign explanation"

    def test_injection_primitives_name_their_companions(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """Companions are what stop a lone scary import becoming a finding."""
        primitives = knowledge.with_danger_class(DangerClass.INJECTION_PRIMITIVE)
        assert primitives
        assert sum(1 for e in primitives if e.companions) >= len(primitives) - 1

    def test_the_version_digest_changes_with_content(self) -> None:
        """A date or a file count would not change when a claim did."""
        base = KnowledgeEntry(
            id="x.y",
            version=1,
            domain=KnowledgeDomain.APIS,
            statement="s",
            source_ref="a documented source",
            confidence=0.5,
        )
        first = StructuredKnowledgeSource([base]).version
        second = StructuredKnowledgeSource([base.model_copy(update={"version": 2})]).version
        assert first != second


class TestLoading:
    def test_a_duplicate_id_is_rejected(self) -> None:
        entry = KnowledgeEntry(
            id="x.y",
            version=1,
            domain=KnowledgeDomain.APIS,
            statement="s",
            source_ref="a documented source",
            confidence=0.5,
        )
        with pytest.raises(KnowledgeLoadError, match="duplicate"):
            StructuredKnowledgeSource([entry, entry])

    def test_an_ambiguous_alias_is_rejected(self) -> None:
        """Two records answering to one symbol would make lookup depend on
        file ordering."""
        common = {
            "version": 1,
            "domain": KnowledgeDomain.APIS,
            "statement": "s",
            "source_ref": "a documented source",
            "confidence": 0.5,
        }
        with pytest.raises(KnowledgeLoadError, match="resolves to both"):
            StructuredKnowledgeSource(
                [
                    KnowledgeEntry(id="a.Foo", **common),  # type: ignore[arg-type]
                    KnowledgeEntry(id="b.Bar", aliases=("Foo",), **common),  # type: ignore[arg-type]
                ]
            )

    def test_a_file_without_a_domain_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("[[record]]\nid = 'x'\n", encoding="utf-8")
        with pytest.raises(KnowledgeLoadError, match="must declare a 'domain'"):
            load_file(bad)

    def test_malformed_toml_names_the_file(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("domain = [unclosed", encoding="utf-8")
        with pytest.raises(KnowledgeLoadError, match="not valid TOML"):
            load_file(bad)

    def test_a_confident_claim_needs_a_real_citation(self) -> None:
        with pytest.raises(ValueError, match="high confidence requires a source"):
            KnowledgeEntry(
                id="x.y",
                version=1,
                domain=KnowledgeDomain.APIS,
                statement="s",
                source_ref="docs",
                confidence=0.95,
            )


class TestLookup:
    def test_lookup_by_symbol_name(self, knowledge: StructuredKnowledgeSource) -> None:
        record = knowledge.lookup("VirtualAllocEx")
        assert record is not None
        assert record.record_id == "win.api.VirtualAllocEx"
        assert record.source_confidence >= 0.9

    def test_lookup_by_full_id(self, knowledge: StructuredKnowledgeSource) -> None:
        assert knowledge.lookup("win.api.VirtualAllocEx") is not None

    def test_lookup_by_alias(self, knowledge: StructuredKnowledgeSource) -> None:
        record = knowledge.lookup("LoadLibraryW")
        assert record is not None
        assert record.record_id == "win.api.LoadLibraryA"

    def test_a_miss_returns_none_rather_than_a_guess(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """A guess arrives wearing the same provenance as a fact."""
        assert knowledge.lookup("TotallyMadeUpApiW") is None

    def test_search_is_deterministic(self, knowledge: StructuredKnowledgeSource) -> None:
        first = [r.record_id for r in knowledge.search("inject")]
        second = [r.record_id for r in knowledge.search("inject")]
        assert first == second

    def test_records_carry_version_and_citation(self, knowledge: StructuredKnowledgeSource) -> None:
        record = knowledge.lookup("CreateRemoteThread")
        assert record is not None
        assert record.record_version >= 1
        assert "Microsoft Learn" in record.source_ref

    def test_it_satisfies_the_knowledge_source_protocol(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        assert isinstance(knowledge, KnowledgeSource)

    def test_structured_knowledge_is_authoritative(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """The semantic layer will answer False here and may not satisfy a
        validation requirement (ADR-017)."""
        assert knowledge.is_authoritative is True


class TestApplicability:
    def test_an_unconstrained_record_applies_everywhere(self) -> None:
        assert Applicability().matches(os_name="linux", architecture="aarch64")

    def test_a_windows_record_does_not_apply_to_linux(self) -> None:
        assert not Applicability(os=frozenset({"windows"})).matches(os_name="linux")

    def test_unknown_context_does_not_disqualify(self) -> None:
        """Refusing to apply knowledge for lack of context would silently
        lose most of it; the uncertainty belongs in confidence."""
        assert Applicability(os=frozenset({"windows"})).matches(os_name=None)


class TestInterpretationIsNotAFinding:
    def test_an_interpretation_cannot_satisfy_a_requirement(self) -> None:
        interpretations = interpret_imports(
            evidence_from("injector_pe.json"),
            StructuredKnowledgeSource.from_directory(),
            investigation_id="inv-1",
        )
        assert interpretations
        for item in interpretations:
            assert item.trust_level is TrustLevel.INTERPRETATION
            assert not may_satisfy_requirement(item.trust_level)

    def test_an_interpretation_must_cite_evidence(self) -> None:
        from cyberre.core.models.interpretation import Interpretation

        with pytest.raises(ValueError, match="at least 1 item"):
            Interpretation(
                investigation_id="inv-1",
                statement="Something is wrong.",
                cites_evidence=(),
                produced_by="test",
            )


class TestInterpretingImports:
    def test_a_dangerous_import_is_interpreted(self, knowledge: StructuredKnowledgeSource) -> None:
        results = interpret_imports(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        statements = " ".join(i.statement for i in results)
        assert "VirtualAllocEx" in statements
        assert "injection primitive" in statements

    def test_the_counter_argument_travels_with_the_claim(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """An interpretation without its counter-argument is half an analysis."""
        results = interpret_imports(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        assert all(i.counter_explanation for i in results)

    def test_it_records_what_is_still_missing(self, knowledge: StructuredKnowledgeSource) -> None:
        """Importing a symbol says nothing about whether it is called."""
        results = interpret_imports(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        assert any(
            "reached from an entry point" in m for i in results for m in i.missing_for_hypothesis
        )

    def test_knowledge_confidence_is_about_the_claim_not_the_binary(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        results = interpret_imports(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        assert all(0.8 <= i.knowledge_confidence <= 1.0 for i in results)

    def test_interpretations_cite_the_knowledge_version(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        results = interpret_imports(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        assert all("@" in ref for i in results for ref in i.cites_knowledge)

    def test_non_windows_context_suppresses_windows_records(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        results = interpret_imports(
            evidence_from("injector_pe.json"),
            knowledge,
            investigation_id="inv-1",
            os_name="linux",
        )
        assert results == []


class TestInterpretingBehaviours:
    def test_the_injector_proposes_process_injection(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        results = interpret_behaviours(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        classes = {i.suggests_hypothesis_class for i in results}
        assert "behaviour:process_injection" in classes

    def test_it_reports_completeness_rather_than_asserting(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """Imports are not calls, and calls are not a reachable path."""
        results = interpret_behaviours(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        remote_thread = next(
            i for i in results if any("remote_thread" in ref for ref in i.cites_knowledge)
        )
        assert "4 of 4" in remote_thread.statement
        assert "remote thread" in remote_thread.statement
        assert any("reachable" in m for m in remote_thread.missing_for_hypothesis)

    def test_the_benign_allocator_proposes_nothing(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """One shared primitive must not propose every behaviour mentioning it."""
        results = interpret_behaviours(
            evidence_from("benign_allocator_pe.json"), knowledge, investigation_id="inv-1"
        )
        assert results == []

    def test_a_partial_sequence_lists_what_is_absent(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        evidence = [
            e
            for e in evidence_from("injector_pe.json")
            if getattr(e.observation, "symbol", None) != "CreateRemoteThread"
        ]
        results = interpret_behaviours(evidence, knowledge, investigation_id="inv-1")
        remote_thread = next(
            i for i in results if any("remote_thread" in ref for ref in i.cites_knowledge)
        )
        assert "3 of 4" in remote_thread.statement
        assert any(
            "CreateRemoteThread is imported" in m for m in remote_thread.missing_for_hypothesis
        )

    def test_variants_of_one_category_are_distinguishable(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """Remote-thread and APC injection share a category. Two statements
        reading the same while meaning different things would be worse than
        useless in a report."""
        results = interpret_behaviours(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        injection = [
            i for i in results if i.suggests_hypothesis_class == "behaviour:process_injection"
        ]
        assert len(injection) > 1
        assert len({i.statement for i in injection}) == len(injection)


class TestInterpretingToolchain:
    def test_recognising_the_toolchain_proposes_no_hypothesis(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """Its value is suppression, not suspicion."""
        results = interpret_toolchain(
            evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1"
        )
        for item in results:
            assert item.suggests_hypothesis_class is None
            assert item.is_actionable is False


class TestTheTwoBinariesDiffer:
    """The whole point of the layer, with no model involved."""

    def test_the_injector_and_the_allocator_interpret_differently(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        injector = interpret(evidence_from("injector_pe.json"), knowledge, investigation_id="inv-1")
        benign = interpret(
            evidence_from("benign_allocator_pe.json"), knowledge, investigation_id="inv-1"
        )

        injector_classes = {i.suggests_hypothesis_class for i in injector}
        benign_classes = {i.suggests_hypothesis_class for i in benign}

        assert "behaviour:process_injection" in injector_classes

        # The benign binary still raises the single-API interpretation - the
        # import really is an injection primitive - but no behaviour is
        # proposed, because the sequence is not there.
        assert any("VirtualAllocEx" in i.statement for i in benign)
        assert not any("4 of 4" in i.statement or "3 of 4" in i.statement for i in benign)
        assert len(injector_classes) > len(benign_classes)

    def test_interpretation_is_deterministic(self, knowledge: StructuredKnowledgeSource) -> None:
        evidence = evidence_from("injector_pe.json")
        first = [i.statement for i in interpret(evidence, knowledge, investigation_id="inv-1")]
        second = [i.statement for i in interpret(evidence, knowledge, investigation_id="inv-1")]
        assert first == second
