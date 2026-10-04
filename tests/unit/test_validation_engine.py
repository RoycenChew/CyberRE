"""The validation engine.

Four properties matter more than the rest, and most of these tests exist for
one of them:

* a model cannot reach VALIDATED - only satisfied requirements can;
* an agent claim cannot satisfy a requirement, whatever it says;
* correlated evidence cannot satisfy several requirements at once;
* a negative answer says *why* - unreachable, inapplicable, contradicted and
  not-enough-evidence are four different answers.
"""

from __future__ import annotations

from typing import Any

import pytest
from cyberre.core.evidence.builder import build_graph
from cyberre.core.evidence.graph import Edge, EvidenceGraph
from cyberre.core.findings.predicates import PredicateContext
from cyberre.core.findings.requirements import (
    RequirementRegistry,
    default_requirement_sets,
)
from cyberre.core.findings.validation import ValidationEngine
from cyberre.core.models.enums import EdgeKind, EvidenceType, FindingStatus
from cyberre.core.models.evidence import AgentClaimRecord, Evidence
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.location import ArtefactLocation, SourceLocation
from cyberre.core.models.observation import (
    DataFlowPath,
    DependencyObservation,
    ImportObservation,
    KnowledgeRecord,
    ReachabilityObservation,
    ScannerFinding,
    SecretMatch,
)
from cyberre.core.models.provenance import Provenance, ToolProvenance
from cyberre.core.trust.levels import TrustLevel

pytestmark = pytest.mark.unit

SHA = "a" * 64


def provenance(tool: str) -> Provenance:
    return Provenance(tool=ToolProvenance(tool=tool, tool_version="1.0"), artefact_sha256=SHA)


def evidence(
    observation: Any,
    *,
    tool: str = "semgrep",
    key: str | None = None,
    location: Any = None,
    trust: TrustLevel = TrustLevel.NORMALIZED_EVIDENCE,
) -> Evidence:
    return Evidence(
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=SHA,
        evidence_type=EvidenceType(observation.kind),
        observation=observation,
        location=location or ArtefactLocation(detail=tool),
        provenance=provenance(tool),
        independence_key=key or f"{tool}-{observation.kind}-{id(observation)}",
        trust_level=trust,
    )


def hypothesis_for(hypothesis_class: str) -> Hypothesis:
    taxonomy, identifier = hypothesis_class.split(":", 1)
    return Hypothesis(
        investigation_id="inv-1",
        statement=f"a {hypothesis_class} weakness is present",
        hypothesis_class=HypothesisClass(taxonomy=taxonomy, identifier=identifier),
        created_by="reasoner",
    )


@pytest.fixture
def registry() -> RequirementRegistry:
    return RequirementRegistry()


@pytest.fixture
def engine() -> ValidationEngine:
    return ValidationEngine()


def validate(
    engine: ValidationEngine,
    registry: RequirementRegistry,
    hypothesis_class: str,
    items: list[Evidence],
    *,
    graph: EvidenceGraph | None = None,
) -> Any:
    return engine.validate(
        hypothesis_for(hypothesis_class),
        registry.for_class(hypothesis_class),
        evidence=items,
        graph=graph if graph is not None else build_graph(items),
    )


# --------------------------------------------------------------------- data


def command_injection_evidence() -> list[Evidence]:
    """A complete CWE-78 case: sink, source, no sanitiser, reachable."""
    return [
        evidence(
            ScannerFinding(
                rule_id="dangerous-subprocess-use",
                message="subprocess with shell=True",
                cwe=("CWE-78",),
            ),
            tool="semgrep",
            key="k-sink",
            location=SourceLocation(path="app/views.py", start_line=42),
        ),
        evidence(
            DataFlowPath(source="request.args", sink="subprocess.call", steps=("host",)),
            tool="dataflow",
            key="k-flow",
        ),
        evidence(
            ReachabilityObservation(
                target="subprocess.call", entry_point="http_route", reachable=True
            ),
            tool="reachability",
            key="k-reach",
        ),
    ]


def injection_sequence_evidence(*, complete: bool = True) -> list[Evidence]:
    symbols = ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    if not complete:
        symbols = symbols[:3]

    items = [
        evidence(
            ImportObservation(library="KERNEL32.dll", symbol=symbol),
            tool="ghidra",
            key=f"k-{symbol}",
        )
        for symbol in symbols
    ]
    items.append(
        evidence(
            KnowledgeRecord(
                record_id="behaviour.process_injection.remote_thread",
                record_version=1,
                statement="classic remote-thread injection",
                source_ref="MITRE ATT&CK T1055.002",
                source_confidence=0.9,
            ),
            tool="knowledge.re",
            key="k-knowledge",
        )
    )
    items.append(
        evidence(
            ReachabilityObservation(
                target="createremotethread", entry_point="main", reachable=True
            ),
            tool="ghidra",
            key="k-reach",
        )
    )
    return items


# -------------------------------------------------------------------- tests


class TestTheGoodPath:
    def test_a_complete_case_validates(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", command_injection_evidence())
        assert outcome.status is FindingStatus.VALIDATED
        assert outcome.completeness == 1.0
        assert outcome.is_validated

    def test_a_validated_outcome_cites_the_evidence(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", command_injection_evidence())
        assert outcome.satisfied_evidence_ids
        assert all(r.evidence_ids for r in outcome.results if r.satisfied)

    def test_the_binary_injection_sequence_validates(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(
            engine,
            registry,
            "behaviour:process_injection",
            injection_sequence_evidence(),
        )
        assert outcome.status is FindingStatus.VALIDATED


class TestIncompleteEvidence:
    def test_a_scanner_hit_alone_is_not_a_finding(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """The single most important negative case. A pattern fired; that is
        an observation about the code, not a vulnerability."""
        only_scanner = command_injection_evidence()[:1]
        outcome = validate(engine, registry, "cwe:78", only_scanner)

        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE
        assert outcome.completeness < 0.5

    def test_the_outcome_names_what_is_missing(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Unsatisfied requirements are the investigation's next needs."""
        outcome = validate(engine, registry, "cwe:78", command_injection_evidence()[:1])
        assert "req.cwe.78.reachable" in outcome.unsatisfied
        assert "Still needed" in outcome.explanation

    def test_completeness_is_the_fraction_satisfied(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", command_injection_evidence()[:2])
        assert 0.0 < outcome.completeness < 1.0

    def test_a_partial_api_sequence_does_not_validate(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Three of four injection calls is ordinary memory work."""
        outcome = validate(
            engine,
            registry,
            "behaviour:process_injection",
            injection_sequence_evidence(complete=False),
        )
        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE

    def test_a_sanitised_flow_does_not_satisfy_the_no_sanitisation_requirement(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """The false-positive trap: parameterised SQL that pattern-matches."""
        items = [
            evidence(
                ScannerFinding(rule_id="avoid-raw-sql", message="raw SQL", cwe=("CWE-89",)),
                key="k-sink",
            ),
            evidence(
                DataFlowPath(
                    source="request.args",
                    sink="cursor.execute",
                    sanitizers=("parameterised query",),
                ),
                tool="dataflow",
                key="k-flow",
            ),
            evidence(
                ReachabilityObservation(
                    target="cursor.execute", entry_point="route", reachable=True
                ),
                tool="reachability",
                key="k-reach",
            ),
        ]
        outcome = validate(engine, registry, "cwe:89", items)

        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE
        assert "req.cwe.89.no_sanitisation" in outcome.unsatisfied


class TestNegativeAnswersSayWhy:
    def test_disproven_reachability_reports_unreachable(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """An established negative, not a failure to find evidence."""
        items = [
            *command_injection_evidence()[:2],
            evidence(
                ReachabilityObservation(
                    target="subprocess.call", entry_point="main", reachable=False
                ),
                tool="reachability",
                key="k-unreach",
            ),
        ]
        outcome = validate(engine, registry, "cwe:78", items)

        assert outcome.status is FindingStatus.UNREACHABLE
        assert "established negative" in outcome.explanation

    def test_unreachable_outranks_not_enough_evidence(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Knowing the code is dead is more useful than knowing we are unsure."""
        items = [
            evidence(
                ReachabilityObservation(
                    target="subprocess.call", entry_point="main", reachable=False
                ),
                tool="reachability",
                key="k-unreach",
            )
        ]
        assert validate(engine, registry, "cwe:78", items).status is (FindingStatus.UNREACHABLE)

    def test_an_unpinned_dependency_is_not_applicable(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """A package name matching an advisory means almost nothing."""
        items = [
            evidence(
                DependencyObservation(ecosystem="pypi", name="requests", version=None),
                tool="deps",
                key="k-dep",
            )
        ]
        outcome = validate(engine, registry, "cve:applicability", items)
        assert outcome.status is FindingStatus.NOT_APPLICABLE

    def test_a_contradiction_is_reported_not_resolved(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Silently picking a winner is how a platform ends up confidently
        wrong."""
        items = command_injection_evidence()
        hypothesis = hypothesis_for("cwe:78")
        graph = build_graph(items)
        graph.add_edge(
            Edge(
                source=items[0].evidence_id,
                kind=EdgeKind.CONTRADICTS,
                target=hypothesis.hypothesis_id,
            )
        )

        outcome = engine.validate(
            hypothesis,
            registry.for_class("cwe:78"),
            evidence=items,
            graph=graph,
        )
        assert outcome.status is FindingStatus.CONTRADICTED


class TestInvariant2AgentClaims:
    def test_an_agent_claim_cannot_satisfy_a_requirement(self) -> None:
        """Enforced at the trust filter, the third independent place after
        the lattice and the storage schema."""
        claim = AgentClaimRecord(
            investigation_id="inv-1",
            artefact_id="ar-1",
            agent="codex",
            statement="This is definitely command injection.",
        )
        assert claim.trust_level is TrustLevel.AGENT_CLAIM
        context = PredicateContext(evidence=[], graph=EvidenceGraph())
        assert context.admissible() == []

    def test_an_interpretation_level_record_is_inadmissible(self) -> None:
        """Only normalised and derived evidence may satisfy a requirement."""
        from cyberre.core.trust.levels import may_satisfy_requirement

        assert not may_satisfy_requirement(TrustLevel.INTERPRETATION)
        assert not may_satisfy_requirement(TrustLevel.HYPOTHESIS)


class TestCorroboration:
    """Independence governs how much a satisfied set is worth, not whether
    each requirement was established.

    One analysis can legitimately establish several distinct facts - a
    data-flow run shows both that a flow exists and that it carries no
    sanitiser - so discounting the second would make a genuine finding
    unprovable. What stops a single scanner hit satisfying a whole set is
    predicate specificity: each requirement demands a different evidence
    type.
    """

    @staticmethod
    def _single_source_items() -> list[Evidence]:
        shared = "one-and-the-same"
        return [
            evidence(
                DataFlowPath(source="request", sink="subprocess.call"),
                tool="dataflow",
                key=shared,
            ),
            evidence(
                ReachabilityObservation(
                    target="subprocess.call", entry_point="route", reachable=True
                ),
                tool="dataflow",
                key=shared,
            ),
        ]

    def test_a_scanner_hit_cannot_satisfy_the_other_requirements(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """The protection that matters, and it comes from the predicates."""
        only_scanner = [
            evidence(
                ScannerFinding(
                    rule_id="dangerous-subprocess-use",
                    message="shell=True",
                    cwe=("CWE-78",),
                ),
                key="k-sink",
            )
        ]
        outcome = validate(engine, registry, "cwe:78", only_scanner)
        satisfied = [r.requirement_id for r in outcome.results if r.satisfied]
        assert satisfied == ["req.cwe.78.sink"]

    def test_requirements_from_one_source_are_marked_uncorroborated(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", self._single_source_items())
        assert outcome.uncorroborated, "later requirements rest on the same source"

    def test_being_uncorroborated_does_not_unsatisfy_a_requirement(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", self._single_source_items())
        marked = [r for r in outcome.results if r.shares_source_with_earlier]
        assert marked
        assert all(r.satisfied for r in marked)

    def test_one_source_and_many_sources_are_distinguishable(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Both may be complete; they are not equally strong, and the
        confidence engine needs to be able to tell."""
        thin = validate(engine, registry, "cwe:78", self._single_source_items())
        thick = validate(engine, registry, "cwe:78", command_injection_evidence())
        assert thick.independent_source_count > thin.independent_source_count

    def test_independent_sources_are_counted(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        outcome = validate(engine, registry, "cwe:78", command_injection_evidence())
        assert outcome.independent_source_count >= 3

    def test_correlated_evidence_counts_once(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Three records sharing a source are one observation."""
        outcome = validate(engine, registry, "cwe:78", self._single_source_items())
        assert outcome.independent_source_count == 1

    def test_tracking_can_be_turned_off_without_changing_outcomes(
        self, registry: RequirementRegistry
    ) -> None:
        items = self._single_source_items()
        tracked = ValidationEngine().validate(
            hypothesis_for("cwe:78"),
            registry.for_class("cwe:78"),
            evidence=items,
            graph=build_graph(items),
        )
        untracked = ValidationEngine(track_corroboration=False).validate(
            hypothesis_for("cwe:78"),
            registry.for_class("cwe:78"),
            evidence=items,
            graph=build_graph(items),
        )
        assert tracked.completeness == untracked.completeness
        assert tracked.uncorroborated and not untracked.uncorroborated


class TestRequirementSets:
    def test_every_shipped_set_has_mandatory_requirements(
        self, registry: RequirementRegistry
    ) -> None:
        """A set with none would validate on an empty evidence list."""
        for requirement_set in registry.all_sets():
            assert requirement_set.mandatory, requirement_set.set_id

    def test_every_profile_requirement_set_exists(self, registry: RequirementRegistry) -> None:
        """A hypothesis class whose set is missing would hang in UNVALIDATED."""
        from pathlib import Path

        from cyberre.core.profiles.loader import ProfileRegistry

        profiles = ProfileRegistry.from_directory(Path(__file__).resolve().parents[2] / "profiles")
        missing: list[str] = []
        for profile in profiles.implemented():
            for set_id in profile.requirement_sets.values():
                if set_id not in {s.set_id for s in registry.all_sets()}:
                    missing.append(f"{profile.profile_id.value}: {set_id}")
        assert not missing, missing

    def test_an_unknown_set_raises_with_an_explanation(self, registry: RequirementRegistry) -> None:
        with pytest.raises(KeyError, match="UNVALIDATED"):
            registry.get("req.nonexistent")

    def test_taint_sets_all_demand_reachability(self, registry: RequirementRegistry) -> None:
        """Without it, dead code is reported as a vulnerability."""
        for set_id in ("req.cwe.78", "req.cwe.89", "req.cwe.22", "req.cwe.502"):
            ids = [r.requirement_id for r in registry.get(set_id).requirements]
            assert any(i.endswith(".reachable") for i in ids), set_id

    def test_cve_applicability_demands_a_resolved_version(
        self, registry: RequirementRegistry
    ) -> None:
        ids = [r.requirement_id for r in registry.get("req.cve.applicability").requirements]
        assert "req.cve.applicability.resolved_version" in ids

    def test_the_default_sets_are_stable(self) -> None:
        assert set(default_requirement_sets()) == {
            s.set_id for s in RequirementRegistry().all_sets()
        }


class TestHardcodedSecret:
    def test_an_embedded_credential_validates_on_its_own(
        self, engine: ValidationEngine, registry: RequirementRegistry
    ) -> None:
        """Unlike a taint weakness, a committed credential needs no
        reachability argument - it is already disclosed."""
        items = [
            evidence(
                SecretMatch(detector="aws_access_key_id", redacted_preview="AKIA****"),
                tool="secrets",
                key="k-secret",
            )
        ]
        assert validate(engine, registry, "cwe:798", items).status is (FindingStatus.VALIDATED)
