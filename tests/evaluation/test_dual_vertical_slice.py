"""The dual vertical slice: source security and binary reverse engineering,
each through the whole chain.

    artefact -> evidence -> interpretation -> packet -> hypothesis
             -> validation -> adversarial review -> confidence -> report

This is the M12 acceptance test, and per ADR-002 it is the first point at
which anything in CyberRE may call itself a finding - validation and review
exist now, so there is something able to say no.

Four cases, and the negative ones matter as much as the positive:

* source, genuinely injectable  -> VALIDATED
* source, parameterised query   -> not established (the false-positive trap)
* binary, full injection chain  -> VALIDATED
* binary, benign allocator      -> not established, despite the scary import

The model is replayed from a cassette, so these run offline, deterministically
and for free. What is *not* replayed is anything that decides an outcome:
validation, confidence and status resolution are deterministic code, and the
reviewer can only weaken. Swapping the cassette for a live provider changes
the wording of a hypothesis, not whether it becomes a finding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cyberre.adapters.ghidra.parser import build_provenance as ghidra_provenance
from cyberre.adapters.ghidra.parser import parse_export
from cyberre.adapters.ghidra.runner import EXPECTED_SCRIPT_VERSION
from cyberre.adapters.models.prompt import hash_prompt
from cyberre.adapters.models.replay import Cassette, RecordedCall, ReplayProvider
from cyberre.adapters.semgrep.parser import build_provenance as semgrep_provenance
from cyberre.adapters.semgrep.parser import parse_semgrep, ruleset_digest
from cyberre.agent.reasoning.reasoner import (
    DISCOVERY_TEMPLATE_VERSION,
    VERIFICATION_TEMPLATE_VERSION,
    ChiefSecurityReasoner,
    DiscoveryResponse,
    VerificationResponse,
)
from cyberre.agent.reviewers.adversarial import (
    PROMPT_TEMPLATE_VERSION as REVIEW_TEMPLATE_VERSION,
)
from cyberre.agent.reviewers.adversarial import (
    AdversarialReviewer,
    ReviewResponse,
    build_packet,
)
from cyberre.core.contracts.model_provider import Message, MessageRole, ModelTier
from cyberre.core.evidence.builder import build_graph
from cyberre.core.evidence.compiler import EvidenceContextCompiler
from cyberre.core.evidence.digest import build_manifest
from cyberre.core.findings.assembly import assemble
from cyberre.core.findings.confidence import ConfidenceConfig, ConfidenceEngine
from cyberre.core.findings.report import ReportGenerator
from cyberre.core.findings.requirements import RequirementRegistry
from cyberre.core.findings.validation import ValidationEngine
from cyberre.core.models.enums import EvidenceType, FindingStatus, InvestigationStatus
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.observation import DataFlowPath, ReachabilityObservation
from cyberre.core.models.state import InvestigationState, Objective
from cyberre.knowledge.re.interpret import interpret
from cyberre.knowledge.re.source import StructuredKnowledgeSource

pytestmark = pytest.mark.evaluation

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "confidence.toml"
SHA_SOURCE = "c" * 64


# --------------------------------------------------------------------------
# Evidence assembly for each slice.
# --------------------------------------------------------------------------


def _extra(observation: Any, *, tool: str, key: str) -> Evidence:
    """Evidence a dedicated analyser would produce.

    Data-flow and reachability analysis are capabilities CyberRE declares
    and has not implemented yet, so these stand in for them. They are built
    through the same model and carry the same provenance discipline as any
    other evidence - nothing here is privileged.
    """
    from cyberre.core.models.location import ArtefactLocation
    from cyberre.core.models.provenance import Provenance, ToolProvenance

    location = ArtefactLocation(detail=key)
    return Evidence(
        investigation_id="inv-slice",
        artefact_id="ar-source",
        artefact_sha256=SHA_SOURCE,
        evidence_type=EvidenceType(observation.kind),
        observation=observation,
        location=location,
        provenance=Provenance(
            tool=ToolProvenance(tool=tool, tool_version="1.0.0"),
            artefact_sha256=SHA_SOURCE,
        ),
        independence_key=derive_independence_key(tool, SHA_SOURCE, str(location), observation.kind),
        source_reliability=0.85,
    )


def source_evidence(*, vulnerable: bool) -> list[Evidence]:
    """Evidence for the source slice, from the recorded Semgrep run."""
    document = json.loads(
        (ROOT / "fixtures" / "semgrep" / "vulnerable_app.json").read_text(encoding="utf-8")
    )
    wanted = "views.py" if vulnerable else "reports.py"
    document["results"] = [r for r in document["results"] if wanted in str(r.get("path", ""))]

    report = parse_semgrep(
        document,
        investigation_id="inv-slice",
        artefact_id="ar-source",
        artefact_sha256=SHA_SOURCE,
        provenance=semgrep_provenance(
            semgrep_version="1.52.0",
            ruleset_version="p/security-audit",
            ruleset_hash=ruleset_digest(["p/security-audit"]),
            artefact_sha256=SHA_SOURCE,
            raw_output_ref="obj/semgrep",
        ),
    )
    items = list(report.evidence)

    if vulnerable:
        items.append(
            _extra(
                DataFlowPath(
                    source="request.args.get('host')",
                    sink="subprocess.call",
                    steps=("host",),
                    source_is_external=True,
                ),
                tool="dataflow",
                key="flow-injectable",
            )
        )
    else:
        # The false-positive trap: the same shape of flow, but parameterised.
        items.append(
            _extra(
                DataFlowPath(
                    source="request.args.get('id')",
                    sink="cursor.execute",
                    steps=("report_id",),
                    sanitizers=("parameterised query",),
                    source_is_external=True,
                ),
                tool="dataflow",
                key="flow-parameterised",
            )
        )

    items.append(
        _extra(
            ReachabilityObservation(
                target="subprocess.call" if vulnerable else "cursor.execute",
                entry_point="http_route",
                reachable=True,
            ),
            tool="reachability",
            key="reach",
        )
    )
    return items


def binary_evidence(*, injector: bool) -> list[Evidence]:
    """Evidence for the binary slice, from a recorded Ghidra export."""
    name = "injector_pe.json" if injector else "benign_allocator_pe.json"
    document = json.loads((ROOT / "fixtures" / "ghidra" / name).read_text(encoding="utf-8"))
    sha = str(document["binary"]["sha256"])
    report = parse_export(
        document,
        investigation_id="inv-slice",
        artefact_id="ar-binary",
        artefact_sha256=sha,
        provenance=ghidra_provenance(
            document,
            artefact_sha256=sha,
            config_hash="default",
            raw_output_ref="obj/ghidra",
        ),
        expected_script_version=EXPECTED_SCRIPT_VERSION,
    )
    return list(report.evidence)


def knowledge_evidence(
    items: list[Evidence], knowledge: StructuredKnowledgeSource
) -> list[Evidence]:
    """Turn applicable knowledge records into evidence.

    The behaviour requirement set demands a knowledge record, so the lookup
    has to produce evidence rather than only an interpretation.
    """
    from cyberre.core.models.location import ArtefactLocation
    from cyberre.core.models.provenance import Provenance, ToolProvenance

    symbols = {
        str(getattr(e.observation, "symbol", ""))
        for e in items
        if e.evidence_type is EvidenceType.IMPORT
    }
    entry = knowledge.entry("behaviour.process_injection.remote_thread")
    if entry is None or not set(entry.companions) <= symbols:
        return []

    artefact_sha = items[0].artefact_sha256
    location = ArtefactLocation(detail=entry.id)
    return [
        Evidence(
            investigation_id="inv-slice",
            artefact_id=items[0].artefact_id,
            artefact_sha256=artefact_sha,
            evidence_type=EvidenceType.KNOWLEDGE_RECORD,
            observation=knowledge.to_record(entry),
            location=location,
            provenance=Provenance(
                tool=ToolProvenance(tool="knowledge.re", tool_version=knowledge.version),
                artefact_sha256=artefact_sha,
            ),
            independence_key=derive_independence_key(
                "knowledge.re", artefact_sha, str(location), "knowledge_record"
            ),
            source_reliability=entry.confidence,
        )
    ]


def reachability_for_sequence(items: list[Evidence]) -> list[Evidence]:
    """Reachability of the injection sequence, from the call graph.

    Derived from the graph rather than asserted: if no path exists, no
    evidence is produced, and the requirement stays unsatisfied.
    """
    from cyberre.core.models.location import ArtefactLocation
    from cyberre.core.models.provenance import Provenance, ToolProvenance

    graph = build_graph(items)
    if "fn:main" not in graph or "fn:CreateRemoteThread" not in graph:
        return []
    if graph.find_path("fn:main", "fn:CreateRemoteThread") is None:
        return []

    artefact_sha = items[0].artefact_sha256
    location = ArtefactLocation(detail="reachability")
    return [
        Evidence(
            investigation_id="inv-slice",
            artefact_id=items[0].artefact_id,
            artefact_sha256=artefact_sha,
            evidence_type=EvidenceType.REACHABILITY,
            observation=ReachabilityObservation(
                target="createremotethread", entry_point="main", reachable=True
            ),
            location=location,
            provenance=Provenance(
                tool=ToolProvenance(tool="callgraph", tool_version="1.0.0"),
                artefact_sha256=artefact_sha,
            ),
            independence_key=derive_independence_key(
                "callgraph", artefact_sha, str(location), "reachability"
            ),
            source_reliability=0.8,
        )
    ]


# --------------------------------------------------------------------------
# The cassette. Recorded answers for each packet the slices produce.
# --------------------------------------------------------------------------


def record(
    packet_text: str,
    template: str,
    schema_name: str,
    payload: Any,
) -> RecordedCall:
    system = {
        DISCOVERY_TEMPLATE_VERSION: "discovery",
        VERIFICATION_TEMPLATE_VERSION: "verification",
        REVIEW_TEMPLATE_VERSION: "review",
    }
    assert template in system
    return RecordedCall(
        prompt_hash="placeholder",
        schema_name=schema_name,
        template_version=template,
        tier=ModelTier.REASONING,
        model_id="recorded",
        provider="cassette",
        response_json=payload.model_dump_json(),
    )


def cassette_for(
    *,
    discovery: tuple[str, DiscoveryResponse, list[Message]],
    verification: tuple[VerificationResponse, list[Message]] | None,
    review: tuple[ReviewResponse, list[Message]] | None,
) -> Cassette:
    calls = []

    _, discovery_payload, discovery_messages = discovery
    calls.append(
        RecordedCall(
            prompt_hash=hash_prompt(
                discovery_messages,
                schema_name="DiscoveryResponse",
                template_version=DISCOVERY_TEMPLATE_VERSION,
            ),
            schema_name="DiscoveryResponse",
            template_version=DISCOVERY_TEMPLATE_VERSION,
            tier=ModelTier.REASONING,
            model_id="recorded",
            provider="cassette",
            response_json=discovery_payload.model_dump_json(),
        )
    )

    if verification is not None:
        payload, messages = verification
        calls.append(
            RecordedCall(
                prompt_hash=hash_prompt(
                    messages,
                    schema_name="VerificationResponse",
                    template_version=VERIFICATION_TEMPLATE_VERSION,
                ),
                schema_name="VerificationResponse",
                template_version=VERIFICATION_TEMPLATE_VERSION,
                tier=ModelTier.REASONING,
                model_id="recorded",
                provider="cassette",
                response_json=payload.model_dump_json(),
            )
        )

    if review is not None:
        payload, messages = review
        calls.append(
            RecordedCall(
                prompt_hash=hash_prompt(
                    messages,
                    schema_name="ReviewResponse",
                    template_version=REVIEW_TEMPLATE_VERSION,
                ),
                schema_name="ReviewResponse",
                template_version=REVIEW_TEMPLATE_VERSION,
                tier=ModelTier.REASONING,
                model_id="recorded",
                provider="cassette",
                response_json=payload.model_dump_json(),
            )
        )

    return Cassette(calls=tuple(calls))


# --------------------------------------------------------------------------
# The pipeline, run end to end.
# --------------------------------------------------------------------------


class SliceResult:
    def __init__(self) -> None:
        self.findings: list[Any] = []
        self.report: Any = None
        self.outcome: Any = None
        self.model_calls = 0


def run_slice(
    *,
    question: str,
    objective: str,
    evidence: list[Evidence],
    hypothesis_class: str,
    discovery: DiscoveryResponse,
    verification: VerificationResponse,
    review: ReviewResponse,
    interpretations: Any = (),
) -> SliceResult:
    """Run one slice all the way to a report."""
    result = SliceResult()
    graph = build_graph(evidence)
    by_id = {e.evidence_id: e for e in evidence}

    compiler = EvidenceContextCompiler()
    packet = compiler.compile(
        question=question,
        objective=objective,
        evidence=evidence,
        graph=graph,
        interpretations=interpretations,
    ).packet

    # Build the cassette against the exact prompts this packet produces.
    from cyberre.agent.reasoning.reasoner import DISCOVERY_PROMPT, VERIFICATION_PROMPT

    discovery_messages = [
        Message(role=MessageRole.SYSTEM, content=DISCOVERY_PROMPT),
        Message(role=MessageRole.USER, content=packet.render()),
    ]

    provider = ReplayProvider(
        cassette_for(
            discovery=("", discovery, discovery_messages),
            verification=None,
            review=None,
        )
    )
    reasoner = ChiefSecurityReasoner(provider)

    # The verification prompt depends on the hypotheses discovery produced,
    # so the cassette is completed after the first pass is known.
    first = reasoner.reason(packet, investigation_id="inv-slice")
    if first.hypotheses:
        listing = "\n".join(
            f"  - {h.statement} [{h.hypothesis_class}] cites {', '.join(h.cites)}"
            for h in first.hypotheses
        )
        verification_messages = [
            Message(role=MessageRole.SYSTEM, content=VERIFICATION_PROMPT),
            Message(
                role=MessageRole.USER,
                content=f"{packet.render()}\n\nHYPOTHESES TO VERIFY:\n{listing}",
            ),
        ]
        provider = ReplayProvider(
            cassette_for(
                discovery=("", discovery, discovery_messages),
                verification=(verification, verification_messages),
                review=None,
            )
        )
        reasoning = ChiefSecurityReasoner(provider).reason(packet, investigation_id="inv-slice")
    else:
        reasoning = first

    result.model_calls = reasoning.model_calls

    registry = RequirementRegistry()
    validator = ValidationEngine()
    engine = ConfidenceEngine(ConfidenceConfig.load(CONFIG))

    for candidate in reasoning.candidates:
        hypothesis = next(
            h for h in reasoning.hypotheses if h.hypothesis_id == candidate.hypothesis_id
        )
        if not registry.covers(str(hypothesis.hypothesis_class)):
            continue

        outcome = validator.validate(
            hypothesis,
            registry.for_class(str(hypothesis.hypothesis_class)),
            evidence=evidence,
            graph=graph,
        )
        result.outcome = outcome

        review_packet = build_packet(
            candidate, outcome, evidence=by_id, interpretations=interpretations
        )
        review_messages = [
            Message(
                role=MessageRole.SYSTEM,
                content=__import__(
                    "cyberre.agent.reviewers.adversarial", fromlist=["SYSTEM_PROMPT"]
                ).SYSTEM_PROMPT,
            ),
            Message(role=MessageRole.USER, content=review_packet.render()),
        ]
        reviewer = AdversarialReviewer(
            ReplayProvider(
                cassette_for(
                    discovery=("", discovery, discovery_messages),
                    verification=None,
                    review=(review, review_messages),
                )
            )
        )
        verdict = reviewer.review(review_packet, known_evidence_ids=frozenset(by_id))

        result.findings.append(
            assemble(
                candidate,
                outcome,
                hypothesis.hypothesis_class,
                evidence=by_id,
                confidence_engine=engine,
                review=verdict,
            )
        )

    state = InvestigationState(
        investigation_id="inv-slice",
        objective=Objective(question=question, normalised_intent=objective),
        status=InvestigationStatus.COMPLETE,
        evidence_ids=tuple(by_id),
        artefact_ids=(evidence[0].artefact_id,),
    )
    result.report = ReportGenerator().generate(
        state,
        findings=result.findings,
        evidence=by_id,
        manifest=build_manifest(
            investigation_id="inv-slice",
            evidence=evidence,
            findings=result.findings,
            cyberre_version="0.1.0.dev0",
            confidence_formula_version="v1",
        ),
    )
    return result


# --------------------------------------------------------------------------
# The four cases.
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def knowledge() -> StructuredKnowledgeSource:
    return StructuredKnowledgeSource.from_directory()


class TestSourceSlice:
    def test_a_genuine_injection_reaches_a_validated_finding(self) -> None:
        evidence = source_evidence(vulnerable=True)
        sink = next(e for e in evidence if e.evidence_type is EvidenceType.SCANNER_FINDING)
        flow = next(e for e in evidence if e.evidence_type is EvidenceType.DATA_FLOW)
        reach = next(e for e in evidence if e.evidence_type is EvidenceType.REACHABILITY)

        result = run_slice(
            question="Are there command injection vulnerabilities?",
            objective="find_command_injection",
            evidence=evidence,
            hypothesis_class="cwe:78",
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "User-controlled input reaches a shell command.",
                        "hypothesis_class": "cwe:78",
                        "cited_evidence": [sink.evidence_id, flow.evidence_id],
                        "missing_evidence": [],
                    }
                ]
            ),
            verification=VerificationResponse(
                candidates=[
                    {  # type: ignore[list-item]
                        "hypothesis_statement": "User-controlled input reaches a shell command.",
                        "title": "Command injection in the ping handler",
                        "description": (
                            "A request parameter flows into a subprocess call with "
                            "shell=True and no sanitiser was observed on the path."
                        ),
                        "cited_evidence": [
                            sink.evidence_id,
                            flow.evidence_id,
                            reach.evidence_id,
                        ],
                    }
                ]
            ),
            review=ReviewResponse(
                verdict="uphold",
                rationale="The flow is unsanitised and reachable from an HTTP route.",
                cited_evidence=[flow.evidence_id, reach.evidence_id],
            ),
        )

        assert result.findings, "the slice should produce a finding"
        finding = result.findings[0]
        assert finding.status is FindingStatus.VALIDATED
        assert finding.severity is not None
        assert finding.confidence is not None
        assert finding.confidence.final_score > 0.5
        assert finding.evidence_ids

    def test_a_parameterised_query_is_not_established(self) -> None:
        """The false-positive trap. The scanner fired, the flow exists and
        it is reachable - and a sanitiser is on the path, so the
        no-sanitisation requirement is unmet."""
        evidence = source_evidence(vulnerable=False)
        sink = next(e for e in evidence if e.evidence_type is EvidenceType.SCANNER_FINDING)
        flow = next(e for e in evidence if e.evidence_type is EvidenceType.DATA_FLOW)

        result = run_slice(
            question="Are there SQL injection vulnerabilities?",
            objective="find_sql_injection",
            evidence=evidence,
            hypothesis_class="cwe:89",
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "A request parameter reaches a SQL query.",
                        "hypothesis_class": "cwe:89",
                        "cited_evidence": [sink.evidence_id, flow.evidence_id],
                        "missing_evidence": ["whether the query is parameterised"],
                    }
                ]
            ),
            verification=VerificationResponse(
                candidates=[
                    {  # type: ignore[list-item]
                        "hypothesis_statement": "A request parameter reaches a SQL query.",
                        "title": "Possible SQL injection in the report lookup",
                        "description": "A request parameter reaches cursor.execute.",
                        "cited_evidence": [sink.evidence_id, flow.evidence_id],
                    }
                ]
            ),
            review=ReviewResponse(
                verdict="reject",
                rationale="The query is parameterised; the value is bound, not interpolated.",
                cited_evidence=[flow.evidence_id],
            ),
        )

        assert result.findings
        finding = result.findings[0]
        assert finding.status is not FindingStatus.VALIDATED
        assert finding.severity is None, "an unestablished outcome carries no severity"
        assert not finding.is_reportable

    def test_the_sanitiser_is_why_it_failed(self) -> None:
        """Not an accident of scoring - the specific requirement is named."""
        evidence = source_evidence(vulnerable=False)
        graph = build_graph(evidence)
        registry = RequirementRegistry()
        from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass

        outcome = ValidationEngine().validate(
            Hypothesis(
                investigation_id="inv-slice",
                statement="sql injection",
                hypothesis_class=HypothesisClass(taxonomy="cwe", identifier="89"),
                created_by="test",
            ),
            registry.for_class("cwe:89"),
            evidence=evidence,
            graph=graph,
        )
        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE
        assert "req.cwe.89.no_sanitisation" in outcome.unsatisfied


class TestBinarySlice:
    def test_the_injector_reaches_a_validated_finding(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        evidence = binary_evidence(injector=True)
        evidence += knowledge_evidence(evidence, knowledge)
        evidence += reachability_for_sequence(evidence)

        interpretations = interpret(
            evidence, knowledge, investigation_id="inv-slice", os_name="windows"
        )
        imports = [e for e in evidence if e.evidence_type is EvidenceType.IMPORT]
        cited = [e.evidence_id for e in imports[:3]]

        result = run_slice(
            question="What does this binary do?",
            objective="assess_binary_behaviour",
            evidence=evidence,
            hypothesis_class="behaviour:process_injection",
            interpretations=interpretations,
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "The binary may perform remote-thread process injection.",
                        "hypothesis_class": "behaviour:process_injection",
                        "cited_evidence": cited,
                        "missing_evidence": [],
                    }
                ]
            ),
            verification=VerificationResponse(
                candidates=[
                    {  # type: ignore[list-item]
                        "hypothesis_statement": (
                            "The binary may perform remote-thread process injection."
                        ),
                        "title": "Remote-thread process injection sequence",
                        "description": (
                            "The binary imports OpenProcess, VirtualAllocEx, "
                            "WriteProcessMemory and CreateRemoteThread, and the call "
                            "graph connects them on a path from main."
                        ),
                        "cited_evidence": cited,
                    }
                ]
            ),
            review=ReviewResponse(
                verdict="uphold",
                rationale="The full sequence is present and reachable from main.",
                cited_evidence=cited[:1],
            ),
        )

        assert result.findings
        finding = result.findings[0]
        assert finding.status is FindingStatus.VALIDATED
        assert finding.confidence is not None

    def test_the_benign_allocator_is_not_established(
        self, knowledge: StructuredKnowledgeSource
    ) -> None:
        """The scary import is present and nothing else is. No model is
        involved in that distinction."""
        evidence = binary_evidence(injector=False)
        evidence += knowledge_evidence(evidence, knowledge)
        evidence += reachability_for_sequence(evidence)

        imports = [e for e in evidence if e.evidence_type is EvidenceType.IMPORT]
        symbols = {str(getattr(e.observation, "symbol", "")) for e in imports}
        assert "VirtualAllocEx" in symbols, "the alarming import is present"

        from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass

        outcome = ValidationEngine().validate(
            Hypothesis(
                investigation_id="inv-slice",
                statement="process injection",
                hypothesis_class=HypothesisClass(
                    taxonomy="behaviour", identifier="process_injection"
                ),
                created_by="test",
            ),
            RequirementRegistry().for_class("behaviour:process_injection"),
            evidence=evidence,
            graph=build_graph(evidence),
        )

        assert outcome.status is FindingStatus.NOT_ENOUGH_EVIDENCE
        assert "req.behaviour.process_injection.api_sequence" in outcome.unsatisfied


class TestTheReport:
    def test_a_validated_finding_is_reported_with_its_evidence(self) -> None:
        evidence = source_evidence(vulnerable=True)
        sink = next(e for e in evidence if e.evidence_type is EvidenceType.SCANNER_FINDING)
        flow = next(e for e in evidence if e.evidence_type is EvidenceType.DATA_FLOW)
        reach = next(e for e in evidence if e.evidence_type is EvidenceType.REACHABILITY)

        result = run_slice(
            question="Are there command injection vulnerabilities?",
            objective="find_command_injection",
            evidence=evidence,
            hypothesis_class="cwe:78",
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "User-controlled input reaches a shell command.",
                        "hypothesis_class": "cwe:78",
                        "cited_evidence": [sink.evidence_id, flow.evidence_id],
                        "missing_evidence": [],
                    }
                ]
            ),
            verification=VerificationResponse(
                candidates=[
                    {  # type: ignore[list-item]
                        "hypothesis_statement": "User-controlled input reaches a shell command.",
                        "title": "Command injection in the ping handler",
                        "description": "A request parameter flows into a shell command.",
                        "cited_evidence": [sink.evidence_id, flow.evidence_id, reach.evidence_id],
                    }
                ]
            ),
            review=ReviewResponse(
                verdict="uphold",
                rationale="Unsanitised and reachable.",
                cited_evidence=[flow.evidence_id],
            ),
        )

        markdown = result.report.markdown
        assert "## Findings" in markdown
        assert "Command injection in the ping handler" in markdown
        assert "Confidence:" in markdown
        assert "capped by completeness" in markdown
        assert "## Reproducibility" in markdown
        assert "semgrep" in markdown

    def test_the_report_states_its_own_limits(self) -> None:
        evidence = source_evidence(vulnerable=True)
        result = run_slice(
            question="Are there vulnerabilities?",
            objective="find_vulnerabilities",
            evidence=evidence,
            hypothesis_class="cwe:78",
            discovery=DiscoveryResponse(hypotheses=[]),
            verification=VerificationResponse(),
            review=ReviewResponse(verdict="uphold", rationale="n/a"),
        )
        markdown = result.report.markdown
        assert "## Limitations" in markdown
        assert "not a statement that no other weakness exists" in markdown


class TestTheModelCannotDecideTheOutcome:
    def test_an_uncited_hypothesis_is_dropped(self) -> None:
        """A hypothesis citing nothing was invented rather than inferred."""
        evidence = source_evidence(vulnerable=True)
        result = run_slice(
            question="Are there command injection vulnerabilities?",
            objective="find_command_injection",
            evidence=evidence,
            hypothesis_class="cwe:78",
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "I feel certain there is a backdoor.",
                        "hypothesis_class": "cwe:78",
                        "cited_evidence": [],
                        "missing_evidence": [],
                    }
                ]
            ),
            verification=VerificationResponse(),
            review=ReviewResponse(verdict="uphold", rationale="n/a"),
        )
        assert result.findings == []

    def test_an_invented_evidence_id_is_dropped(self) -> None:
        evidence = source_evidence(vulnerable=True)
        result = run_slice(
            question="Are there command injection vulnerabilities?",
            objective="find_command_injection",
            evidence=evidence,
            hypothesis_class="cwe:78",
            discovery=DiscoveryResponse(
                hypotheses=[
                    {  # type: ignore[list-item]
                        "statement": "There is a vulnerability.",
                        "hypothesis_class": "cwe:78",
                        "cited_evidence": ["ev-does-not-exist"],
                        "missing_evidence": [],
                    }
                ]
            ),
            verification=VerificationResponse(),
            review=ReviewResponse(verdict="uphold", rationale="n/a"),
        )
        assert result.findings == []
