"""Running the pipeline over the corpus.

What is measured is the deterministic chain:

    source -> taint analysis -> evidence -> validation -> confidence

The language model is not in it. That is deliberate rather than a
convenience: the model proposes wording for a hypothesis, and nothing it
says decides an outcome (ADR-002, ADR-009). Benchmarking with a model in
the loop would measure its phrasing and cost money to learn nothing, and
it would make the numbers irreproducible.

So the harness synthesises the hypothesis the model would have worded,
directly from the evidence, and lets validation do what it always does.
A case is "reported vulnerable" only if validation returns VALIDATED -
the same bar a real finding has to clear.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from cyberre.adapters.dataflow.evidence import build_provenance, module_evidence
from cyberre.adapters.dataflow.python_taint import SINKS, analyse_source, propagate
from cyberre.core.evidence.builder import build_graph
from cyberre.core.findings.confidence import ConfidenceConfig, ConfidenceEngine
from cyberre.core.findings.requirements import RequirementRegistry
from cyberre.core.findings.validation import ValidationEngine
from cyberre.core.models.enums import EvidenceType, FindingStatus, HypothesisStatus
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass
from cyberre.core.models.observation import DataFlowPath
from cyberre.core.trust.levels import TrustLevel
from cyberre.evaluation.corpus import Case, Corpus, Split
from cyberre.evaluation.metrics import BenchmarkResult, Outcome, evaluate

#: Which requirement set answers which sink category. The analyser speaks
#: in categories, the registry in CWE classes, and this is the join.
CATEGORY_TO_CLASS: dict[str, str] = {
    "command": "cwe:78",
    "sql": "cwe:89",
    "deserialise": "cwe:502",
    "code": "cwe:94",
    "path": "cwe:22",
}

INVESTIGATION_ID = "inv-benchmark"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def analyse_case(case: Case) -> tuple[Sequence[Evidence], str]:
    """Run the real analyser over one case and return its evidence."""
    source = case.path.read_text(encoding="utf-8")
    sha256 = _digest(source)
    analysis = analyse_source(source, path=str(case.path))
    propagate(analysis)
    evidence = module_evidence(
        analysis,
        investigation_id=INVESTIGATION_ID,
        artefact_id=case.case_id,
        artefact_sha256=sha256,
        provenance=build_provenance(artefact_sha256=sha256),
    )
    return evidence, sha256


def _sink_category(sink: str) -> str:
    """Which weakness class a sink belongs to.

    The observation records the sink by name, not by category, because a
    category is an interpretation and an observation should not carry
    one. The join happens here, against the analyser's own table, so the
    two cannot drift.
    """
    if sink in SINKS:
        return SINKS[sink]
    # A dotted sink may have been recorded with its receiver, e.g.
    # "db.execute" against a table entry of the same shape; fall back to
    # matching on the final attribute.
    tail = sink.rsplit(".", 1)[-1]
    for name, category in SINKS.items():
        if name.rsplit(".", 1)[-1] == tail:
            return category
    return "unknown"


def _parse_class(value: str) -> HypothesisClass:
    taxonomy, identifier = value.split(":", 1)
    return HypothesisClass(taxonomy=taxonomy, identifier=identifier)


def _hypotheses_from(evidence: Sequence[Evidence], case: Case) -> list[Hypothesis]:
    """The hypotheses a reasoner would raise, derived deterministically.

    One per distinct (sink category, sink) pair with a flow behind it.
    Where no flow was found, no hypothesis is raised - which is the
    correct behaviour and makes the case a true negative only if it
    really is clean.
    """
    seen: set[tuple[str, str]] = set()
    hypotheses: list[Hypothesis] = []

    for item in evidence:
        if item.evidence_type is not EvidenceType.DATA_FLOW:
            continue
        observation = item.observation
        if not isinstance(observation, DataFlowPath):
            continue

        category = _sink_category(observation.sink)
        key = (category, observation.sink)
        if key in seen:
            continue
        seen.add(key)

        hypothesis_class = CATEGORY_TO_CLASS.get(category)
        if hypothesis_class is None:
            continue

        hypotheses.append(
            Hypothesis(
                investigation_id=INVESTIGATION_ID,
                statement=(
                    f"Attacker-controlled input from {observation.source} reaches "
                    f"{observation.sink} in {case.case_id} without sanitisation."
                ),
                hypothesis_class=_parse_class(hypothesis_class),
                status=HypothesisStatus.UNTESTED,
                trust_level=TrustLevel.HYPOTHESIS,
                supporting_evidence=(item.evidence_id,),
                created_by="benchmark-harness",
            )
        )
    return hypotheses


def run_case(
    case: Case,
    *,
    engine: ConfidenceEngine,
    registry: RequirementRegistry | None = None,
    validator: ValidationEngine | None = None,
) -> Outcome:
    """Decide what CyberRE concludes about one case.

    The reported confidence is that of the *strongest validated* finding.
    When nothing validates, the case is reported clean at confidence 0 -
    not at 1.0. An absent finding is not a confident claim of absence,
    and scoring it as one would reward a silent analyser.
    """
    registry = registry if registry is not None else RequirementRegistry()
    validator = validator if validator is not None else ValidationEngine()

    evidence, _ = analyse_case(case)
    if not evidence:
        return Outcome(
            case_id=case.case_id,
            expected_vulnerable=case.vulnerable,
            reported_vulnerable=False,
            confidence=0.0,
            note="no evidence produced",
        )

    graph = build_graph(evidence)
    by_id = {item.evidence_id: item for item in evidence}

    best = 0.0
    validated = False
    notes: list[str] = []

    for hypothesis in _hypotheses_from(evidence, case):
        if not registry.covers(str(hypothesis.hypothesis_class)):
            notes.append(f"no requirement set for {hypothesis.hypothesis_class}")
            continue

        outcome = validator.validate(
            hypothesis,
            registry.for_class(str(hypothesis.hypothesis_class)),
            evidence=list(evidence),
            graph=graph,
        )
        breakdown = engine.score(outcome, evidence=by_id)

        if outcome.status is FindingStatus.VALIDATED:
            validated = True
            best = max(best, breakdown.final_score)
        else:
            notes.append(f"{hypothesis.hypothesis_class}: {outcome.status.value}")

    return Outcome(
        case_id=case.case_id,
        expected_vulnerable=case.vulnerable,
        reported_vulnerable=validated,
        confidence=round(best, 6),
        note="; ".join(notes[:3]),
    )


def run_benchmark(
    corpus: Corpus,
    *,
    config: ConfidenceConfig | None = None,
    split: Split | None = None,
    label: str = "benchmark",
) -> BenchmarkResult:
    """Run every case in `corpus` (or one split of it) and measure."""
    engine = ConfidenceEngine(config)
    registry = RequirementRegistry()
    validator = ValidationEngine()

    cases = corpus.cases if split is None else corpus.split(split)
    outcomes = [
        run_case(case, engine=engine, registry=registry, validator=validator) for case in cases
    ]
    return evaluate(label, outcomes)
