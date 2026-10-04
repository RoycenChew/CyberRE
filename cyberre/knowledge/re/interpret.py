"""Deterministic interpretation of binary evidence.

Applies the knowledge tables to observations and produces interpretations.
No model is involved: "VirtualAllocEx is an injection primitive" is a table
lookup, and asking a model to recall it would be slower, costlier and less
reproducible for a worse answer.

The functions here are deliberately conservative about what they claim. A
behaviour interpretation reports which companion calls are present and which
are missing; it never asserts the behaviour. That assertion requires a
reachable path connecting the sequence, which validation establishes from the
evidence graph.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.interpretation import Interpretation
from cyberre.knowledge.re.schema import DangerClass, KnowledgeDomain, KnowledgeEntry
from cyberre.knowledge.re.source import StructuredKnowledgeSource

PRODUCER = "knowledge.re.interpreter"

#: Danger classes worth raising an interpretation for. BENIGN and the purely
#: descriptive classes are looked up but not surfaced: an interpretation per
#: import would bury the few that matter.
NOTEWORTHY = frozenset(
    {
        DangerClass.INJECTION_PRIMITIVE,
        DangerClass.PERSISTENCE_PRIMITIVE,
        DangerClass.CREDENTIAL_ACCESS,
        DangerClass.PRIVILEGE_ESCALATION,
        DangerClass.ANTI_ANALYSIS,
        DangerClass.DYNAMIC_RESOLUTION,
    }
)

#: Which hypothesis class a danger class would become, if the rest of the
#: evidence supported it.
HYPOTHESIS_FOR = {
    DangerClass.INJECTION_PRIMITIVE: "behaviour:process_injection",
    DangerClass.PERSISTENCE_PRIMITIVE: "behaviour:persistence",
    DangerClass.CREDENTIAL_ACCESS: "behaviour:credential_access",
    DangerClass.PRIVILEGE_ESCALATION: "behaviour:privilege_escalation",
    DangerClass.ANTI_ANALYSIS: "behaviour:anti_analysis",
    DangerClass.DYNAMIC_RESOLUTION: "behaviour:dynamic_resolution",
}


def _imported_symbols(evidence: Iterable[Evidence]) -> dict[str, Evidence]:
    """Imported symbol name to the evidence that observed it."""
    found: dict[str, Evidence] = {}
    for item in evidence:
        if item.evidence_type is EvidenceType.IMPORT:
            symbol = getattr(item.observation, "symbol", None)
            if symbol:
                found.setdefault(str(symbol), item)
    return found


def interpret_imports(
    evidence: Sequence[Evidence],
    knowledge: StructuredKnowledgeSource,
    *,
    investigation_id: str,
    os_name: str | None = None,
    architecture: str | None = None,
) -> list[Interpretation]:
    """One interpretation per noteworthy imported API.

    Each carries the benign explanation from the knowledge table, so the
    counter-argument travels with the claim rather than being left for the
    reviewer to remember.
    """
    interpretations: list[Interpretation] = []

    for symbol, item in sorted(_imported_symbols(evidence).items()):
        entry = knowledge.entry(symbol)
        if entry is None or entry.danger_class not in NOTEWORTHY:
            continue
        if not entry.applicability.matches(os_name=os_name, architecture=architecture):
            continue

        assert entry.danger_class is not None  # narrowed by NOTEWORTHY
        interpretations.append(
            Interpretation(
                investigation_id=investigation_id,
                statement=(
                    f"{symbol} is associated with "
                    f"{entry.danger_class.value.replace('_', ' ')}: {entry.statement}"
                ),
                cites_evidence=(item.evidence_id,),
                cites_knowledge=(f"{entry.id}@{entry.version}",),
                suggests_hypothesis_class=HYPOTHESIS_FOR.get(entry.danger_class),
                counter_explanation=entry.benign_explanation,
                # Importing a symbol says nothing about whether it is called.
                missing_for_hypothesis=("the call is reached from an entry point",),
                knowledge_confidence=entry.confidence,
                produced_by=PRODUCER,
            )
        )

    return interpretations


def _behaviour_entries(knowledge: StructuredKnowledgeSource) -> Sequence[KnowledgeEntry]:
    return [entry for entry in knowledge.in_domain(KnowledgeDomain.BEHAVIOURS) if entry.companions]


def interpret_behaviours(
    evidence: Sequence[Evidence],
    knowledge: StructuredKnowledgeSource,
    *,
    investigation_id: str,
    os_name: str | None = None,
    minimum_present: int = 2,
) -> list[Interpretation]:
    """Candidate behaviours, from which companion calls co-occur.

    Reports what is present and what is absent. It does not assert the
    behaviour even when every companion is imported, because imports are not
    calls and calls are not a reachable path - that is validation's job
    (architecture section 8).

    `minimum_present` keeps a single shared primitive from proposing every
    behaviour that happens to mention it.
    """
    symbols = _imported_symbols(evidence)
    if not symbols:
        return []

    interpretations: list[Interpretation] = []

    for entry in _behaviour_entries(knowledge):
        if not entry.applicability.matches(os_name=os_name):
            continue

        present = [c for c in entry.companions if c in symbols]
        missing = [c for c in entry.companions if c not in symbols]
        if len(present) < minimum_present:
            continue

        cited = tuple(symbols[name].evidence_id for name in present)
        completeness = f"{len(present)} of {len(entry.companions)}"

        # The variant, not just the category. Several techniques share a
        # category - remote-thread and APC injection are both
        # process_injection - and two interpretations reading "N of M calls
        # characteristic of process_injection" would be indistinguishable in
        # a report while meaning different things.
        technique = _leaf(entry.id).replace("_", " ")

        interpretations.append(
            Interpretation(
                investigation_id=investigation_id,
                statement=(
                    f"{completeness} calls characteristic of {technique} "
                    f"({entry.category or entry.id}) are imported "
                    f"({', '.join(present)}). {entry.statement}"
                ),
                cites_evidence=cited,
                cites_knowledge=(f"{entry.id}@{entry.version}",),
                suggests_hypothesis_class=(
                    f"behaviour:{entry.category}" if entry.category else None
                ),
                counter_explanation=entry.benign_explanation,
                missing_for_hypothesis=(
                    *(f"{name} is imported" for name in missing),
                    "the calls are reachable from a common entry point",
                ),
                knowledge_confidence=entry.confidence,
                produced_by=PRODUCER,
            )
        )

    return interpretations


def interpret_toolchain(
    evidence: Sequence[Evidence],
    knowledge: StructuredKnowledgeSource,
    *,
    investigation_id: str,
) -> list[Interpretation]:
    """Recognise the toolchain, to discount findings that are really runtime.

    This produces no hypothesis. Its value is the opposite: a Go binary with
    an empty import table is expected rather than evidence of API hashing,
    and recording that stops a later stage from drawing the wrong conclusion
    from it.
    """
    metadata = [e for e in evidence if e.evidence_type is EvidenceType.BINARY_METADATA]
    if not metadata:
        return []

    compiler = getattr(metadata[0].observation, "compiler", None)
    if not compiler:
        return []

    needle = str(compiler).lower()
    for entry in knowledge.in_domain(KnowledgeDomain.COMPILERS):
        if _leaf(entry.id) in needle or needle in _leaf(entry.id):
            return [
                Interpretation(
                    investigation_id=investigation_id,
                    statement=f"The binary appears to be {entry.statement}",
                    cites_evidence=(metadata[0].evidence_id,),
                    cites_knowledge=(f"{entry.id}@{entry.version}",),
                    suggests_hypothesis_class=None,
                    counter_explanation=entry.benign_explanation,
                    knowledge_confidence=entry.confidence,
                    produced_by=PRODUCER,
                )
            ]
    return []


def interpret(
    evidence: Sequence[Evidence],
    knowledge: StructuredKnowledgeSource,
    *,
    investigation_id: str,
    os_name: str | None = None,
    architecture: str | None = None,
) -> list[Interpretation]:
    """Every deterministic interpretation available for this evidence.

    Ordering is stable, so an investigation replays identically.
    """
    return [
        *interpret_toolchain(evidence, knowledge, investigation_id=investigation_id),
        *interpret_behaviours(
            evidence, knowledge, investigation_id=investigation_id, os_name=os_name
        ),
        *interpret_imports(
            evidence,
            knowledge,
            investigation_id=investigation_id,
            os_name=os_name,
            architecture=architecture,
        ),
    ]


def _leaf(record_id: str) -> str:
    return record_id.rsplit(".", 1)[-1]
