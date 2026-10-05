"""Turning taint analysis into evidence.

Two evidence types come out of one analysis, and keeping them separate
matters: a data-flow observation says input reaches a sink, a reachability
observation says the code runs at all. The validation sets demand both,
because either alone supports a conclusion the other refutes - a flow in
dead code, or reachable code that handles its input correctly.

Reachability is emitted for the negative case too. "No path reaches this"
is an established result that justifies UNREACHABLE, and it is only
available because the analyser looked.
"""

from __future__ import annotations

from collections.abc import Sequence

from cyberre.adapters.dataflow.python_taint import (
    ANALYSER_VERSION,
    TOOL_NAME,
    AnalysisReport,
    ModuleAnalysis,
    reachable_functions,
)
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.location import SourceLocation
from cyberre.core.models.observation import DataFlowPath, ReachabilityObservation
from cyberre.core.models.provenance import Provenance, ToolProvenance

#: How much to trust this analyser. Middling on purpose. It is syntactic,
#: intraprocedural with one level of propagation, and blind to aliasing
#: and dynamic dispatch - so it narrows an investigation rather than
#: settling one, and the confidence engine should treat it that way.
FLOW_RELIABILITY = 0.65

#: Reachability is scored lower still. Matching on function name
#: over-approximates, and a reachability claim carries more weight in the
#: requirement sets than a flow does, so it should earn less of it.
REACHABILITY_RELIABILITY = 0.6


def build_provenance(*, artefact_sha256: str, raw_output_ref: str | None = None) -> Provenance:
    return Provenance(
        tool=ToolProvenance(
            tool=TOOL_NAME,
            tool_version=ANALYSER_VERSION,
            # The source and sink tables are the ruleset. Recording their
            # size means a finding can be re-examined when they grow.
            ruleset_version=f"tables@{ANALYSER_VERSION}",
        ),
        artefact_sha256=artefact_sha256,
        raw_output_ref=raw_output_ref,
    )


def _evidence(
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    evidence_type: EvidenceType,
    observation: DataFlowPath | ReachabilityObservation,
    location: SourceLocation,
    provenance: Provenance,
    reliability: float,
) -> Evidence:
    return Evidence(
        investigation_id=investigation_id,
        artefact_id=artefact_id,
        artefact_sha256=artefact_sha256,
        evidence_type=evidence_type,
        observation=observation,
        location=location,
        provenance=provenance,
        independence_key=derive_independence_key(
            TOOL_NAME, artefact_sha256, str(location), observation.kind
        ),
        source_reliability=reliability,
    )


def module_evidence(
    module: ModuleAnalysis,
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    provenance: Provenance,
) -> list[Evidence]:
    """Evidence from one analysed file."""
    if module.parse_error is not None:
        return []

    entry_points = [name for name, facts in module.functions.items() if facts.is_entry]
    reachable = reachable_functions(module)
    evidence: list[Evidence] = []
    seen_reachability: set[str] = set()

    for flow in module.flows:
        location = SourceLocation(path=module.path, start_line=flow.line, symbol=flow.function)
        evidence.append(
            _evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=EvidenceType.DATA_FLOW,
                observation=DataFlowPath(
                    source=flow.source,
                    sink=flow.sink,
                    steps=flow.steps,
                    # Recorded whether or not they make the flow safe.
                    # Which sanitiser was used is what lets a reviewer
                    # judge whether it was the right one.
                    sanitizers=flow.sanitisers,
                    excerpt=flow.excerpt,
                ),
                location=location,
                provenance=provenance,
                reliability=FLOW_RELIABILITY,
            )
        )

        if flow.function in seen_reachability:
            continue
        seen_reachability.add(flow.function)

        if not entry_points:
            # No entry point was identified in this module, so there is
            # nothing to be reachable *from*. Emitting reachable=False
            # here would turn "we could not look" into positive evidence
            # that the code is dead - which is the strongest negative
            # claim the system can make, and it would be unfounded.
            #
            # Emitting nothing is correct: the reachability requirement
            # stays unsatisfied and the outcome is NOT_ENOUGH_EVIDENCE
            # rather than UNREACHABLE.
            continue

        is_reachable = flow.function in reachable
        entry = entry_points[0]
        evidence.append(
            _evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=EvidenceType.REACHABILITY,
                observation=ReachabilityObservation(
                    # The sink name, because that is what the requirement
                    # asks about - "is the dangerous operation reachable",
                    # not "is this function reachable".
                    target=flow.sink,
                    entry_point=entry if is_reachable else None,
                    reachable=is_reachable,
                    path=(entry, flow.function) if is_reachable else (),
                ),
                location=SourceLocation(
                    path=module.path, start_line=flow.line, symbol=flow.function
                ),
                provenance=provenance,
                reliability=REACHABILITY_RELIABILITY,
            )
        )

    return evidence


def report_evidence(
    report: AnalysisReport,
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
) -> Sequence[Evidence]:
    """Evidence from a whole tree."""
    provenance = build_provenance(artefact_sha256=artefact_sha256)
    evidence: list[Evidence] = []
    for module in report.modules:
        evidence.extend(
            module_evidence(
                module,
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                provenance=provenance,
            )
        )
    return evidence
