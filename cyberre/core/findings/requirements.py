"""Requirement sets: what must be true before a class of claim is a finding.

The bar is set here, in code the whole team can read and argue with, rather
than in a prompt. A model may propose a hypothesis; it may not decide what
would count as proving it.

Every set follows the same shape for a reason. A weakness claim needs a
source of attacker influence, a dangerous sink, the absence of mitigation,
and reachability. Drop any one and the claim is weaker than it sounds:
without reachability it may be dead code, without the sanitiser check it may
already be handled, without the source it may not be attacker-influenced at
all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from cyberre.core.findings.predicates import (
    AnyOf,
    FlowIsUnsanitised,
    HasApiSequence,
    HasDataFlow,
    HasEvidenceOfType,
    HasKnowledgeRecord,
    HasScannerFinding,
    HasVersionedDependency,
    IsReachable,
    Predicate,
    ReachabilityDisproven,
)
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import EvidenceType


class Requirement(DomainModel):
    """One thing that must be established.

    `optional` requirements contribute to completeness but do not block
    validation. Used sparingly - exploitability under a specific
    configuration, for instance, where demanding it would reject every
    genuine finding.
    """

    model_config = DomainModel.model_config | {"arbitrary_types_allowed": True}

    requirement_id: NonEmptyStr
    predicate: Predicate
    optional: bool = False
    weight: float = 1.0

    @property
    def description(self) -> str:
        return self.predicate.description


class RequirementSet(DomainModel):
    """Everything a class of hypothesis must establish."""

    model_config = DomainModel.model_config | {"arbitrary_types_allowed": True}

    set_id: NonEmptyStr
    hypothesis_class: NonEmptyStr
    requirements: tuple[Requirement, ...]
    disproving: tuple[Requirement, ...] = ()
    """Requirements whose satisfaction *refutes* the hypothesis.

    Positive evidence of unreachability belongs here. Without it the only
    possible negative answer is "not enough evidence", which throws away the
    most useful thing an investigation can establish (ADR-013).
    """

    applicability: tuple[Requirement, ...] = ()
    """Preconditions. Unmet, the outcome is NOT_APPLICABLE rather than a
    failure to prove - a real weakness against the wrong target."""

    @property
    def mandatory(self) -> tuple[Requirement, ...]:
        return tuple(r for r in self.requirements if not r.optional)


# --------------------------------------------------------------------------
# Builders. Weakness classes differ in their sinks, not in their shape, so
# the shape lives in one place: changing what "a validated injection" means
# is then one edit rather than five.
# --------------------------------------------------------------------------


def taint_requirement_set(
    *,
    set_id: str,
    hypothesis_class: str,
    cwe_ids: frozenset[str],
    sink_markers: frozenset[str],
    sink_label: str,
) -> RequirementSet:
    """The standard shape for an input-reaches-dangerous-operation weakness."""
    return RequirementSet(
        set_id=set_id,
        hypothesis_class=hypothesis_class,
        requirements=(
            Requirement(
                requirement_id=f"{set_id}.sink",
                predicate=AnyOf(
                    options=(
                        HasScannerFinding(cwe_ids=cwe_ids, label=sink_label),
                        HasDataFlow(sink_markers=sink_markers, label=sink_label),
                    ),
                    label=sink_label,
                ),
            ),
            Requirement(
                requirement_id=f"{set_id}.attacker_controlled_source",
                predicate=HasDataFlow(
                    sink_markers=sink_markers,
                    label="attacker-controlled input reaches the sink",
                ),
            ),
            Requirement(
                requirement_id=f"{set_id}.no_sanitisation",
                predicate=FlowIsUnsanitised(sink_markers=sink_markers),
            ),
            Requirement(
                requirement_id=f"{set_id}.reachable",
                predicate=IsReachable(targets=sink_markers),
            ),
        ),
        disproving=(
            Requirement(
                requirement_id=f"{set_id}.unreachable",
                predicate=ReachabilityDisproven(targets=sink_markers),
            ),
        ),
    )


def behaviour_requirement_set(
    *,
    set_id: str,
    hypothesis_class: str,
    symbols: frozenset[str],
    knowledge_prefix: str,
    label: str,
) -> RequirementSet:
    """The standard shape for a binary behaviour claim.

    The sequence *and* a reachable path. An imported symbol is not a call
    and a call is not a reachable path, which is the distinction that keeps
    a benign allocator from being reported as an injector.
    """
    return RequirementSet(
        set_id=set_id,
        hypothesis_class=hypothesis_class,
        requirements=(
            Requirement(
                requirement_id=f"{set_id}.api_sequence",
                predicate=HasApiSequence(symbols=symbols, label=label),
            ),
            Requirement(
                requirement_id=f"{set_id}.knowledge",
                predicate=HasKnowledgeRecord(
                    record_prefix=knowledge_prefix,
                    label="the technique is documented in the knowledge layer",
                ),
            ),
            Requirement(
                requirement_id=f"{set_id}.reachable",
                predicate=IsReachable(
                    targets=frozenset(s.lower() for s in symbols),
                    label="the sequence is reachable from an entry point",
                ),
            ),
        ),
    )


# --------------------------------------------------------------------------
# The shipped sets.
# --------------------------------------------------------------------------

_SUBPROCESS_SINKS = frozenset({"system", "exec", "popen", "subprocess", "shell", "spawn"})
_SQL_SINKS = frozenset({"execute", "query", "cursor", "raw", "sql"})
_PATH_SINKS = frozenset({"open", "read", "write", "path", "join", "file"})
_DESERIALISE_SINKS = frozenset({"loads", "pickle", "unserialize", "yaml", "marshal"})
_MEMORY_SINKS = frozenset({"strcpy", "memcpy", "sprintf", "gets", "strcat", "alloca"})


def _cve_applicability() -> RequirementSet:
    """CVE applicability.

    Written out rather than generated, because the thing it exists to
    prevent is specific: a package name matching an advisory is trivially
    easy and means almost nothing. Product, a resolved version, and the
    version falling in the affected range are three separate requirements.
    """
    return RequirementSet(
        set_id="req.cve.applicability",
        hypothesis_class="cve:applicability",
        requirements=(
            Requirement(
                requirement_id="req.cve.applicability.product",
                predicate=HasEvidenceOfType(
                    types=frozenset({EvidenceType.DEPENDENCY}),
                    label="the affected product is actually declared",
                ),
            ),
            Requirement(
                requirement_id="req.cve.applicability.resolved_version",
                predicate=HasVersionedDependency(),
            ),
            Requirement(
                requirement_id="req.cve.applicability.advisory",
                predicate=HasKnowledgeRecord(
                    record_prefix="cve.",
                    label="an advisory describing the affected range was retrieved",
                ),
            ),
        ),
        applicability=(
            Requirement(
                requirement_id="req.cve.applicability.version_in_range",
                predicate=HasKnowledgeRecord(
                    record_prefix="cve.range.",
                    label="the resolved version falls in the affected range",
                ),
            ),
        ),
    )


def default_requirement_sets() -> dict[str, RequirementSet]:
    """Every requirement set this version ships."""
    sets: list[RequirementSet] = [
        taint_requirement_set(
            set_id="req.cwe.78",
            hypothesis_class="cwe:78",
            cwe_ids=frozenset({"CWE-78"}),
            sink_markers=_SUBPROCESS_SINKS,
            sink_label="a command-execution sink is present",
        ),
        taint_requirement_set(
            set_id="req.cwe.89",
            hypothesis_class="cwe:89",
            cwe_ids=frozenset({"CWE-89"}),
            sink_markers=_SQL_SINKS,
            sink_label="a SQL query is constructed",
        ),
        taint_requirement_set(
            set_id="req.cwe.22",
            hypothesis_class="cwe:22",
            cwe_ids=frozenset({"CWE-22"}),
            sink_markers=_PATH_SINKS,
            sink_label="a filesystem path is constructed from input",
        ),
        taint_requirement_set(
            set_id="req.cwe.502",
            hypothesis_class="cwe:502",
            cwe_ids=frozenset({"CWE-502"}),
            sink_markers=_DESERIALISE_SINKS,
            sink_label="untrusted data is deserialised",
        ),
        taint_requirement_set(
            set_id="req.cwe.787",
            hypothesis_class="cwe:787",
            cwe_ids=frozenset({"CWE-787", "CWE-120"}),
            sink_markers=_MEMORY_SINKS,
            sink_label="an unbounded memory operation is present",
        ),
        RequirementSet(
            set_id="req.cwe.798",
            hypothesis_class="cwe:798",
            requirements=(
                Requirement(
                    requirement_id="req.cwe.798.secret",
                    predicate=HasEvidenceOfType(
                        types=frozenset({EvidenceType.SECRET_MATCH}),
                        label="a credential-shaped value is embedded in the source",
                    ),
                ),
            ),
        ),
        behaviour_requirement_set(
            set_id="req.behaviour.process_injection",
            hypothesis_class="behaviour:process_injection",
            symbols=frozenset(
                {
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                }
            ),
            knowledge_prefix="behaviour.process_injection",
            label="the full remote-thread injection sequence is present",
        ),
        behaviour_requirement_set(
            set_id="req.behaviour.persistence",
            hypothesis_class="behaviour:persistence",
            symbols=frozenset({"RegCreateKeyExA", "RegSetValueExA"}),
            knowledge_prefix="behaviour.persistence",
            label="a persistence mechanism is written",
        ),
        behaviour_requirement_set(
            set_id="req.behaviour.credential_access",
            hypothesis_class="behaviour:credential_access",
            symbols=frozenset({"CryptUnprotectData"}),
            knowledge_prefix="behaviour.credential_access",
            label="protected credentials are decrypted",
        ),
        behaviour_requirement_set(
            set_id="req.behaviour.dynamic_resolution",
            hypothesis_class="behaviour:dynamic_resolution",
            symbols=frozenset({"LoadLibraryA", "GetProcAddress"}),
            knowledge_prefix="behaviour.dynamic_resolution",
            label="imports are resolved at runtime",
        ),
        RequirementSet(
            set_id="req.behaviour.anti_analysis",
            hypothesis_class="behaviour:anti_analysis",
            requirements=(
                Requirement(
                    requirement_id="req.behaviour.anti_analysis.technique",
                    predicate=HasKnowledgeRecord(
                        record_prefix="antianalysis.",
                        label="a known anti-analysis technique is identified",
                    ),
                ),
                Requirement(
                    requirement_id="req.behaviour.anti_analysis.observed",
                    predicate=HasEvidenceOfType(
                        types=frozenset({EvidenceType.IMPORT, EvidenceType.CALL_EDGE}),
                        label="the technique is observed in the binary",
                    ),
                ),
            ),
        ),
        RequirementSet(
            set_id="req.behaviour.packing",
            hypothesis_class="behaviour:packing",
            requirements=(
                Requirement(
                    requirement_id="req.behaviour.packing.signature",
                    predicate=HasKnowledgeRecord(
                        record_prefix="packing.",
                        label="a packer signature or indicator matches",
                    ),
                ),
                Requirement(
                    requirement_id="req.behaviour.packing.section",
                    predicate=HasEvidenceOfType(
                        types=frozenset({EvidenceType.SECTION}),
                        label="section layout supports the signature",
                    ),
                ),
            ),
        ),
        _cve_applicability(),
    ]
    return {requirement_set.set_id: requirement_set for requirement_set in sets}


class RequirementRegistry:
    """Lookup from requirement-set id and hypothesis class."""

    def __init__(self, sets: Mapping[str, RequirementSet] | None = None) -> None:
        self._by_id = dict(sets) if sets is not None else default_requirement_sets()
        self._by_class: dict[str, RequirementSet] = {}
        for requirement_set in self._by_id.values():
            self._by_class[requirement_set.hypothesis_class] = requirement_set

    def get(self, set_id: str) -> RequirementSet:
        if set_id not in self._by_id:
            raise KeyError(
                f"no requirement set '{set_id}'; a hypothesis class with no "
                f"requirements could never be validated and would hang in "
                f"UNVALIDATED for ever"
            )
        return self._by_id[set_id]

    def for_class(self, hypothesis_class: str) -> RequirementSet:
        if hypothesis_class not in self._by_class:
            raise KeyError(f"no requirement set covers '{hypothesis_class}'")
        return self._by_class[hypothesis_class]

    def covers(self, hypothesis_class: str) -> bool:
        return hypothesis_class in self._by_class

    def all_sets(self) -> Sequence[RequirementSet]:
        return [self._by_id[key] for key in sorted(self._by_id)]

    def __len__(self) -> int:
        return len(self._by_id)
