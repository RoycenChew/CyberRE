"""Closed vocabularies for the domain.

Every one of these is an enum rather than a string because the alternative -
free text - is how a pipeline quietly accumulates ``"high"``, ``"High"`` and
``"HIGH"`` as three different severities.
"""

from __future__ import annotations

from enum import StrEnum


class ArtefactType(StrEnum):
    """What kind of thing is under analysis."""

    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    SOURCE_TREE = "source_tree"
    SOURCE_FILE = "source_file"
    ARCHIVE = "archive"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    CONFIGURATION = "configuration"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class Depth(StrEnum):
    """How much investigation is justified.

    Escalation is one-way in V1 (FAST -> STANDARD -> DEEP); keeping the loop
    monotonic makes it analysable.
    """

    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"


class RiskLevel(StrEnum):
    """Action risk, governing what may run without a human.

    Levels 0-2 may be automatic subject to policy; level 3 requires approval;
    levels 4-5 are blocked absent an explicit policy.
    """

    L0_READ_ONLY = "l0_read_only"
    L1_LOCAL_STATIC = "l1_local_static"
    L2_SANDBOX = "l2_sandbox"
    L3_NETWORKED_LAB = "l3_networked_lab"
    L4_MODIFYING = "l4_modifying"
    L5_EXTERNAL_TARGET = "l5_external_target"


#: Ordering for comparison. ``StrEnum`` sorts alphabetically, which would put
#: L0 next to L1 but is meaningless in general, so severity of risk is explicit.
RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.L0_READ_ONLY: 0,
    RiskLevel.L1_LOCAL_STATIC: 1,
    RiskLevel.L2_SANDBOX: 2,
    RiskLevel.L3_NETWORKED_LAB: 3,
    RiskLevel.L4_MODIFYING: 4,
    RiskLevel.L5_EXTERNAL_TARGET: 5,
}


class EvidenceType(StrEnum):
    """What an observation is about.

    Used for relevance filtering in the compiler and for requirement matching
    in validation, so it is a closed set rather than a label.
    """

    BINARY_METADATA = "binary_metadata"
    SECTION = "section"
    IMPORT = "import"
    EXPORT = "export"
    SYMBOL = "symbol"
    STRING_MATCH = "string_match"
    FUNCTION = "function"
    DECOMPILATION = "decompilation"
    CALL_EDGE = "call_edge"
    CROSS_REFERENCE = "cross_reference"
    DATA_FLOW = "data_flow"
    REACHABILITY = "reachability"
    SCANNER_FINDING = "scanner_finding"
    SECRET_MATCH = "secret_match"
    DEPENDENCY = "dependency"
    KNOWLEDGE_RECORD = "knowledge_record"
    SANDBOX_EVENT = "sandbox_event"
    AGENT_CLAIM = "agent_claim"
    SUSPECTED_INJECTION = "suspected_injection"
    """Injection-shaped text found in an artefact.

    Recorded as an observation *about* the artefact. That it was found is a
    security signal in its own right, not merely something to filter out.
    """


class HypothesisStatus(StrEnum):
    """Where a hypothesis stands.

    Transitions are driven by the validation engine, not by model assertion.
    """

    UNTESTED = "untested"
    TESTING = "testing"
    SUPPORTED = "supported"
    PROBABLE = "probable"
    REJECTED = "rejected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFIRMED = "confirmed"


class FindingStatus(StrEnum):
    """The outcome of investigating a hypothesis.

    Unlike a severity scale, this set can express *why* the answer is negative.
    An unreachable vulnerability, an inapplicable CVE and a genuinely
    under-investigated case are three different answers, and collapsing them
    into one discards the most actionable part (ADR-013).
    """

    VALIDATED = "validated"
    """Requirements satisfied by independent evidence, reviewer did not reject."""

    UNVALIDATED = "unvalidated"
    """Not yet put through validation. Never reportable as a finding."""

    NOT_ENOUGH_EVIDENCE = "not_enough_evidence"
    """Requirements unmet and no remaining capability would settle it.

    A successful outcome. "We cannot responsibly conclude" is an answer.
    """

    CONTRADICTED = "contradicted"
    """Evidence exists that is inconsistent with the hypothesis."""

    NOT_APPLICABLE = "not_applicable"
    """Real weakness, wrong target - e.g. the version is not in range."""

    UNREACHABLE = "unreachable"
    """The code exists but no path reaches it from an entry point."""

    NEEDS_REVIEW = "needs_review"
    """Automated analysis stopped short; a human should look."""


#: Statuses that may appear in a report as an established finding. Everything
#: else is reported as an outcome, with its reason, and carries no severity.
REPORTABLE_AS_FINDING: frozenset[FindingStatus] = frozenset({FindingStatus.VALIDATED})


class Severity(StrEnum):
    """Impact of a validated finding.

    Optional on a finding, and ``None`` for every non-validated status -
    uncertainty is never expressed as a severity (invariant 10).
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReviewVerdict(StrEnum):
    """What the adversarial reviewer concluded.

    There is deliberately no verdict that strengthens a finding; the reviewer
    can only uphold, weaken, reject or ask for more (invariant 9).
    """

    UPHOLD = "uphold"
    DOWNGRADE = "downgrade"
    REJECT = "reject"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"


class InvestigationStatus(StrEnum):
    """Lifecycle of an investigation."""

    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    PARTIAL = "partial"
    """Completed with known gaps - a tool failed, or the budget ran out.

    Reported as PARTIAL rather than COMPLETE, because pretending otherwise
    misrepresents coverage.
    """

    COMPLETE = "complete"
    BLOCKED = "blocked"
    FAILED = "failed"


class ProfileId(StrEnum):
    """Analysis profiles. Declarative configuration, never agents (ADR-008)."""

    BINARY_RE = "binary_re"
    SOURCE_SECURITY = "source_security"
    DEPENDENCY_SECURITY = "dependency_security"
    MALWARE_ANALYSIS = "malware_analysis"
    VULNERABILITY_RESEARCH = "vulnerability_research"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_INVESTIGATION = "incident_investigation"


class EdgeKind(StrEnum):
    """Relationships in the evidence graph."""

    DERIVED_FROM = "derived_from"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    DEPENDS_ON = "depends_on"
    OBSERVED_IN = "observed_in"
    GENERATED_BY = "generated_by"
    VALIDATED_BY = "validated_by"
    APPLIES_TO = "applies_to"
