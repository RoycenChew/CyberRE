"""What was observed, as structured data rather than a sentence.

Free-text observations are the slow leak through which an evidence system
becomes a pile of model-written prose. Every observation here is typed, and
the one that carries free text - :class:`AgentClaim` - is marked unverified
and is excluded from satisfying validation requirements by its trust level.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr


class BinaryMetadata(DomainModel):
    kind: Literal["binary_metadata"] = "binary_metadata"
    format: NonEmptyStr
    architecture: NonEmptyStr
    bits: int = Field(ge=8, le=128)
    endianness: Literal["little", "big"]
    entry_point: int | None = Field(default=None, ge=0)
    compiler: str | None = None
    """Best-effort compiler or runtime fingerprint, e.g. ``msvc``, ``go``."""


class SectionObservation(DomainModel):
    kind: Literal["section"] = "section"
    name: NonEmptyStr
    virtual_size: int = Field(ge=0)
    raw_size: int = Field(ge=0)
    entropy: float | None = Field(default=None, ge=0.0, le=8.0)
    executable: bool = False
    writable: bool = False


class ImportObservation(DomainModel):
    kind: Literal["import"] = "import"
    library: str | None = None
    symbol: NonEmptyStr
    ordinal: int | None = Field(default=None, ge=0)


class StringMatch(DomainModel):
    kind: Literal["string_match"] = "string_match"
    value: NonEmptyStr
    encoding: Literal["ascii", "utf-8", "utf-16"] = "ascii"
    is_untrusted_content: bool = True
    """Strings come from the artefact, so they are untrusted by default.

    The compiler uses this to decide what must be fenced before it can appear
    anywhere near a model prompt.
    """


class FunctionObservation(DomainModel):
    kind: Literal["function"] = "function"
    name: NonEmptyStr
    size: int | None = Field(default=None, ge=0)
    is_thunk: bool = False
    is_library: bool = False
    """Recognised library code. The reviewer uses this to argue a finding is
    in vendored or runtime code rather than in the analysed program."""


class CallEdge(DomainModel):
    kind: Literal["call_edge"] = "call_edge"
    caller: NonEmptyStr
    callee: NonEmptyStr
    call_site: int | None = Field(default=None, ge=0)


class DataFlowPath(DomainModel):
    kind: Literal["data_flow"] = "data_flow"
    source: NonEmptyStr
    sink: NonEmptyStr
    steps: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    """Sanitisers observed on the path.

    Present and non-empty is a strong argument *against* a finding, which is
    why it is recorded here rather than inferred later.
    """

    excerpt: str | None = None
    """The sink line as written.

    An analyser's summary of a flow is a claim about code; the line itself
    is the code. A reviewer asked to judge whether a value is interpolated
    into a command or passed as an argv element cannot do it from a label,
    and said so.

    This is artefact content and is fenced as untrusted wherever it is
    rendered.
    """

    excerpt_is_untrusted: Literal[True] = True


class ReachabilityObservation(DomainModel):
    kind: Literal["reachability"] = "reachability"
    target: NonEmptyStr
    entry_point: str | None = None
    reachable: bool
    path: tuple[str, ...] = ()
    """``reachable=False`` is evidence, not an absence of evidence - it is what
    justifies the ``UNREACHABLE`` outcome."""


class ScannerFinding(DomainModel):
    kind: Literal["scanner_finding"] = "scanner_finding"
    rule_id: NonEmptyStr
    message: NonEmptyStr
    severity_reported: str | None = None
    """What the scanner called it. Recorded, never adopted: CyberRE derives its
    own severity from validated evidence."""

    cwe: tuple[str, ...] = ()


class SecretMatch(DomainModel):
    kind: Literal["secret_match"] = "secret_match"
    detector: NonEmptyStr
    redacted_preview: NonEmptyStr
    """A redacted fragment only. The matched secret is never stored in evidence,
    because evidence is durable, queryable and rendered into reports."""

    entropy: float | None = Field(default=None, ge=0.0)
    verified_active: bool | None = None


class DependencyObservation(DomainModel):
    kind: Literal["dependency"] = "dependency"
    ecosystem: NonEmptyStr
    name: NonEmptyStr
    version: str | None = None
    direct: bool = True
    """A name match alone never establishes a vulnerability; version and
    configuration are separate requirements (ADR-013 rationale)."""


class KnowledgeRecord(DomainModel):
    """A fact retrieved from the structured knowledge layer.

    Carries its own provenance fields so knowledge-derived evidence is held to
    the same standard as tool-derived evidence (ADR-017).
    """

    kind: Literal["knowledge_record"] = "knowledge_record"
    record_id: NonEmptyStr
    record_version: int = Field(ge=1)
    statement: NonEmptyStr
    source_ref: NonEmptyStr
    source_confidence: float = Field(ge=0.0, le=1.0)
    applicability: dict[str, str] = Field(default_factory=dict)


class SandboxEvent(DomainModel):
    kind: Literal["sandbox_event"] = "sandbox_event"
    event_type: NonEmptyStr
    detail: NonEmptyStr
    sequence: int = Field(ge=0)


class SuspectedInjection(DomainModel):
    """Injection-shaped text found inside an artefact.

    Recorded as a security observation about the artefact. Something trying to
    instruct the analyst's tooling is itself worth reporting.
    """

    kind: Literal["suspected_injection"] = "suspected_injection"
    pattern: NonEmptyStr
    excerpt: NonEmptyStr
    is_untrusted_content: Literal[True] = True


class AgentClaim(DomainModel):
    """An assertion by an external coding agent.

    The only observation carrying free text. It is always unverified, and its
    trust level (``AGENT_CLAIM``) excludes it from satisfying any validation
    requirement - invariant 2, enforced in the lattice rather than here.
    """

    kind: Literal["agent_claim"] = "agent_claim"
    agent: NonEmptyStr
    statement: NonEmptyStr
    is_unverified: Literal[True] = True


Observation = Annotated[
    BinaryMetadata
    | SectionObservation
    | ImportObservation
    | StringMatch
    | FunctionObservation
    | CallEdge
    | DataFlowPath
    | ReachabilityObservation
    | ScannerFinding
    | SecretMatch
    | DependencyObservation
    | KnowledgeRecord
    | SandboxEvent
    | SuspectedInjection
    | AgentClaim,
    Field(discriminator="kind"),
]
