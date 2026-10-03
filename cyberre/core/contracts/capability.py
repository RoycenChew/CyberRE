"""The capability contract: how a security tool is exposed to the planner.

Capabilities are typed and narrow (``decompile_function(artefact, function)``)
rather than general (``run_shell(command)``). A general shell tool would make
the policy engine unenforceable, because nothing could be said in advance about
what a call would do.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from cyberre.core.models.artefact import Artefact
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import ArtefactType, EvidenceType, RiskLevel
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.provenance import ToolProvenance


class CapabilityCost(DomainModel):
    """What running this is expected to cost."""

    seconds: float = Field(ge=0.0)
    model_tokens: int = Field(default=0, ge=0)


class CapabilitySpec(DomainModel):
    """Everything the planner knows about a capability.

    The planner sees only this, never the adapter, so that ranking an action
    never depends on implementation detail.
    """

    capability_id: NonEmptyStr
    """Dotted and stable, e.g. ``ghidra.decompile_function``."""

    name: NonEmptyStr
    description: NonEmptyStr

    artefact_types: frozenset[ArtefactType]
    produces: frozenset[EvidenceType]
    """Which evidence types this can yield. The planner uses it to ask "would
    running this move me toward an unsatisfied requirement?" rather than
    "which tools exist?"."""

    cost: CapabilityCost
    reliability: float = Field(ge=0.0, le=1.0)
    """How much the resulting evidence should be trusted. A property of the
    tool, measured against the benchmark, not a per-run judgement."""

    risk_level: RiskLevel
    prerequisites: tuple[str, ...] = ()
    """Capability IDs that must have produced evidence first.

    Checked against the evidence graph, so the planner cannot ask to decompile
    a function in a binary that was never analysed.
    """

    information_gain_prior: float = Field(default=0.5, ge=0.0, le=1.0)
    timeout_seconds: int = Field(default=300, ge=1)
    requires_sandbox: bool = False
    requires_network: bool = False


class CapabilityResult(DomainModel):
    """What a capability produced.

    Evidence and raw output are separate: the evidence is the structured
    summary that enters the graph, the reference points at the unmodified
    output kept for audit.
    """

    capability_id: NonEmptyStr
    evidence: tuple[Evidence, ...]
    raw_output_ref: str | None = None
    tool_provenance: ToolProvenance
    partial: bool = False
    """True when the tool succeeded but could not analyse everything.

    Distinct from failure, and distinct from success - a partial result that
    reports as complete silently understates what was missed.
    """


@runtime_checkable
class Capability[InputT: BaseModel, OutputT: BaseModel](Protocol):
    """A single typed security operation."""

    @property
    def spec(self) -> CapabilitySpec: ...

    def execute(self, payload: InputT, *, artefact: Artefact) -> CapabilityResult:
        """Run the capability and return evidence.

        An implementation must not raise for an expected analytical failure -
        an unsupported architecture, a corrupt file - it returns a result the
        caller converts into a ``ToolFailure``. Exceptions are for programming
        errors.
        """
        ...


@runtime_checkable
class CapabilityRegistry(Protocol):
    """Lookup over registered capabilities."""

    def get(self, capability_id: str) -> CapabilitySpec: ...

    def all_specs(self) -> Sequence[CapabilitySpec]: ...

    def for_artefact_type(self, artefact_type: ArtefactType) -> Sequence[CapabilitySpec]: ...

    def producing(self, evidence_type: EvidenceType) -> Sequence[CapabilitySpec]: ...
