"""The structured knowledge record.

Knowledge-derived evidence is held to the same standard as tool-derived
evidence (ADR-017): every record carries a version, a source reference, a
confidence in the claim itself, and the conditions under which it applies.

Without applicability conditions a knowledge base lies by omission. "LoadLibrary
indicates dynamic resolution" is true on Windows and meaningless on Linux, and
a lookup that cannot express that will eventually be applied to the wrong
binary.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr


class KnowledgeDomain(StrEnum):
    """Which body of knowledge a record belongs to.

    Separate domains rather than one pool, because they answer different
    questions and carry different weight. A compiler idiom is a reason to
    *discount* a finding; an API danger class is a reason to look closer.
    """

    FORMATS = "formats"
    ARCH = "arch"
    COMPILERS = "compilers"
    APIS = "apis"
    BEHAVIOURS = "behaviours"
    ANTIANALYSIS = "antianalysis"
    PACKING = "packing"


class DangerClass(StrEnum):
    """What an API is useful for, from an attacker's point of view.

    Not a severity. `injection_primitive` says the call is a building block
    of process injection, not that injection is happening - that requires the
    sequence and a reachable path (section 8 of the architecture).
    """

    BENIGN = "benign"
    RECONNAISSANCE = "reconnaissance"
    INJECTION_PRIMITIVE = "injection_primitive"
    PERSISTENCE_PRIMITIVE = "persistence_primitive"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANTI_ANALYSIS = "anti_analysis"
    DYNAMIC_RESOLUTION = "dynamic_resolution"
    EXECUTION = "execution"
    NETWORK = "network"
    CRYPTO = "crypto"
    FILESYSTEM = "filesystem"


class Applicability(DomainModel):
    """When a record applies.

    Empty fields mean "no constraint". A record that applies everywhere is
    stating that deliberately rather than by omission.
    """

    os: frozenset[str] = frozenset()
    architectures: frozenset[str] = frozenset()
    formats: frozenset[str] = frozenset()
    min_version: str | None = None

    def matches(
        self,
        *,
        os_name: str | None = None,
        architecture: str | None = None,
        binary_format: str | None = None,
    ) -> bool:
        """Whether this record applies to the thing being analysed.

        Unknown context does not disqualify a record: if we do not know the
        OS, an OS-constrained record still applies, because refusing to apply
        knowledge for lack of context would silently lose most of it. The
        uncertainty belongs in confidence, not in a filter.
        """
        if os_name is not None and self.os and os_name.lower() not in self.os:
            return False
        if (
            architecture is not None
            and self.architectures
            and architecture.lower() not in self.architectures
        ):
            return False
        return not (
            binary_format is not None and self.formats and binary_format.lower() not in self.formats
        )


class KnowledgeEntry(DomainModel):
    """One fact, with everything needed to re-examine it later."""

    id: NonEmptyStr
    """Namespaced and stable, e.g. ``win.api.VirtualAllocEx``."""

    version: int = Field(ge=1)
    """Bumped when the claim changes. A finding that leaned on version 1 of a
    record can be re-examined when version 2 says something different."""

    domain: KnowledgeDomain
    statement: NonEmptyStr
    """What is being claimed, in a sentence. Rendered into reports, so it is
    written for a reader rather than as a lookup key."""

    source_ref: NonEmptyStr
    """Where the claim comes from. A knowledge base without citations is a
    set of opinions with extra steps."""

    confidence: float = Field(ge=0.0, le=1.0)
    """Confidence in the claim itself, independent of any investigation.

    A documented API contract is near certain; a packer signature inferred
    from samples is not, and the difference must survive into the finding.
    """

    applicability: Applicability = Applicability()

    # Domain-specific fields. Optional rather than subclassed: the records
    # are data, and a reader comparing two entries should not have to track
    # which schema each one follows.
    aliases: tuple[str, ...] = ()
    category: str | None = None
    danger_class: DangerClass | None = None
    companions: tuple[str, ...] = ()
    """Calls that, together with this one, form a recognised sequence.

    The mechanism that keeps a single scary import from becoming a finding:
    the companions are what validation looks for.
    """

    attack: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    indicators: tuple[str, ...] = ()
    """Observable signs of this behaviour or technique."""

    benign_explanation: str | None = None
    """The innocent reading, where there is a common one.

    Recorded so the adversarial reviewer has the counter-argument to hand
    rather than having to invent it. Most uses of most dangerous APIs are
    legitimate, and a knowledge base that does not say so trains the system
    toward false positives.
    """

    @model_validator(mode="after")
    def _high_confidence_claims_need_a_real_citation(self) -> KnowledgeEntry:
        """A near-certain claim citing nothing specific is not near-certain."""
        if self.confidence >= 0.9 and len(self.source_ref) < 8:
            raise ValueError(
                f"record '{self.id}' claims confidence {self.confidence} with a "
                f"citation of '{self.source_ref}'; high confidence requires a "
                f"source a reader can check"
            )
        return self
