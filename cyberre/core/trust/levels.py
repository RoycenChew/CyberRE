"""Trust levels and the single chokepoint through which objects are promoted.

The architecture rests on the claim that a model statement cannot become a
security finding. That claim is only worth something if it is mechanical, so
every domain object carries a :class:`TrustLevel` and every promotion between
levels goes through :func:`promote`, which refuses illegal transitions.

See ``docs/TRUST_MODEL.md`` for the prose version and ADR-001 for why this
exists as a lattice rather than as a flag on one evidence type.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Final


class TrustLevel(IntEnum):
    """How much authority an object carries.

    The integer ordering is meaningful for comparison and display, but it does
    *not* define which promotions are legal - :data:`LEGAL_PROMOTIONS` does.
    A higher number is not automatically reachable from a lower one.
    """

    RAW_ARTEFACT = 0
    """Bytes supplied by a user or extracted from a target. Pure data."""

    TOOL_OUTPUT = 1
    """What a capability produced, before normalisation. No provenance yet."""

    AGENT_CLAIM = 2
    """An assertion by a coding agent. Never satisfies a requirement."""

    NORMALIZED_EVIDENCE = 3
    """A structured observation with complete provenance."""

    DERIVED_EVIDENCE = 4
    """Produced by a deterministic transform of other evidence."""

    INTERPRETATION = 5
    """What evidence might mean. Useful, and not a finding."""

    HYPOTHESIS = 6
    """A testable statement about a specific weakness."""

    VALIDATED_FINDING = 7
    """A hypothesis whose evidence requirements were satisfied."""


class Actor(IntEnum):
    """Who or what performed a promotion.

    Recorded because the legality of a promotion depends on it: only the
    validation engine may produce a finding, whatever else is true.
    """

    CAPABILITY = 0
    """A security tool executing under policy."""

    NORMALIZER = 1
    """An adapter converting tool output into evidence."""

    TRANSFORM = 2
    """A deterministic derivation over existing evidence."""

    KNOWLEDGE = 3
    """A structured knowledge lookup."""

    MODEL = 4
    """A language model."""

    VALIDATION_ENGINE = 5
    """The only actor permitted to create a validated finding."""

    CODING_AGENT = 6
    """An external engineering agent (Claude Code, Codex, Pi, ...)."""


#: Legal transitions, as ``(from, to) -> actors permitted to perform it``.
#:
#: Everything absent from this mapping is forbidden. Notably absent, and
#: deliberately so:
#:
#: * ``AGENT_CLAIM -> anything`` - invariant 2. A coding agent saying "this is
#:   command injection" is a lead to investigate, never a step toward a finding.
#: * ``INTERPRETATION -> VALIDATED_FINDING`` - interpretation is where a model
#:   is most useful and least accountable, so it must pass through a hypothesis
#:   and then through validation.
#: * ``TOOL_OUTPUT -> anything but NORMALIZED_EVIDENCE`` - normalisation is
#:   where provenance is attached, and skipping it loses the audit trail
#:   (invariant 6).
#: * ``* -> VALIDATED_FINDING`` by any actor other than the validation engine -
#:   invariants 1 and 8.
LEGAL_PROMOTIONS: Final[dict[tuple[TrustLevel, TrustLevel], frozenset[Actor]]] = {
    (TrustLevel.RAW_ARTEFACT, TrustLevel.TOOL_OUTPUT): frozenset({Actor.CAPABILITY}),
    (TrustLevel.TOOL_OUTPUT, TrustLevel.NORMALIZED_EVIDENCE): frozenset({Actor.NORMALIZER}),
    (TrustLevel.NORMALIZED_EVIDENCE, TrustLevel.DERIVED_EVIDENCE): frozenset({Actor.TRANSFORM}),
    (TrustLevel.DERIVED_EVIDENCE, TrustLevel.DERIVED_EVIDENCE): frozenset({Actor.TRANSFORM}),
    (TrustLevel.NORMALIZED_EVIDENCE, TrustLevel.INTERPRETATION): frozenset(
        {Actor.KNOWLEDGE, Actor.MODEL}
    ),
    (TrustLevel.DERIVED_EVIDENCE, TrustLevel.INTERPRETATION): frozenset(
        {Actor.KNOWLEDGE, Actor.MODEL}
    ),
    (TrustLevel.INTERPRETATION, TrustLevel.HYPOTHESIS): frozenset({Actor.MODEL}),
    (TrustLevel.HYPOTHESIS, TrustLevel.VALIDATED_FINDING): frozenset({Actor.VALIDATION_ENGINE}),
    # A coding agent may record a claim about raw material. That is the whole
    # of its authority, and the claim stays at level 2 (ADR-011).
    (TrustLevel.RAW_ARTEFACT, TrustLevel.AGENT_CLAIM): frozenset({Actor.CODING_AGENT}),
    (TrustLevel.TOOL_OUTPUT, TrustLevel.AGENT_CLAIM): frozenset({Actor.CODING_AGENT}),
}

#: Levels whose objects may be counted toward satisfying a validation
#: requirement. Membership is checked by the validation engine (M10); it is
#: defined here so the rule lives beside the lattice it constrains.
MAY_SATISFY_REQUIREMENT: Final[frozenset[TrustLevel]] = frozenset(
    {TrustLevel.NORMALIZED_EVIDENCE, TrustLevel.DERIVED_EVIDENCE}
)


class IllegalPromotionError(Exception):
    """Raised when a promotion is not in :data:`LEGAL_PROMOTIONS`.

    This is an error, not a warning. A system that logs an illegal promotion
    and continues has performed the promotion.
    """

    def __init__(self, source: TrustLevel, target: TrustLevel, actor: Actor) -> None:
        self.source = source
        self.target = target
        self.actor = actor
        permitted = LEGAL_PROMOTIONS.get((source, target))
        if permitted is None:
            detail = f"{source.name} -> {target.name} is not a legal transition"
        else:
            names = ", ".join(sorted(a.name for a in permitted))
            detail = (
                f"{source.name} -> {target.name} is legal only for: {names}; "
                f"{actor.name} attempted it"
            )
        super().__init__(f"Illegal trust promotion: {detail}")


def is_legal(source: TrustLevel, target: TrustLevel, actor: Actor) -> bool:
    """Whether `actor` may promote an object from `source` to `target`."""
    return actor in LEGAL_PROMOTIONS.get((source, target), frozenset())


def promote(source: TrustLevel, target: TrustLevel, actor: Actor) -> TrustLevel:
    """Return `target`, or raise if the promotion is not permitted.

    Every producer of a higher-trust object calls this. It returns the target
    level so it reads naturally at a construction site::

        level = promote(TrustLevel.TOOL_OUTPUT,
                        TrustLevel.NORMALIZED_EVIDENCE,
                        Actor.NORMALIZER)

    Raises:
        IllegalPromotionError: if the transition is not in :data:`LEGAL_PROMOTIONS`
            or the actor is not permitted to perform it.
    """
    if not is_legal(source, target, actor):
        raise IllegalPromotionError(source, target, actor)
    return target


def may_satisfy_requirement(level: TrustLevel) -> bool:
    """Whether an object at `level` can count toward a validation requirement.

    Invariant 2 lives here: ``AGENT_CLAIM`` is excluded, so a coding agent
    cannot shortcut validation however confident its wording.
    """
    return level in MAY_SATISFY_REQUIREMENT
