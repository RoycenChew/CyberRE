"""Choosing what to do next.

Pure functions over plain data: no I/O, no model, no workflow engine
(ADR-003, ADR-022). Everything here is decidable from the registry, the
profile and what has already been observed, which is what makes the
investigation's behaviour testable without running anything.

The question these functions answer is "what do I need to know next?" rather
than "what tools can I call?". The difference shows in the ranking: an action
scores on whether it would close an open information need, not on how
sophisticated it is.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pydantic import Field

from cyberre.core.contracts.capability import CapabilitySpec
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import ArtefactType, Depth, EvidenceType
from cyberre.core.profiles.model import AnalysisProfile

#: How many actions a single round may dispatch. The planner returns a set
#: rather than one action because independent capabilities run concurrently,
#: and that is the single largest Time-to-Justified-Conclusion win available
#: (architecture section 10). The cap keeps a round from saturating the pool.
MAX_PARALLEL_ACTIONS = 6

#: Weights for the ranking. Named and configurable rather than buried in an
#: expression, so a planner that starts making poor choices can be diagnosed
#: and retuned against the benchmark instead of being guessed at.
WEIGHT_CLOSES_NEED = 0.45
WEIGHT_INFORMATION_GAIN = 0.2
WEIGHT_RELIABILITY = 0.15
WEIGHT_PROFILE_PREFERENCE = 0.1
WEIGHT_CHEAPNESS = 0.1

#: Seconds beyond which an action is treated as maximally expensive. Not a
#: timeout - purely the scale on which cost is compared.
COST_HORIZON_SECONDS = 300.0


class InformationNeed(DomainModel):
    """Something the investigation does not yet know.

    Needs come from unsatisfied validation requirements and from the
    profile's hypothesis classes. Making them explicit is what lets the
    planner be judged on whether it closed one.
    """

    need_id: NonEmptyStr
    description: NonEmptyStr
    satisfied_by: frozenset[EvidenceType]
    """Evidence types that would help. A need no capability can produce is
    reported as unresolvable rather than driving an endless loop."""

    for_hypothesis: str | None = None
    urgency: float = Field(default=0.5, ge=0.0, le=1.0)


class PlannedAction(DomainModel):
    """A capability the planner wants to run, and why."""

    capability_id: NonEmptyStr
    score: float = Field(ge=0.0, le=1.0)
    rationale: NonEmptyStr
    """Recorded on the investigation. "Why did it run that?" is an audit
    question as much as a debugging one."""

    closes_needs: tuple[str, ...] = ()
    estimated_seconds: float = Field(default=0.0, ge=0.0)


def _cheapness(spec: CapabilitySpec) -> float:
    """1.0 for an instant action, approaching 0.0 at the cost horizon."""
    return max(0.0, 1.0 - min(spec.cost.seconds, COST_HORIZON_SECONDS) / COST_HORIZON_SECONDS)


def _profile_preference(spec: CapabilitySpec, profile: AnalysisProfile | None) -> float:
    """1.0 for the profile's first preference, decaying down the list."""
    if profile is None or not profile.preferred_capabilities:
        return 0.5
    rank = profile.preference_rank(spec.capability_id)
    if rank > len(profile.preferred_capabilities):
        return 0.0
    return 1.0 - (rank / max(1, len(profile.preferred_capabilities)))


def needs_closed_by(spec: CapabilitySpec, needs: Sequence[InformationNeed]) -> tuple[str, ...]:
    """Which open needs this capability could help close."""
    return tuple(need.need_id for need in needs if spec.produces & need.satisfied_by)


def score_action(
    spec: CapabilitySpec,
    *,
    needs: Sequence[InformationNeed] = (),
    profile: AnalysisProfile | None = None,
) -> tuple[float, tuple[str, ...]]:
    """Score a capability between 0 and 1, with the needs it would close.

    Closing an open need dominates deliberately. Tracing attacker-controlled
    input to a subprocess sink should outrank searching a CVE database when
    the open question is whether a command injection is reachable, even
    though the CVE search is cheaper and more reliable in the abstract.
    """
    closes = needs_closed_by(spec, needs)

    if needs:
        urgency = max((n.urgency for n in needs if n.need_id in closes), default=0.0)
        need_component = urgency if closes else 0.0
    else:
        # Nothing specific is being asked yet, so the opening round is driven
        # by the capability's own prior rather than by a need.
        need_component = spec.information_gain_prior

    score = (
        WEIGHT_CLOSES_NEED * need_component
        + WEIGHT_INFORMATION_GAIN * spec.information_gain_prior
        + WEIGHT_RELIABILITY * spec.reliability
        + WEIGHT_PROFILE_PREFERENCE * _profile_preference(spec, profile)
        + WEIGHT_CHEAPNESS * _cheapness(spec)
    )
    return min(1.0, max(0.0, score)), closes


def _rationale(spec: CapabilitySpec, closes: tuple[str, ...]) -> str:
    if closes:
        return f"would help close: {', '.join(closes)}"
    return f"{spec.name} contributes {', '.join(sorted(e.value for e in spec.produces))}"


def plan_actions(
    specs: Iterable[CapabilitySpec],
    *,
    artefact_types: Iterable[ArtefactType],
    satisfied_capabilities: Iterable[str] = (),
    needs: Sequence[InformationNeed] = (),
    profile: AnalysisProfile | None = None,
    depth: Depth = Depth.STANDARD,
    limit: int = MAX_PARALLEL_ACTIONS,
) -> list[PlannedAction]:
    """Rank the capabilities worth running now.

    A set rather than one action, because independent capabilities run
    concurrently. Excluded are capabilities that do not apply to the
    artefact, that the profile forbids, that have already run, and whose
    prerequisites are unmet - the last so the planner cannot ask to decompile
    a function in a binary nobody has analysed.

    Ordering is deterministic: score descending, then capability id. A
    planner whose order depended on dictionary iteration would make
    investigations unreproducible.
    """
    applicable_types = set(artefact_types)
    already = set(satisfied_capabilities)
    forbidden = profile.forbidden_capabilities if profile else frozenset()

    candidates: list[PlannedAction] = []
    for spec in specs:
        if spec.capability_id in already or spec.capability_id in forbidden:
            continue
        if applicable_types and not (spec.artefact_types & applicable_types):
            continue
        if any(prerequisite not in already for prerequisite in spec.prerequisites):
            continue

        score, closes = score_action(spec, needs=needs, profile=profile)
        candidates.append(
            PlannedAction(
                capability_id=spec.capability_id,
                score=score,
                rationale=_rationale(spec, closes),
                closes_needs=closes,
                estimated_seconds=spec.cost.seconds,
            )
        )

    candidates.sort(key=lambda action: (-action.score, action.capability_id))

    # FAST investigations take a narrow slice: the point of the depth
    # setting is that a simple question does not trigger an expensive
    # investigation (architecture section 10).
    effective_limit = 2 if depth is Depth.FAST else limit
    return candidates[:effective_limit]


def unresolvable_needs(
    specs: Iterable[CapabilitySpec], needs: Sequence[InformationNeed]
) -> tuple[str, ...]:
    """Needs no registered capability could ever close.

    Reported rather than retried. A need nothing can satisfy is the reason an
    investigation ends as NOT_ENOUGH_EVIDENCE, and saying which one is the
    most useful part of that answer.
    """
    producible: set[EvidenceType] = set()
    for spec in specs:
        producible |= spec.produces
    return tuple(need.need_id for need in needs if not (need.satisfied_by & producible))
