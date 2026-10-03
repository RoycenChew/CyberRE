"""Analysis profiles: declarative configuration, never agents.

A profile parameterises an investigation - which capabilities the planner
prefers, which evidence a class of hypothesis requires, which knowledge
sources apply, how deep to go. It is data (ADR-008, ADR-021).

The single most important property is that a profile *requests* and
*forbids*; it never grants. Its policy contribution enters the five-way
intersection as one more term that can only subtract (invariant 3).
"""

from __future__ import annotations

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import ArtefactType, Depth, ProfileId, RiskLevel
from cyberre.core.policies.permissions import PermissionSet, PermissionTerm


class ProfileNotImplementedError(NotImplementedError):
    """A declared profile that has no implementation behind it yet.

    Raised rather than falling back to a general-purpose profile. Silently
    running THREAT_HUNTING as though it were SOURCE_SECURITY would produce a
    report that looks like threat hunting and is not, which is worse than
    refusing.
    """


class ProfilePolicyRequest(DomainModel):
    """What a profile would like to be permitted.

    A request, not a grant. MALWARE_ANALYSIS asking for sandbox access states
    that it is useless without one; whether it gets one is the global
    policy's decision.
    """

    max_risk_level: RiskLevel = RiskLevel.L1_LOCAL_STATIC
    wants_sandbox: bool = False
    wants_network: bool = False
    approval_required_above: RiskLevel = RiskLevel.L1_LOCAL_STATIC
    """A profile may tighten this below the global setting - never above."""

    def as_permission_term(self) -> PermissionSet:
        """Convert to a term for the policy intersection.

        The result can only narrow. Because intersection takes the lower
        ceiling and requires both booleans, a profile asking for more than
        the global policy allows simply has no effect - there is no code path
        by which the request becomes authority.
        """
        return PermissionSet(
            term=PermissionTerm.PROFILE,
            max_risk_level=self.max_risk_level,
            approval_required_above=self.approval_required_above,
            allowed_capabilities=None,
            allow_network=self.wants_network,
            allow_sandbox=self.wants_sandbox,
        )


class AnalysisProfile(DomainModel):
    """How to investigate a particular kind of problem."""

    profile_id: ProfileId
    name: NonEmptyStr
    description: NonEmptyStr
    implemented: bool = True
    """False for a profile that is declared but has no behaviour yet.

    Declared rather than omitted so that `cyberre capabilities list` can show
    what exists, what does not, and that the gap is known.
    """

    applicable_artefact_types: frozenset[ArtefactType] = frozenset()
    default_depth: Depth = Depth.STANDARD

    preferred_capabilities: tuple[str, ...] = ()
    """A planner prior, not a permission grant and not a whitelist.

    Preferring a capability says "try this first", never "this is allowed".
    """

    forbidden_capabilities: frozenset[str] = frozenset()
    """A profile-level prohibition. This one does bind, because forbidding is
    subtraction and subtraction is always permitted."""

    hypothesis_classes: tuple[str, ...] = ()
    """Weakness classes this profile looks for, as ``taxonomy:identifier``."""

    requirement_sets: dict[str, str] = Field(default_factory=dict)
    """Hypothesis class to requirement-set id. The validation engine (M10)
    resolves evidence requirements through this."""

    knowledge_sources: tuple[str, ...] = ()
    policy: ProfilePolicyRequest = ProfilePolicyRequest()

    @model_validator(mode="after")
    def _unimplemented_profiles_promise_nothing(self) -> AnalysisProfile:
        """A stub must not look configured.

        A stub carrying capability preferences and requirement sets reads as
        working, and someone will eventually wire it up by accident.
        """
        if not self.implemented and (self.preferred_capabilities or self.requirement_sets):
            raise ValueError(
                f"profile '{self.profile_id.value}' is marked unimplemented but "
                f"declares behaviour; a stub should declare only its identity"
            )
        return self

    @model_validator(mode="after")
    def _preferences_are_not_prohibitions(self) -> AnalysisProfile:
        """Preferring and forbidding the same capability is incoherent."""
        conflict = set(self.preferred_capabilities) & self.forbidden_capabilities
        if conflict:
            raise ValueError(
                f"profile '{self.profile_id.value}' both prefers and forbids: {sorted(conflict)}"
            )
        return self

    def require_implemented(self) -> None:
        """Raise unless this profile actually does something."""
        if not self.implemented:
            raise ProfileNotImplementedError(
                f"the '{self.profile_id.value}' profile is declared but not "
                f"implemented in this version; running it would produce a report "
                f"that looks like {self.name.lower()} and is not"
            )

    def prefers(self, capability_id: str) -> bool:
        return capability_id in self.preferred_capabilities

    def preference_rank(self, capability_id: str) -> int:
        """Position in the preference list, or a large number if absent.

        Used by the planner as a tiebreak. Lower is preferred.
        """
        try:
            return self.preferred_capabilities.index(capability_id)
        except ValueError:
            return len(self.preferred_capabilities) + 1


def merge_profiles(profiles: list[AnalysisProfile]) -> AnalysisProfile:
    """Combine several active profiles into one.

    A repository with a dropped binary is SOURCE_SECURITY *and* BINARY_RE, and
    the combination must not be more permissive than either part. So:

    * requirements, hypothesis classes and knowledge sources **union** - more
      things to check is always safe;
    * prohibitions **union** - a prohibition from any profile binds;
    * the policy request **intersects** - the combination asks for no more
      than the most restrictive member;
    * depth takes the **deepest**, since the combined problem is at least as
      hard as its hardest part.

    Preferences concatenate in order, de-duplicated, so the first profile
    named keeps priority.
    """
    if not profiles:
        raise ValueError("at least one profile is required")
    if len(profiles) == 1:
        profiles[0].require_implemented()
        return profiles[0]

    for profile in profiles:
        profile.require_implemented()

    preferred: list[str] = []
    for profile in profiles:
        for capability_id in profile.preferred_capabilities:
            if capability_id not in preferred:
                preferred.append(capability_id)

    forbidden: frozenset[str] = frozenset()
    for profile in profiles:
        forbidden |= profile.forbidden_capabilities

    requirement_sets: dict[str, str] = {}
    for profile in profiles:
        requirement_sets.update(profile.requirement_sets)

    classes: list[str] = []
    sources: list[str] = []
    for profile in profiles:
        classes.extend(c for c in profile.hypothesis_classes if c not in classes)
        sources.extend(s for s in profile.knowledge_sources if s not in sources)

    artefacts: frozenset[ArtefactType] = frozenset()
    for profile in profiles:
        artefacts |= profile.applicable_artefact_types

    depth = max((p.default_depth for p in profiles), key=_depth_rank)

    merged_policy = _intersect_policy_requests([p.policy for p in profiles])

    # A prohibition from one profile beats a preference from another: the
    # combination must not be more permissive than either part.
    preferred = [c for c in preferred if c not in forbidden]

    return AnalysisProfile(
        profile_id=profiles[0].profile_id,
        name=" + ".join(p.name for p in profiles),
        description="Combined profile: " + "; ".join(p.name for p in profiles),
        applicable_artefact_types=artefacts,
        default_depth=depth,
        preferred_capabilities=tuple(preferred),
        forbidden_capabilities=forbidden,
        hypothesis_classes=tuple(classes),
        requirement_sets=requirement_sets,
        knowledge_sources=tuple(sources),
        policy=merged_policy,
    )


_DEPTH_RANK = {Depth.FAST: 0, Depth.STANDARD: 1, Depth.DEEP: 2}


def _depth_rank(depth: Depth) -> int:
    return _DEPTH_RANK[depth]


def _intersect_policy_requests(requests: list[ProfilePolicyRequest]) -> ProfilePolicyRequest:
    from cyberre.core.models.enums import RISK_ORDER

    lowest_ceiling = min(requests, key=lambda r: RISK_ORDER[r.max_risk_level])
    lowest_approval = min(requests, key=lambda r: RISK_ORDER[r.approval_required_above])
    return ProfilePolicyRequest(
        max_risk_level=lowest_ceiling.max_risk_level,
        approval_required_above=lowest_approval.approval_required_above,
        wants_sandbox=all(r.wants_sandbox for r in requests),
        wants_network=all(r.wants_network for r in requests),
    )
