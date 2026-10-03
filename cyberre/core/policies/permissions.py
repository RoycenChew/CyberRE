"""Effective permissions: what may actually run, here, now, for this user.

Five terms are intersected (ADR-015). The property that matters is that
intersection is the *only* operation: no term can widen another, so a profile
asking for sandbox network access cannot obtain it from a global policy that
withholds it (invariants 3 and 4).

Written as an explicit fold rather than a chain of ``and``s so that every
denial can name the term responsible. "Permission denied" without a reason is
a support ticket.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from enum import StrEnum

from pydantic import Field

from cyberre.core.models.base import DomainModel
from cyberre.core.models.enums import RISK_ORDER, RiskLevel


class PermissionTerm(StrEnum):
    """Which policy a restriction came from.

    Recorded on every decision. With five terms, "why was this denied?" is
    otherwise a guessing game.
    """

    GLOBAL = "global"
    ENVIRONMENT = "environment"
    PROFILE = "profile"
    CAPABILITY = "capability"
    USER = "user"
    EFFECTIVE = "effective"


def _max_allowed(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    """The more restrictive of two risk ceilings."""
    return left if RISK_ORDER[left] <= RISK_ORDER[right] else right


class PermissionSet(DomainModel):
    """One term in the intersection.

    Defaults are the restrictive ones throughout. A term constructed with no
    arguments permits local static analysis and nothing else, so an
    unconfigured deployment is safe rather than open.

    That cuts both ways, and the edge is worth knowing: a subordinate term
    written only to forbid one capability - ``PermissionSet(
    forbidden_capabilities={"x"})`` - also carries the default L1 ceiling and
    will clamp the effective risk level. Build subordinate terms from
    :meth:`no_opinion` and narrow from there. Erring toward over-restriction
    is the right direction for a security boundary, but it should be a choice
    rather than a surprise.
    """

    term: PermissionTerm = PermissionTerm.GLOBAL

    max_risk_level: RiskLevel = RiskLevel.L1_LOCAL_STATIC
    """Highest risk this term permits. Default allows local static analysis."""

    approval_required_above: RiskLevel = RiskLevel.L1_LOCAL_STATIC
    """Anything riskier than this needs a human, even when permitted."""

    allowed_capabilities: frozenset[str] | None = None
    """``None`` means "no opinion", not "everything".

    An explicit empty set means "nothing", which is a different statement and
    must stay distinguishable.
    """

    forbidden_capabilities: frozenset[str] = frozenset()
    allow_network: bool = False
    allow_sandbox: bool = False

    @classmethod
    def no_opinion(cls, term: PermissionTerm) -> PermissionSet:
        """The identity element of :meth:`intersect`: restricts nothing.

        Needed because the four subordinate terms are usually unset, and an
        unset term must not clamp the ceiling the global policy established -
        otherwise nothing above L1 could ever be authorised without writing
        out all five terms, and policy that is tedious to express correctly
        gets expressed incorrectly.

        This is not a hole in the fail-closed rule. Authority originates in
        the global policy, which defaults to static analysis; the subordinate
        terms exist only to subtract from it. :func:`effective_permissions`
        over an empty sequence still yields the restrictive default, so a
        deployment with no policy at all permits nothing.

        Raises:
            ValueError: if asked for a ``GLOBAL`` term. A global policy that
                restricts nothing is the one way this helper could open a
                hole, so that use is refused rather than documented against.
        """
        if term is PermissionTerm.GLOBAL:
            raise ValueError(
                "the global policy must state what is permitted; it is the term "
                "that carries authority, and an unrestricted one would authorise "
                "destructive operations by omission"
            )
        return cls(
            term=term,
            max_risk_level=RiskLevel.L5_EXTERNAL_TARGET,
            approval_required_above=RiskLevel.L5_EXTERNAL_TARGET,
            allowed_capabilities=None,
            forbidden_capabilities=frozenset(),
            allow_network=True,
            allow_sandbox=True,
        )

    def intersect(self, other: PermissionSet) -> PermissionSet:
        """Combine with `other`, keeping only what both permit.

        Allow-lists intersect; where one side has no opinion the other stands.
        Deny-lists union, because a prohibition from any term is a
        prohibition. Booleans require both. Ceilings take the lower.
        """
        if self.allowed_capabilities is None:
            allowed = other.allowed_capabilities
        elif other.allowed_capabilities is None:
            allowed = self.allowed_capabilities
        else:
            allowed = self.allowed_capabilities & other.allowed_capabilities

        return PermissionSet(
            term=PermissionTerm.EFFECTIVE,
            max_risk_level=_max_allowed(self.max_risk_level, other.max_risk_level),
            approval_required_above=_max_allowed(
                self.approval_required_above, other.approval_required_above
            ),
            allowed_capabilities=allowed,
            forbidden_capabilities=self.forbidden_capabilities | other.forbidden_capabilities,
            allow_network=self.allow_network and other.allow_network,
            allow_sandbox=self.allow_sandbox and other.allow_sandbox,
        )

    def permits_capability(self, capability_id: str) -> bool:
        if capability_id in self.forbidden_capabilities:
            return False
        if self.allowed_capabilities is None:
            return True
        return capability_id in self.allowed_capabilities

    def permits_risk(self, risk: RiskLevel) -> bool:
        return RISK_ORDER[risk] <= RISK_ORDER[self.max_risk_level]

    def needs_approval_for(self, risk: RiskLevel) -> bool:
        return RISK_ORDER[risk] > RISK_ORDER[self.approval_required_above]


def effective_permissions(terms: Iterable[PermissionSet]) -> PermissionSet:
    """Fold the terms into one permission set.

    An empty sequence yields the default - read-only - rather than
    unrestricted. Forgetting to configure policy must not grant authority.
    """
    folded: PermissionSet | None = None
    for term in terms:
        folded = term if folded is None else folded.intersect(term)
    if folded is None:
        return PermissionSet(term=PermissionTerm.EFFECTIVE)
    return folded.model_copy(update={"term": PermissionTerm.EFFECTIVE})


def restricting_terms(
    terms: Sequence[PermissionSet], capability_id: str, risk: RiskLevel
) -> tuple[PermissionTerm, ...]:
    """Which terms individually refuse this capability.

    Used to explain a denial. Reported in policy order, so the message names
    the global policy before the user's, which is usually the more useful
    thing to read first.
    """
    return tuple(
        term.term
        for term in terms
        if not term.permits_capability(capability_id) or not term.permits_risk(risk)
    )


#: Sensible starting points. Deployments override them through configuration;
#: they exist so that a default deployment is restrictive rather than absent.
READ_ONLY = PermissionSet(
    term=PermissionTerm.GLOBAL,
    max_risk_level=RiskLevel.L0_READ_ONLY,
    approval_required_above=RiskLevel.L0_READ_ONLY,
)

STATIC_ANALYSIS = PermissionSet(
    term=PermissionTerm.GLOBAL,
    max_risk_level=RiskLevel.L1_LOCAL_STATIC,
    approval_required_above=RiskLevel.L1_LOCAL_STATIC,
)

SANDBOXED_ANALYSIS = PermissionSet(
    term=PermissionTerm.GLOBAL,
    max_risk_level=RiskLevel.L2_SANDBOX,
    approval_required_above=RiskLevel.L1_LOCAL_STATIC,
    allow_sandbox=True,
)

#: Levels 4 and 5 are absent from every preset on purpose. Destructive and
#: external-target operations require a policy written deliberately for the
#: engagement, not a constant someone can reach for.
NETWORKED_LAB = PermissionSet(
    term=PermissionTerm.GLOBAL,
    max_risk_level=RiskLevel.L3_NETWORKED_LAB,
    approval_required_above=RiskLevel.L2_SANDBOX,
    allow_sandbox=True,
    allow_network=True,
)


class PolicyContext(DomainModel):
    """The five terms for one decision.

    The global policy carries the authority and defaults to static analysis.
    The other four default to :meth:`PermissionSet.no_opinion`, because their
    role is to narrow what the global policy allows, never to be the reason
    something is allowed.
    """

    global_policy: PermissionSet = STATIC_ANALYSIS
    environment_policy: PermissionSet = Field(
        default_factory=lambda: PermissionSet.no_opinion(PermissionTerm.ENVIRONMENT)
    )
    profile_policy: PermissionSet = Field(
        default_factory=lambda: PermissionSet.no_opinion(PermissionTerm.PROFILE)
    )
    capability_policy: PermissionSet = Field(
        default_factory=lambda: PermissionSet.no_opinion(PermissionTerm.CAPABILITY)
    )
    user_policy: PermissionSet = Field(
        default_factory=lambda: PermissionSet.no_opinion(PermissionTerm.USER)
    )

    def terms(self) -> tuple[PermissionSet, ...]:
        return (
            self.global_policy,
            self.environment_policy,
            self.profile_policy,
            self.capability_policy,
            self.user_policy,
        )

    def effective(self) -> PermissionSet:
        return effective_permissions(self.terms())
