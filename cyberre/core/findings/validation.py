"""The validation engine.

The only thing in CyberRE permitted to promote a hypothesis to a finding
(invariant 8). It evaluates requirement predicates over the evidence graph
and reports coverage: what was established, what was not, and why the answer
is what it is.

Deterministic throughout. No model is consulted, because the question
"is there enough evidence?" must not be answered by the component whose
output the evidence is meant to check.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from cyberre.core.evidence.graph import EvidenceGraph
from cyberre.core.findings.predicates import PredicateContext
from cyberre.core.findings.requirements import Requirement, RequirementSet
from cyberre.core.models.base import DomainModel, NonEmptyStr
from cyberre.core.models.enums import FindingStatus
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.hypothesis import Hypothesis


class RequirementResult(DomainModel):
    """Whether one requirement was met, and by what."""

    requirement_id: NonEmptyStr
    description: NonEmptyStr
    satisfied: bool
    evidence_ids: tuple[str, ...] = ()
    optional: bool = False
    shares_source_with_earlier: bool = False
    """True when this was satisfied only by evidence already used elsewhere
    in the same set.

    It does **not** make the requirement unsatisfied. One analysis can
    legitimately establish several distinct facts - a data-flow run
    establishes both that a flow exists and that it carries no sanitiser -
    and refusing that would make a genuine finding unprovable.

    What it does is mark the requirement as uncorroborated, so the
    confidence engine can see that a set was satisfied by few underlying
    observations rather than many. Independence governs how much a set of
    facts is worth, not whether each fact was established.
    """


class ValidationOutcome(DomainModel):
    """The engine's verdict on one hypothesis."""

    hypothesis_id: NonEmptyStr
    requirement_set_id: NonEmptyStr
    status: FindingStatus
    results: tuple[RequirementResult, ...]
    satisfied_evidence_ids: tuple[str, ...] = ()
    completeness: float = Field(ge=0.0, le=1.0)
    """Satisfied mandatory requirements over total, counting only
    independent evidence. Caps the confidence score, so it is the single
    number that stops a thin finding scoring highly."""

    explanation: NonEmptyStr
    independent_source_count: int = 0
    """Distinct underlying observations behind the satisfied requirements.

    A set satisfied by one observation and a set satisfied by five are both
    complete, and they are not equally strong. The confidence engine reads
    this; validation only reports it.
    """

    @property
    def uncorroborated(self) -> tuple[str, ...]:
        """Requirements resting on evidence already used elsewhere."""
        return tuple(r.requirement_id for r in self.results if r.shares_source_with_earlier)

    @property
    def unsatisfied(self) -> tuple[str, ...]:
        """The investigation's next information needs."""
        return tuple(r.requirement_id for r in self.results if not r.satisfied)

    @property
    def is_validated(self) -> bool:
        return self.status is FindingStatus.VALIDATED


class ValidationEngine:
    """Evaluates hypotheses against requirement sets."""

    def __init__(self, *, track_corroboration: bool = True) -> None:
        """
        Args:
            track_corroboration: whether to mark requirements satisfied only
                by already-used evidence. On by default; turning it off
                simply stops the marking, since it never changes whether a
                requirement is satisfied.
        """
        self._require_independent = track_corroboration

    def validate(
        self,
        hypothesis: Hypothesis,
        requirement_set: RequirementSet,
        *,
        evidence: Sequence[Evidence],
        graph: EvidenceGraph,
        os_name: str | None = None,
        architecture: str | None = None,
    ) -> ValidationOutcome:
        """Decide what the evidence supports."""
        context = PredicateContext(
            evidence=evidence, graph=graph, os_name=os_name, architecture=architecture
        )

        refuted = self._first_satisfied(requirement_set.disproving, context)
        if refuted is not None:
            return self._outcome(
                hypothesis,
                requirement_set,
                status=FindingStatus.UNREACHABLE,
                results=(refuted,),
                completeness=1.0,
                explanation=(
                    f"refuted: {refuted.description}. This is an established "
                    f"negative rather than a failure to find evidence."
                ),
            )

        inapplicable = self._first_unsatisfied(requirement_set.applicability, context)
        if inapplicable is not None:
            return self._outcome(
                hypothesis,
                requirement_set,
                status=FindingStatus.NOT_APPLICABLE,
                results=(inapplicable,),
                completeness=0.0,
                explanation=(
                    f"not applicable: {inapplicable.description} could not be "
                    f"established, so the weakness does not apply to this target"
                ),
            )

        results, used = self._evaluate(requirement_set, context, graph)
        mandatory = [r for r in results if not r.optional]
        satisfied = [r for r in mandatory if r.satisfied]
        completeness = len(satisfied) / len(mandatory) if mandatory else 0.0

        independent = graph.count_independent(used) if used else 0

        # A hypothesis the caller never added to the graph has no recorded
        # contradictions. Asking the graph directly raises, correctly - an
        # unknown node and a node with no edges are different things - so the
        # distinction is resolved here rather than weakened there.
        contradicted = hypothesis.hypothesis_id in graph and graph.has_contradiction(
            hypothesis.hypothesis_id
        )
        if contradicted:
            return self._outcome(
                hypothesis,
                requirement_set,
                status=FindingStatus.CONTRADICTED,
                results=tuple(results),
                completeness=completeness,
                explanation=(
                    "evidence inconsistent with the hypothesis is present; the "
                    "contradiction is reported rather than resolved"
                ),
                used=used,
                independent=independent,
            )

        if completeness >= 1.0:
            return self._outcome(
                hypothesis,
                requirement_set,
                status=FindingStatus.VALIDATED,
                results=tuple(results),
                completeness=completeness,
                explanation=(
                    f"every requirement in {requirement_set.set_id} is satisfied by "
                    f"{independent} independent source(s)"
                ),
                used=used,
                independent=independent,
            )

        missing = [r.description for r in mandatory if not r.satisfied]
        return self._outcome(
            hypothesis,
            requirement_set,
            status=FindingStatus.NOT_ENOUGH_EVIDENCE,
            results=tuple(results),
            completeness=completeness,
            explanation=(
                f"{len(satisfied)} of {len(mandatory)} requirements satisfied. "
                f"Still needed: {'; '.join(missing)}"
            ),
            used=used,
            independent=independent,
        )

    # ----------------------------------------------------------- internals

    def _evaluate(
        self,
        requirement_set: RequirementSet,
        context: PredicateContext,
        graph: EvidenceGraph,
    ) -> tuple[list[RequirementResult], list[str]]:
        """Evaluate each requirement and track how many sources were used.

        A requirement satisfied only by already-used evidence is still
        satisfied, and marked as uncorroborated. One analysis can establish
        several distinct facts, and treating that as a failure would make a
        genuine finding unprovable.

        What stops one Semgrep hit satisfying a whole set is the predicates,
        not a discount: a scanner match is SCANNER_FINDING evidence, and the
        source, sanitiser and reachability requirements each demand a
        different evidence type. Specificity does the work, and it does it
        without punishing a tool for being thorough.
        """
        results: list[RequirementResult] = []
        used: list[str] = []
        used_keys: set[str] = set()

        for requirement in requirement_set.requirements:
            found = sorted(requirement.predicate.satisfied_by(context))
            if not found:
                results.append(
                    RequirementResult(
                        requirement_id=requirement.requirement_id,
                        description=requirement.description,
                        satisfied=False,
                        optional=requirement.optional,
                    )
                )
                continue

            keys = {self._source_key(graph, evidence_id) for evidence_id in found}
            shares_source = self._require_independent and keys <= used_keys

            used_keys |= keys
            used.extend(found)

            results.append(
                RequirementResult(
                    requirement_id=requirement.requirement_id,
                    description=requirement.description,
                    satisfied=True,
                    evidence_ids=tuple(found),
                    optional=requirement.optional,
                    shares_source_with_earlier=shares_source,
                )
            )

        return results, used

    @staticmethod
    def _source_key(graph: EvidenceGraph, evidence_id: str) -> str:
        """The underlying observation an evidence record describes."""
        try:
            return graph.root_observation(evidence_id)
        except KeyError:
            # Not in the graph: treat it as its own source rather than
            # silently merging it with something unrelated.
            return evidence_id

    @staticmethod
    def _first_satisfied(
        requirements: Sequence[Requirement], context: PredicateContext
    ) -> RequirementResult | None:
        for requirement in requirements:
            found = requirement.predicate.satisfied_by(context)
            if found:
                return RequirementResult(
                    requirement_id=requirement.requirement_id,
                    description=requirement.description,
                    satisfied=True,
                    evidence_ids=tuple(sorted(found)),
                )
        return None

    @staticmethod
    def _first_unsatisfied(
        requirements: Sequence[Requirement], context: PredicateContext
    ) -> RequirementResult | None:
        for requirement in requirements:
            if not requirement.predicate.satisfied_by(context):
                return RequirementResult(
                    requirement_id=requirement.requirement_id,
                    description=requirement.description,
                    satisfied=False,
                )
        return None

    @staticmethod
    def _outcome(
        hypothesis: Hypothesis,
        requirement_set: RequirementSet,
        *,
        status: FindingStatus,
        results: tuple[RequirementResult, ...],
        completeness: float,
        explanation: str,
        used: Sequence[str] = (),
        independent: int = 0,
    ) -> ValidationOutcome:
        return ValidationOutcome(
            hypothesis_id=hypothesis.hypothesis_id,
            requirement_set_id=requirement_set.set_id,
            status=status,
            results=results,
            satisfied_evidence_ids=tuple(sorted(set(used))),
            completeness=completeness,
            explanation=explanation,
            independent_source_count=independent,
        )
