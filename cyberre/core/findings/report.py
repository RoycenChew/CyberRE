"""Report generation.

Output is ASCII. A report is read on whatever terminal the analyst has, and
a Windows console in its default code page mangles typographic characters -
a report that renders as mojibake is a report nobody trusts.

The report is where the architecture's discipline either shows or is
undone. Three rules govern it:

* **Uncertainty is not hidden.** Negative outcomes get their own section
  rather than being omitted, because "we checked and it is unreachable" is
  a result the reader paid for.
* **Nothing unvalidated is presented as a finding.** The generator accepts
  `Finding`, and a `CandidateFinding` has no shape it could render
  (ADR-002).
* **Language is proportionate.** "The evidence supports" rather than "the
  binary is malicious". Section 44 of the master prompt is a style rule
  with a technical purpose: a report that overstates once is discounted
  entirely thereafter.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from cyberre.core.evidence.digest import ReproducibilityManifest
from cyberre.core.models.base import DomainModel, NonEmptyStr, utcnow
from cyberre.core.models.enums import FindingStatus, InvestigationStatus, Severity
from cyberre.core.models.evidence import Evidence, ToolFailure
from cyberre.core.models.finding import Finding
from cyberre.core.models.state import InvestigationState

#: Order findings are presented in. Validated first because that is what a
#: reader is looking for, then the outcomes that say something definite,
#: then the ones that say we could not tell.
STATUS_ORDER: dict[FindingStatus, int] = {
    FindingStatus.VALIDATED: 0,
    FindingStatus.NEEDS_REVIEW: 1,
    FindingStatus.CONTRADICTED: 2,
    FindingStatus.UNREACHABLE: 3,
    FindingStatus.NOT_APPLICABLE: 4,
    FindingStatus.NOT_ENOUGH_EVIDENCE: 5,
    FindingStatus.UNVALIDATED: 6,
}

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}

#: How each outcome is described. Written out rather than derived from the
#: enum name, because the phrasing is the part that keeps a report honest.
STATUS_LANGUAGE: dict[FindingStatus, str] = {
    FindingStatus.VALIDATED: "supported by evidence",
    FindingStatus.NEEDS_REVIEW: "requires human review",
    FindingStatus.CONTRADICTED: "contradicted by evidence",
    FindingStatus.UNREACHABLE: "present but not reachable",
    FindingStatus.NOT_APPLICABLE: "does not apply to this target",
    FindingStatus.NOT_ENOUGH_EVIDENCE: "not established",
    FindingStatus.UNVALIDATED: "not yet validated",
}


class Report(DomainModel):
    """A rendered investigation report."""

    investigation_id: NonEmptyStr
    question: NonEmptyStr
    generated_at: datetime
    markdown: NonEmptyStr

    validated_count: int = 0
    unresolved_count: int = 0
    is_partial: bool = False


def _sort_key(finding: Finding) -> tuple[int, int, str]:
    severity = SEVERITY_ORDER.get(finding.severity, 9) if finding.severity else 9
    return (STATUS_ORDER.get(finding.status, 9), severity, finding.title)


def _confidence_line(finding: Finding) -> str:
    if finding.confidence is None:
        return "Confidence: not scored (only a validated finding carries one)"
    breakdown = finding.confidence
    factors = ", ".join(f"{name} {value:.2f}" for name, value in sorted(breakdown.factors.items()))
    return (
        f"Confidence: {breakdown.final_score:.2f} "
        f"(capped by completeness {breakdown.completeness:.2f}; "
        f"formula {breakdown.formula_version}; {factors})"
    )


def _render_finding(finding: Finding, evidence: Mapping[str, Evidence], index: int) -> list[str]:
    severity = finding.severity.value if finding.severity else "no severity"
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"**Status:** {STATUS_LANGUAGE.get(finding.status, finding.status.value)} "
        f"(`{finding.status.value}`) | **Severity:** {severity} | "
        f"**Class:** {finding.hypothesis_class}",
        "",
        finding.description,
        "",
        _confidence_line(finding),
        "",
    ]

    if finding.locations:
        lines += ["**Locations:** " + ", ".join(str(loc) for loc in finding.locations), ""]

    if finding.evidence_ids:
        lines += ["**Evidence**", ""]
        for evidence_id in finding.evidence_ids:
            item = evidence.get(evidence_id)
            if item is None:
                lines.append(f"- `{evidence_id}` (not retained)")
                continue
            lines.append(
                f"- `{evidence_id}` {item.evidence_type.value} at {item.location} "
                f"via {item.provenance.tool.tool} "
                f"{item.provenance.tool.tool_version}"
            )
        lines.append("")

    if finding.unsatisfied_requirements:
        lines += [
            "**Not established**",
            "",
            *(f"- {r}" for r in finding.unsatisfied_requirements),
            "",
        ]

    if finding.review is not None:
        review = finding.review
        lines += [
            f"**Adversarial review:** {review.verdict.value} - {review.rationale}",
            "",
        ]
        if review.alternative_explanation:
            lines += [
                f"**Alternative explanation considered:** {review.alternative_explanation}",
                "",
            ]

    if finding.validation_plan:
        lines += [f"**What would settle this:** {finding.validation_plan}", ""]

    if finding.remediation:
        lines += [f"**Remediation:** {finding.remediation}", ""]

    return lines


class ReportGenerator:
    """Renders an investigation into Markdown."""

    def generate(
        self,
        state: InvestigationState,
        *,
        findings: Sequence[Finding],
        evidence: Mapping[str, Evidence],
        manifest: ReproducibilityManifest | None = None,
        failures: Sequence[ToolFailure] = (),
        observations: Sequence[str] = (),
    ) -> Report:
        """Render the report.

        Accepts `Finding` only. A candidate has no shape this could render,
        which is how ADR-002 is enforced at the last step rather than by
        remembering not to pass one.
        """
        ordered = sorted(findings, key=_sort_key)
        validated = [f for f in ordered if f.status is FindingStatus.VALIDATED]
        unresolved = [f for f in ordered if f.status is not FindingStatus.VALIDATED]
        partial = state.status is InvestigationStatus.PARTIAL or bool(failures)

        lines: list[str] = [
            f"# Investigation {state.investigation_id}",
            "",
            f"**Question:** {state.objective.question}",
            "",
            f"**Status:** {state.status.value} | **Depth:** {state.depth.value} | "
            f"**Generated:** {utcnow().isoformat()}",
            "",
            "## Executive summary",
            "",
        ]

        if validated:
            lines.append(
                f"The investigation established {len(validated)} finding(s) supported "
                f"by evidence, and examined {len(unresolved)} further "
                f"hypothes{'is' if len(unresolved) == 1 else 'es'} that the evidence "
                f"did not support."
            )
        elif unresolved:
            lines.append(
                f"The investigation established no findings. {len(unresolved)} "
                f"hypothes{'is was' if len(unresolved) == 1 else 'es were'} examined "
                f"and not supported by the available evidence; the reasons are given "
                f"below and are themselves a result."
            )
        else:
            lines.append(
                "The investigation established no findings and has none to report "
                "as examined-and-unsupported. This may mean the artefact is sound, "
                "or that the available capabilities could not see enough of it, or "
                "that proposed hypotheses did not survive verification. The "
                "observations and limitations sections say which."
            )

        if partial:
            lines += [
                "",
                "> **This investigation is partial.** A tool failed or the budget "
                "was exhausted, so coverage is incomplete. Absence of a finding "
                "here is not evidence of absence.",
            ]

        lines += ["", "## Scope", ""]
        lines.append(f"- Objective: {state.objective.normalised_intent}")
        lines.append(f"- Artefacts: {len(state.artefact_ids)}")
        lines.append(f"- Evidence collected: {len(state.evidence_ids)}")
        if state.profiles:
            lines.append("- Profiles: " + ", ".join(p.value for p in state.profiles))

        # Every capability that ran, including the ones that found nothing.
        # Without this a reader cannot tell "the scanner ran and found
        # nothing" from "the scanner never ran", and those support very
        # different conclusions. The reproducibility manifest records only
        # tools that produced evidence, so it cannot answer this alone.
        executed = sorted(
            {ref.identifier for ref in state.tool_history if ref.kind == "capability"}
        )
        if executed:
            lines += ["", "**Capabilities run:** " + ", ".join(executed)]
        elif state.artefact_ids:
            lines += [
                "",
                "**Capabilities run:** none. No analysis was performed, so this "
                "report establishes nothing about the artefacts.",
            ]

        if validated:
            lines += ["", "## Findings", ""]
            for index, finding in enumerate(validated, start=1):
                lines += _render_finding(finding, evidence, index)

        if unresolved:
            # Their own section, not an appendix. "We checked and it is
            # unreachable" is a result the reader paid for.
            lines += ["", "## Examined and not established", ""]
            for index, finding in enumerate(unresolved, start=1):
                lines += _render_finding(finding, evidence, index)

        if observations:
            lines += ["", "## Observations", "", *(f"- {o}" for o in observations)]

        lines += ["", "## Limitations", ""]
        if failures:
            lines.append("The following tools did not complete:")
            lines.append("")
            for failure in failures:
                lines.append(f"- `{failure.capability_id}`: {failure.reason}")
            lines.append("")
        if state.unresolved_questions:
            lines.append("Open questions:")
            lines.append("")
            for question in state.unresolved_questions:
                lines.append(f"- {question.question} - {question.why_unresolved}")
            lines.append("")
        if not failures and not state.unresolved_questions:
            lines.append("No tool failures and no unresolved questions were recorded.")
            lines.append("")

        lines.append(
            "This report describes what the available evidence supports. It is not "
            "a statement that no other weakness exists."
        )

        if manifest is not None:
            lines += [
                "",
                "## Reproducibility",
                "",
                f"- CyberRE: {manifest.cyberre_version}",
                f"- Evidence digest: `{manifest.evidence_set_digest}`",
                f"- Finding digest: `{manifest.finding_set_digest}`",
            ]
            for tool, version in sorted(manifest.tool_versions.items()):
                lines.append(f"- {tool}: {version}")
            for tool, ruleset in sorted(manifest.ruleset_versions.items()):
                lines.append(f"- {tool} ruleset: {ruleset}")
            for artefact_hash in manifest.artefact_hashes:
                lines.append(f"- artefact: `{artefact_hash}`")
            if manifest.confidence_formula_version:
                lines.append(f"- confidence formula: {manifest.confidence_formula_version}")

        return Report(
            investigation_id=state.investigation_id,
            question=state.objective.question,
            generated_at=utcnow(),
            markdown="\n".join(lines),
            validated_count=len(validated),
            unresolved_count=len(unresolved),
            is_partial=partial,
        )
