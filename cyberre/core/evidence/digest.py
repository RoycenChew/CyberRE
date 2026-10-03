"""Canonical digests, for deciding whether two runs produced the same result.

"Reproducible" needs defining before it can be tested. Two runs of the same
investigation over the same inputs will differ in generated identifiers and
timestamps, so byte equality of the stored records is the wrong test - it
would fail every time while telling us nothing.

What must be stable is the *content*: the same observations, from the same
tools at the same versions, over the same artefact bytes, related the same
way. These functions hash exactly that and deliberately exclude the volatile
fields, so a digest mismatch means the analysis changed.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr, sha256_hex
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.finding import Finding

#: Fields excluded from a content digest because they vary between runs
#: without the analysis having changed.
VOLATILE_EVIDENCE_FIELDS = frozenset(
    {"evidence_id", "investigation_id", "artefact_id", "created_at", "derived_from"}
)

#: Provenance fields that vary per run. ``collected_at`` is a timestamp and
#: ``invocation_id`` identifies the execution, not the observation.
#: ``raw_output_ref`` is kept: it is a content hash, so a change in it means
#: the tool genuinely produced different output.
VOLATILE_PROVENANCE_FIELDS = frozenset({"collected_at", "invocation_id"})

VOLATILE_FINDING_FIELDS = frozenset(
    {
        "finding_id",
        "investigation_id",
        "hypothesis_id",
        "created_at",
        "evidence_ids",
        "review",
    }
)


def _canonical_json(data: object) -> str:
    """Stable JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _strip(data: dict[str, object], exclude: frozenset[str]) -> dict[str, object]:
    return {k: v for k, v in data.items() if k not in exclude}


def evidence_digest(evidence: Evidence) -> str:
    """Content digest of one piece of evidence.

    Covers the observation, the location, the tool and its version, and the
    artefact hash. Changing any of those is a real change in what was found
    or how it was found.
    """
    payload = _strip(evidence.model_dump(mode="json"), VOLATILE_EVIDENCE_FIELDS)
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        payload["provenance"] = _strip(provenance, VOLATILE_PROVENANCE_FIELDS)
    return sha256_hex(_canonical_json(payload).encode("utf-8"))


def finding_digest(finding: Finding) -> str:
    """Content digest of a finding.

    Includes the status, the severity and the confidence score, because a run
    that reaches the same conclusion with different confidence has not
    reproduced the earlier run.
    """
    payload = _strip(finding.model_dump(mode="json"), VOLATILE_FINDING_FIELDS)
    return sha256_hex(_canonical_json(payload).encode("utf-8"))


def evidence_set_digest(evidence: Iterable[Evidence]) -> str:
    """Digest over a whole evidence set.

    Order-independent: the digests are sorted before combining, because two
    capabilities running concurrently may finish in either order without the
    analysis having changed. What must not change is the *set* of things
    observed.
    """
    digests = sorted(evidence_digest(item) for item in evidence)
    return sha256_hex("\n".join(digests).encode("utf-8"))


def finding_set_digest(findings: Iterable[Finding]) -> str:
    digests = sorted(finding_digest(item) for item in findings)
    return sha256_hex("\n".join(digests).encode("utf-8"))


class ReproducibilityManifest(DomainModel):
    """Everything needed to re-run an investigation and compare the result.

    Recorded with every investigation. Without it, a finding from six months
    ago cannot be re-examined - and being able to re-examine a finding is the
    difference between a security assessment and an opinion.
    """

    investigation_id: NonEmptyStr
    artefact_hashes: tuple[str, ...]
    tool_versions: dict[str, str]
    ruleset_versions: dict[str, str] = Field(default_factory=dict)
    knowledge_versions: dict[str, str] = Field(default_factory=dict)
    model_ids: dict[str, str] = Field(default_factory=dict)
    prompt_template_versions: dict[str, str] = Field(default_factory=dict)
    confidence_formula_version: str | None = None
    policy_version: str | None = None
    sandbox_image_digests: tuple[str, ...] = ()
    cyberre_version: NonEmptyStr

    evidence_set_digest: NonEmptyStr
    finding_set_digest: NonEmptyStr

    def matches(self, other: ReproducibilityManifest) -> bool:
        """Whether two runs produced the same analysis.

        Compares results *and* the inputs that produced them. Identical
        digests from different tool versions is a coincidence worth knowing
        about, not a successful reproduction.
        """
        return (
            self.evidence_set_digest == other.evidence_set_digest
            and self.finding_set_digest == other.finding_set_digest
            and self.tool_versions == other.tool_versions
            and self.artefact_hashes == other.artefact_hashes
        )

    def divergence(self, other: ReproducibilityManifest) -> tuple[str, ...]:
        """Which parts differ, for reporting a failed reproduction."""
        differences: list[str] = []
        if self.artefact_hashes != other.artefact_hashes:
            differences.append("artefact_hashes")
        if self.tool_versions != other.tool_versions:
            differences.append("tool_versions")
        if self.ruleset_versions != other.ruleset_versions:
            differences.append("ruleset_versions")
        if self.knowledge_versions != other.knowledge_versions:
            differences.append("knowledge_versions")
        if self.model_ids != other.model_ids:
            differences.append("model_ids")
        if self.confidence_formula_version != other.confidence_formula_version:
            differences.append("confidence_formula_version")
        if self.evidence_set_digest != other.evidence_set_digest:
            differences.append("evidence")
        if self.finding_set_digest != other.finding_set_digest:
            differences.append("findings")
        return tuple(differences)


def build_manifest(
    *,
    investigation_id: str,
    evidence: Iterable[Evidence],
    findings: Iterable[Finding] = (),
    cyberre_version: str,
    confidence_formula_version: str | None = None,
    policy_version: str | None = None,
) -> ReproducibilityManifest:
    """Derive a manifest from what an investigation actually used.

    Tool and ruleset versions are read out of evidence provenance rather than
    supplied by the caller, so the manifest records what ran, not what was
    believed to have run.
    """
    items = list(evidence)
    results = list(findings)

    tool_versions: dict[str, str] = {}
    ruleset_versions: dict[str, str] = {}
    artefact_hashes: set[str] = set()

    for item in items:
        tool = item.provenance.tool
        tool_versions[tool.tool] = tool.tool_version
        if tool.ruleset_version is not None:
            ruleset_versions[tool.tool] = tool.ruleset_version
        artefact_hashes.add(item.artefact_sha256)

    return ReproducibilityManifest(
        investigation_id=investigation_id,
        artefact_hashes=tuple(sorted(artefact_hashes)),
        tool_versions=dict(sorted(tool_versions.items())),
        ruleset_versions=dict(sorted(ruleset_versions.items())),
        confidence_formula_version=confidence_formula_version,
        policy_version=policy_version,
        cyberre_version=cyberre_version,
        evidence_set_digest=evidence_set_digest(items),
        finding_set_digest=finding_set_digest(results),
    )
