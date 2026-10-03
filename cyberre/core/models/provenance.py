"""Provenance: where a piece of evidence came from, precisely enough to redo it.

Invariant 6 says provenance cannot be lost during normalisation. The way that
is enforced is simply that :class:`Provenance` is a required field of
:class:`~cyberre.core.models.evidence.Evidence` with no default, so evidence
without it cannot be constructed.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, field_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, Sha256, TimestampField


class ToolProvenance(DomainModel):
    """Identity and configuration of whatever produced an observation.

    `tool_version` and `config_hash` are what make a finding re-examinable
    later: "Semgrep found this" is not reproducible, but "Semgrep 1.52.0 with
    ruleset digest abc... found this" is.
    """

    tool: NonEmptyStr
    """Stable tool identifier, e.g. ``ghidra``, ``semgrep``, ``knowledge.re``."""

    tool_version: NonEmptyStr
    """Exact version. ``unknown`` is not acceptable; determine it or fail."""

    config_hash: str | None = None
    """Digest of the tool configuration used, when the tool has one."""

    ruleset_version: str | None = None
    """Ruleset or signature-set version, for scanners that have one."""

    script_version: str | None = None
    """Version of a CyberRE-authored analysis script, e.g. the Ghidra exporter."""

    invocation_id: str | None = None
    """Links back to the recorded tool execution and its raw output."""


class Provenance(DomainModel):
    """The full chain of custody for one observation."""

    tool: ToolProvenance
    artefact_sha256: Sha256
    """Hash of the exact bytes analysed, not of a path that may have changed."""

    collected_at: datetime = TimestampField
    raw_output_ref: str | None = None
    """Object-store key for the unmodified tool output.

    Evidence is a structured summary; this is the receipt. Keeping the raw
    output out of the domain object and behind a reference is what stops the
    investigation state from bloating (see ``InvestigationState``).
    """

    environment: dict[str, str] = Field(default_factory=dict)
    """Reproducibility context - OS, architecture, container digest.

    Deliberately a flat string map: it is recorded and compared, never
    interpreted, so structure would be false precision.
    """

    @field_validator("environment")
    @classmethod
    def _reject_suspicious_environment_keys(cls, value: dict[str, str]) -> dict[str, str]:
        """Keep credentials out of provenance.

        Provenance is written to the database and rendered into reports, so a
        token captured here would be durable and widely copied. The real
        redaction boundary arrives with ``SecretBoundary`` at M4; this is a
        cheap structural guard in the meantime.
        """
        banned = ("key", "token", "secret", "password", "credential")
        offending = sorted(k for k in value if any(b in k.lower() for b in banned))
        if offending:
            raise ValueError(
                f"provenance environment must not carry credential-shaped keys: {offending}"
            )
        return value
