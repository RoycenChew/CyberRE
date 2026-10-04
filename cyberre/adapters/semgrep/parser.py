"""Turning Semgrep output into evidence.

Semgrep is a candidate-discovery tool. A match means a pattern fired, not
that a vulnerability exists, and this parser is careful to carry it across
the boundary as exactly that: a `ScannerFinding` observation, which satisfies
*one* requirement in a validation set - usually the sink - and never the
whole of one.

Semgrep's own severity is recorded and not adopted. CyberRE derives severity
from validated evidence, and importing a scanner's rating would smuggle an
unvalidated judgement into the finding.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from cyberre.core.models.base import stable_digest
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.location import SourceLocation
from cyberre.core.models.observation import ScannerFinding
from cyberre.core.models.provenance import Provenance, ToolProvenance

TOOL_NAME = "semgrep"

#: Semgrep output is stable in the fields we use, but the top-level shape has
#: changed between major versions. Checked rather than assumed.
REQUIRED_KEYS = ("results",)

#: How much to trust a Semgrep match. Deliberately middling: a pattern match
#: is a genuine observation about the code and a weak signal about whether
#: anything is exploitable.
RELIABILITY = 0.7


class SemgrepOutputError(ValueError):
    """The output does not have the shape this parser understands."""


@dataclass
class SemgrepReport:
    """Parsed results, plus what Semgrep could not do.

    Semgrep reports per-file errors inline and still exits zero. Treating
    that as a clean scan would mean a parse failure in the one interesting
    file reads as "no findings".
    """

    evidence: list[Evidence] = field(default_factory=list)
    scan_errors: list[str] = field(default_factory=list)
    skipped: int = 0
    files_scanned: int = 0

    @property
    def is_partial(self) -> bool:
        return bool(self.scan_errors) or self.skipped > 0


def ruleset_digest(rule_ids: list[str]) -> str:
    """A digest over the rules that actually fired or were configured.

    Recorded in provenance so a finding can be re-examined against the same
    ruleset. "Semgrep found this" is not reproducible; "Semgrep 1.52.0 with
    ruleset digest abc... found this" is.
    """
    return stable_digest(*sorted(set(rule_ids)))[:16]


def build_provenance(
    *,
    semgrep_version: str,
    ruleset_version: str,
    ruleset_hash: str,
    artefact_sha256: str,
    raw_output_ref: str | None,
    invocation_id: str | None = None,
) -> Provenance:
    return Provenance(
        tool=ToolProvenance(
            tool=TOOL_NAME,
            tool_version=semgrep_version,
            ruleset_version=ruleset_version,
            config_hash=ruleset_hash,
            invocation_id=invocation_id,
        ),
        artefact_sha256=artefact_sha256,
        raw_output_ref=raw_output_ref,
    )


def _relative(path: str, scope_root: str | None) -> str:
    """Make a path relative to the scope root.

    An absolute path leaks the analyst's filesystem into a report and makes
    the evidence digest machine-specific, which would break replay across
    machines.
    """
    text = path.replace("\\", "/")
    if scope_root:
        root = scope_root.replace("\\", "/").rstrip("/")
        if text.startswith(root + "/"):
            text = text[len(root) + 1 :]
    return str(PurePosixPath(text))


def _metadata_list(extra: dict[str, Any], key: str) -> tuple[str, ...]:
    metadata = extra.get("metadata")
    if not isinstance(metadata, dict):
        return ()
    value = metadata.get(key)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def _results(document: dict[str, Any]) -> Iterator[dict[str, Any]]:
    raw = document.get("results", [])
    if not isinstance(raw, list):
        raise SemgrepOutputError("'results' must be a list")
    for item in raw:
        if isinstance(item, dict):
            yield item


def parse_semgrep(
    document: dict[str, Any],
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    provenance: Provenance,
    scope_root: str | None = None,
) -> SemgrepReport:
    """Convert Semgrep JSON output into evidence."""
    for key in REQUIRED_KEYS:
        if key not in document:
            raise SemgrepOutputError(f"output is missing required key '{key}'")

    report = SemgrepReport()

    errors = document.get("errors", [])
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                report.scan_errors.append(
                    str(error.get("message") or error.get("type") or "unknown error")
                )
            else:
                report.scan_errors.append(str(error))

    paths = document.get("paths")
    if isinstance(paths, dict):
        scanned = paths.get("scanned")
        if isinstance(scanned, list):
            report.files_scanned = len(scanned)
        skipped = paths.get("skipped")
        if isinstance(skipped, list):
            report.skipped = len(skipped)

    for result in _results(document):
        rule_id = result.get("check_id")
        path = result.get("path")
        raw_extra = result.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        message = extra.get("message")

        if not rule_id or not path or not message:
            report.skipped += 1
            continue

        raw_start = result.get("start")
        raw_end = result.get("end")
        start: dict[str, Any] = raw_start if isinstance(raw_start, dict) else {}
        end: dict[str, Any] = raw_end if isinstance(raw_end, dict) else {}
        start_line = int(start.get("line", 1) or 1)
        end_line_raw = end.get("line")
        end_line = int(end_line_raw) if end_line_raw else None

        location = SourceLocation(
            path=_relative(str(path), scope_root),
            start_line=max(1, start_line),
            # Only a genuine span. Semgrep reports end == start for a
            # single-line match, and rendering that as "42-42" is noise in a
            # report - and, because the location string feeds the
            # independence key, an avoidable source of churn.
            end_line=end_line if end_line and end_line > start_line else None,
        )

        observation = ScannerFinding(
            rule_id=str(rule_id),
            message=str(message),
            # Recorded, never adopted. Importing a scanner's rating would
            # smuggle an unvalidated judgement into the finding.
            severity_reported=str(extra.get("severity")) if extra.get("severity") else None,
            cwe=_metadata_list(extra, "cwe"),
        )

        report.evidence.append(
            Evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=EvidenceType.SCANNER_FINDING,
                observation=observation,
                location=location,
                provenance=provenance,
                independence_key=derive_independence_key(
                    TOOL_NAME, artefact_sha256, str(location), observation.kind
                ),
                source_reliability=RELIABILITY,
            )
        )

    return report
