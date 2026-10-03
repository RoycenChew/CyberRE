"""Turning a Ghidra export into evidence.

This is the boundary where Ghidra's view becomes CyberRE's. Everything
crossing it is a typed observation with full provenance, and nothing of
Ghidra's object model crosses at all.

The parser is strict about the document's shape and lenient about individual
records. A malformed document means the contract with the script is broken
and must fail; one unparseable function in fifty thousand should not discard
the other forty-nine thousand, so it is counted and reported instead.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from cyberre.core.models.base import NonEmptyStr
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.location import ArtefactLocation, BinaryLocation, Location
from cyberre.core.models.observation import (
    BinaryMetadata,
    CallEdge,
    FunctionObservation,
    ImportObservation,
    Observation,
    SectionObservation,
    StringMatch,
)
from cyberre.core.models.provenance import Provenance, ToolProvenance

TOOL_NAME = "ghidra"

#: Shapes this parser understands. A document from a newer script may contain
#: fields we would silently ignore, which is how a capability quietly stops
#: collecting something.
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})


class GhidraExportError(ValueError):
    """The export document does not match the contract with the script."""


@dataclass
class ParseReport:
    """What came out, and what did not.

    `skipped` exists because silence about discarded records is how coverage
    gaps become invisible. A capability result carries it forward as
    `partial`.
    """

    evidence: list[Evidence] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    truncated: dict[str, bool] = field(default_factory=dict)

    def skip(self, kind: str) -> None:
        self.skipped[kind] = self.skipped.get(kind, 0) + 1

    @property
    def is_partial(self) -> bool:
        return bool(self.skipped) or any(self.truncated.values())


def _require(document: dict[str, Any], key: str) -> Any:
    if key not in document:
        raise GhidraExportError(f"export is missing required key '{key}'")
    return document[key]


def validate_document(document: dict[str, Any], *, expected_script_version: str) -> None:
    """Check the document against the contract before parsing anything.

    The script version is checked, not merely recorded: a cached export from
    an older script describes a different analysis, and serving it as current
    is exactly the reproducibility failure the cache key exists to prevent.
    """
    schema_version = _require(document, "schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise GhidraExportError(
            f"export schema version {schema_version} is not supported "
            f"(this parser understands {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )

    script_version = _require(document, "script_version")
    if script_version != expected_script_version:
        raise GhidraExportError(
            f"export was produced by script version {script_version}, but this "
            f"parser expects {expected_script_version}; the cache key should have "
            f"prevented this, so treat it as a bug rather than re-parsing"
        )

    for key in ("ghidra_version", "binary"):
        _require(document, key)


def build_provenance(
    document: dict[str, Any],
    *,
    artefact_sha256: str,
    config_hash: str,
    raw_output_ref: str | None,
    invocation_id: str | None = None,
) -> Provenance:
    """Provenance for everything in one export.

    Records the Ghidra version and the script version separately: an upgrade
    to either changes what the analysis found, and a finding should be
    re-examinable against both.
    """
    return Provenance(
        tool=ToolProvenance(
            tool=TOOL_NAME,
            tool_version=str(document["ghidra_version"]),
            script_version=str(document["script_version"]),
            config_hash=config_hash,
            invocation_id=invocation_id,
        ),
        artefact_sha256=artefact_sha256,
        raw_output_ref=raw_output_ref,
    )


def _evidence(
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    evidence_type: EvidenceType,
    observation: Observation,
    location: Location,
    provenance: Provenance,
    reliability: float,
) -> Evidence:
    return Evidence(
        investigation_id=investigation_id,
        artefact_id=artefact_id,
        artefact_sha256=artefact_sha256,
        evidence_type=evidence_type,
        observation=observation,
        location=location,
        provenance=provenance,
        independence_key=derive_independence_key(
            TOOL_NAME, artefact_sha256, str(location), observation.kind
        ),
        source_reliability=reliability,
    )


#: How much to trust each kind of observation from Ghidra. Structural facts -
#: sections, imports, function boundaries - are close to certain. Call edges
#: are weaker: indirect calls, dynamically resolved imports and obfuscated
#: control flow all produce call graphs that are incomplete rather than wrong,
#: and a validation engine treating them as certain would over-conclude from
#: an absent edge.
RELIABILITY = {
    EvidenceType.BINARY_METADATA: 0.95,
    EvidenceType.SECTION: 0.95,
    EvidenceType.IMPORT: 0.9,
    EvidenceType.FUNCTION: 0.9,
    EvidenceType.STRING_MATCH: 0.9,
    EvidenceType.CALL_EDGE: 0.75,
}


def parse_export(
    document: dict[str, Any],
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    provenance: Provenance,
    expected_script_version: str,
) -> ParseReport:
    """Convert an export document into evidence."""
    validate_document(document, expected_script_version=expected_script_version)

    report = ParseReport()
    raw_truncated = document.get("truncated")
    if isinstance(raw_truncated, dict):
        report.truncated = {str(k): bool(v) for k, v in raw_truncated.items()}
    if document.get("cancelled"):
        report.truncated["analysis"] = True

    def emit(evidence_type: EvidenceType, observation: Observation, location: Location) -> None:
        report.evidence.append(
            _evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=evidence_type,
                observation=observation,
                location=location,
                provenance=provenance,
                reliability=RELIABILITY.get(evidence_type, 0.8),
            )
        )

    for evidence_type, observation, location in _observations(document, report):
        emit(evidence_type, observation, location)

    return report


def _observations(
    document: dict[str, Any], report: ParseReport
) -> Iterator[tuple[EvidenceType, Observation, Location]]:
    binary = document["binary"]
    if not isinstance(binary, dict):
        raise GhidraExportError("'binary' must be an object")

    try:
        yield (
            EvidenceType.BINARY_METADATA,
            BinaryMetadata(
                format=_text(binary.get("format"), "unknown"),
                architecture=_text(binary.get("architecture"), "unknown"),
                bits=int(binary.get("bits") or 32),
                endianness="big" if binary.get("endianness") == "big" else "little",
                entry_point=_optional_int(binary.get("entry_point")),
                compiler=_optional_text(binary.get("compiler")),
            ),
            ArtefactLocation(detail="binary metadata"),
        )
    except (TypeError, ValueError) as error:
        # Metadata is the one record whose loss makes the rest hard to
        # interpret, so it is an error rather than a skip.
        raise GhidraExportError(f"binary metadata is malformed: {error}") from error

    for section in _records(document, "sections", report):
        name = _optional_text(section.get("name"))
        if name is None:
            report.skip("sections")
            continue
        yield (
            EvidenceType.SECTION,
            SectionObservation(
                name=name,
                virtual_size=max(0, int(section.get("virtual_size") or 0)),
                raw_size=max(0, int(section.get("raw_size") or 0)),
                executable=bool(section.get("executable")),
                writable=bool(section.get("writable")),
            ),
            BinaryLocation(address=int(section.get("start") or 0), section=name),
        )

    for item in _records(document, "imports", report):
        symbol = _optional_text(item.get("symbol"))
        if symbol is None:
            report.skip("imports")
            continue
        yield (
            EvidenceType.IMPORT,
            ImportObservation(library=_optional_text(item.get("library")), symbol=symbol),
            BinaryLocation(address=int(item.get("address") or 0), function=symbol),
        )

    for item in _records(document, "functions", report):
        name = _optional_text(item.get("name"))
        if name is None:
            report.skip("functions")
            continue
        yield (
            EvidenceType.FUNCTION,
            FunctionObservation(
                name=name,
                size=_optional_int(item.get("size")),
                is_thunk=bool(item.get("is_thunk")),
                is_library=bool(item.get("is_external")),
            ),
            BinaryLocation(address=int(item.get("address") or 0), function=name),
        )

    for item in _records(document, "strings", report):
        value = _optional_text(item.get("value"))
        if value is None:
            report.skip("strings")
            continue
        encoding = item.get("encoding")
        yield (
            EvidenceType.STRING_MATCH,
            StringMatch(
                value=value,
                encoding=encoding if encoding in {"ascii", "utf-8", "utf-16"} else "ascii",
                # Strings come out of the artefact, so they are untrusted and
                # must be fenced before they go anywhere near a model.
                is_untrusted_content=True,
            ),
            BinaryLocation(address=int(item.get("address") or 0)),
        )

    for item in _records(document, "call_edges", report):
        caller = _optional_text(item.get("caller"))
        callee = _optional_text(item.get("callee"))
        if caller is None or callee is None:
            report.skip("call_edges")
            continue
        yield (
            EvidenceType.CALL_EDGE,
            CallEdge(caller=caller, callee=callee, call_site=_optional_int(item.get("call_site"))),
            BinaryLocation(address=int(item.get("call_site") or 0), function=caller),
        )


def _records(document: dict[str, Any], key: str, report: ParseReport) -> Iterator[dict[str, Any]]:
    raw = document.get(key, [])
    if not isinstance(raw, list):
        raise GhidraExportError(f"'{key}' must be a list")
    for item in raw:
        if isinstance(item, dict):
            yield item
        else:
            report.skip(key)


def _text(value: object, default: str) -> NonEmptyStr:
    text = str(value).strip() if value is not None else ""
    return text or default


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int | str | float):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None
