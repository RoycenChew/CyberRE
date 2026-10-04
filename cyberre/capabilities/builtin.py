"""The capabilities this build ships.

Each wraps an adapter behind a typed spec so the planner can rank it, the
policy engine can gate it, and neither has to know how it works.

Two rules hold throughout:

* **An analytical failure is not an exception.** An unsupported
  architecture, a missing tool, a corrupt file - these return a failed
  result the controller turns into a `ToolFailure`. Exceptions are for
  programming errors.
* **A tool that is not installed is reported, not skipped.** "Semgrep is
  not installed" and "Semgrep found nothing" must never look the same, so
  the capability raises `CapabilityUnavailableError` and the investigation
  reports PARTIAL.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from cyberre.adapters.deps import manifests
from cyberre.adapters.ghidra.parser import build_provenance as ghidra_provenance
from cyberre.adapters.ghidra.parser import parse_export
from cyberre.adapters.ghidra.runner import (
    EXPECTED_SCRIPT_VERSION,
    AnalysisConfig,
    ExportCache,
    GhidraAnalysisError,
    GhidraHeadlessRunner,
    GhidraUnavailableError,
    locate_ghidra,
)
from cyberre.adapters.secrets import scanner as secrets
from cyberre.adapters.semgrep.parser import build_provenance as semgrep_provenance
from cyberre.adapters.semgrep.parser import parse_semgrep, ruleset_digest
from cyberre.adapters.semgrep.runner import (
    SemgrepRunner,
    SemgrepScanError,
    SemgrepUnavailableError,
)
from cyberre.core.contracts.capability import (
    CapabilityCost,
    CapabilityResult,
    CapabilitySpec,
)
from cyberre.core.contracts.storage import ObjectStore
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import ArtefactType, EvidenceType, RiskLevel
from cyberre.core.models.provenance import ToolProvenance

SOURCE_TYPES = frozenset({ArtefactType.SOURCE_TREE, ArtefactType.SOURCE_FILE})
BINARY_TYPES = frozenset({ArtefactType.PE, ArtefactType.ELF, ArtefactType.MACHO})


class CapabilityUnavailableError(RuntimeError):
    """The tool this capability needs is not installed.

    Distinct from an analysis failure, and deliberately loud: an
    investigation that silently omitted a scan would report a cleaner
    artefact than was examined.
    """


@dataclass
class CapabilityContext:
    """What a capability needs from the runtime.

    `root` is the path the artefact came from. Artefacts are identified by
    hash, but a tool still has to be pointed at bytes on disk, so the
    runtime carries the mapping rather than putting a path on the artefact.
    """

    investigation_id: str
    root: Path
    object_store: ObjectStore | None = None


# --------------------------------------------------------------- specs

SEMGREP_SPEC = CapabilitySpec(
    capability_id="semgrep.scan",
    name="Semgrep scan",
    description="Pattern and data-flow rules over source, for candidate discovery.",
    artefact_types=SOURCE_TYPES,
    produces=frozenset({EvidenceType.SCANNER_FINDING}),
    cost=CapabilityCost(seconds=45.0),
    # A match means a pattern fired, which is a genuine observation about
    # the code and a weak signal about exploitability.
    reliability=0.7,
    risk_level=RiskLevel.L1_LOCAL_STATIC,
    information_gain_prior=0.8,
    timeout_seconds=900,
)

SECRETS_SPEC = CapabilitySpec(
    capability_id="secrets.scan",
    name="Secret scan",
    description="Credential-shaped values embedded in source.",
    artefact_types=SOURCE_TYPES,
    produces=frozenset({EvidenceType.SECRET_MATCH}),
    cost=CapabilityCost(seconds=5.0),
    reliability=0.75,
    risk_level=RiskLevel.L1_LOCAL_STATIC,
    information_gain_prior=0.6,
)

DEPS_SPEC = CapabilitySpec(
    capability_id="deps.parse_manifests",
    name="Dependency manifests",
    description="What the project declares it depends on, and at what version.",
    artefact_types=frozenset({ArtefactType.SOURCE_TREE, ArtefactType.DEPENDENCY_MANIFEST}),
    produces=frozenset({EvidenceType.DEPENDENCY}),
    cost=CapabilityCost(seconds=2.0),
    # A manifest is an exact record of what was declared. Whether that is
    # what is installed is a different question.
    reliability=0.9,
    risk_level=RiskLevel.L1_LOCAL_STATIC,
    information_gain_prior=0.5,
)

GHIDRA_SPEC = CapabilitySpec(
    capability_id="ghidra.analyze_binary",
    name="Ghidra analysis",
    description="Headless analysis: metadata, sections, imports, functions, call graph.",
    artefact_types=BINARY_TYPES,
    produces=frozenset(
        {
            EvidenceType.BINARY_METADATA,
            EvidenceType.SECTION,
            EvidenceType.IMPORT,
            EvidenceType.FUNCTION,
            EvidenceType.STRING_MATCH,
            EvidenceType.CALL_EDGE,
        }
    ),
    cost=CapabilityCost(seconds=120.0),
    reliability=0.9,
    risk_level=RiskLevel.L1_LOCAL_STATIC,
    information_gain_prior=0.95,
    timeout_seconds=1800,
)

BUILTIN_SPECS: tuple[CapabilitySpec, ...] = (
    SEMGREP_SPEC,
    SECRETS_SPEC,
    DEPS_SPEC,
    GHIDRA_SPEC,
)


# ---------------------------------------------------------- executors


def run_secrets(context: CapabilityContext, artefact: Artefact) -> CapabilityResult:
    target = context.root if context.root.is_dir() else context.root.parent
    evidence, unreadable = secrets.scan_tree(
        target,
        investigation_id=context.investigation_id,
        artefact_id=artefact.artefact_id,
        artefact_sha256=artefact.sha256,
    )
    return CapabilityResult(
        capability_id=SECRETS_SPEC.capability_id,
        evidence=tuple(evidence),
        tool_provenance=ToolProvenance(
            tool=secrets.TOOL_NAME, tool_version=secrets.DETECTOR_VERSION
        ),
        # Unreadable files mean the scan did not see everything, which is
        # partial coverage rather than a clean result.
        partial=bool(unreadable),
    )


def run_dependencies(context: CapabilityContext, artefact: Artefact) -> CapabilityResult:
    target = context.root if context.root.is_dir() else context.root.parent
    evidence, failures = manifests.scan_tree(
        target,
        investigation_id=context.investigation_id,
        artefact_id=artefact.artefact_id,
        artefact_sha256=artefact.sha256,
    )
    return CapabilityResult(
        capability_id=DEPS_SPEC.capability_id,
        evidence=tuple(evidence),
        tool_provenance=ToolProvenance(
            tool=manifests.TOOL_NAME, tool_version=manifests.PARSER_VERSION
        ),
        partial=bool(failures),
    )


def run_semgrep(context: CapabilityContext, artefact: Artefact) -> CapabilityResult:
    try:
        runner = SemgrepRunner()
    except SemgrepUnavailableError as error:
        raise CapabilityUnavailableError(str(error)) from error

    target = context.root if context.root.is_dir() else context.root.parent
    try:
        document = runner.scan(target)
    except SemgrepScanError as error:
        raise CapabilityUnavailableError(f"semgrep scan failed: {error}") from error

    report = parse_semgrep(
        document,
        investigation_id=context.investigation_id,
        artefact_id=artefact.artefact_id,
        artefact_sha256=artefact.sha256,
        provenance=semgrep_provenance(
            semgrep_version=runner.version,
            ruleset_version=runner.config.ruleset,
            ruleset_hash=ruleset_digest([runner.config.ruleset]),
            artefact_sha256=artefact.sha256,
            raw_output_ref=_store(context, document),
        ),
        scope_root=str(target),
    )
    return CapabilityResult(
        capability_id=SEMGREP_SPEC.capability_id,
        evidence=tuple(report.evidence),
        tool_provenance=ToolProvenance(tool="semgrep", tool_version=runner.version),
        partial=report.is_partial,
    )


def run_ghidra(context: CapabilityContext, artefact: Artefact) -> CapabilityResult:
    try:
        installation = locate_ghidra()
    except GhidraUnavailableError as error:
        raise CapabilityUnavailableError(str(error)) from error

    cache = ExportCache(Path(".cyberre") / "ghidra-cache")
    runner = GhidraHeadlessRunner(installation, cache=cache, config=AnalysisConfig())

    try:
        document = runner.analyse(context.root, artefact_sha256=artefact.sha256)
    except GhidraUnavailableError as error:
        raise CapabilityUnavailableError(str(error)) from error
    except GhidraAnalysisError as error:
        # The analysis ran and did not work. Distinct from the tool being
        # absent, and the controller records it as a ToolFailure either way
        # - but the reason reaching the report differs.
        raise CapabilityUnavailableError(f"ghidra analysis failed: {error}") from error

    report = parse_export(
        document,
        investigation_id=context.investigation_id,
        artefact_id=artefact.artefact_id,
        artefact_sha256=artefact.sha256,
        provenance=ghidra_provenance(
            document,
            artefact_sha256=artefact.sha256,
            config_hash=runner.config.digest(),
            raw_output_ref=_store(context, document),
        ),
        expected_script_version=EXPECTED_SCRIPT_VERSION,
    )
    return CapabilityResult(
        capability_id=GHIDRA_SPEC.capability_id,
        evidence=tuple(report.evidence),
        tool_provenance=ToolProvenance(
            tool="ghidra",
            tool_version=installation.version,
            script_version=EXPECTED_SCRIPT_VERSION,
        ),
        partial=report.is_partial,
    )


def _store(context: CapabilityContext, document: object) -> str | None:
    """Keep the raw tool output, so a finding can be re-derived from it."""
    if context.object_store is None:
        return None
    import json

    return context.object_store.put(json.dumps(document).encode("utf-8"))


EXECUTORS = {
    SEMGREP_SPEC.capability_id: run_semgrep,
    SECRETS_SPEC.capability_id: run_secrets,
    DEPS_SPEC.capability_id: run_dependencies,
    GHIDRA_SPEC.capability_id: run_ghidra,
}


class BuiltinExecutor:
    """Dispatches a capability id to its implementation.

    Satisfies the controller's `CapabilityExecutor` protocol. The mapping
    from artefact to the bytes on disk lives here rather than on the
    artefact, which is identified by hash.
    """

    def __init__(
        self,
        *,
        investigation_id: str,
        roots: dict[str, Path],
        object_store: ObjectStore | None = None,
    ) -> None:
        self._investigation_id = investigation_id
        self._roots = roots
        self._object_store = object_store

    def execute(self, capability_id: str, artefact: Artefact) -> CapabilityResult:
        executor = EXECUTORS.get(capability_id)
        if executor is None:
            raise CapabilityUnavailableError(f"no implementation registered for '{capability_id}'")
        root = self._roots.get(artefact.artefact_id)
        if root is None:
            raise CapabilityUnavailableError(
                f"no path on disk is known for artefact {artefact.artefact_id}"
            )
        return executor(
            CapabilityContext(
                investigation_id=self._investigation_id,
                root=root,
                object_store=self._object_store,
            ),
            artefact,
        )


def available_specs(*, include_unavailable: bool = True) -> Sequence[CapabilitySpec]:
    """The specs to register.

    Unavailable tools are registered by default rather than hidden. The
    planner will select them, the executor will report them unavailable,
    and the investigation will say a capability was missing - which is
    more useful than a quietly narrower analysis.
    """
    if include_unavailable:
        return BUILTIN_SPECS
    return tuple(spec for spec in BUILTIN_SPECS if _is_available(spec))


def _is_available(spec: CapabilitySpec) -> bool:
    if spec.capability_id == SEMGREP_SPEC.capability_id:
        import shutil

        return shutil.which("semgrep") is not None
    if spec.capability_id == GHIDRA_SPEC.capability_id:
        try:
            locate_ghidra()
        except GhidraUnavailableError:
            return False
        return True
    return True
