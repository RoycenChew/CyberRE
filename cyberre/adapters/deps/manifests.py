"""Reading dependency manifests.

Produces `DependencyObservation` evidence: what is declared, at what version,
and whether it is a direct dependency. That is all. Deciding whether a
declared package is *affected* by a known vulnerability is validation's job
and needs product match, version-in-range and configuration conditions as
separate requirements - a package name matching an advisory means almost
nothing on its own.

Pinned and unpinned dependencies are distinguished rather than normalised,
because an unpinned dependency cannot be matched against an advisory at all,
and recording that as "version unknown" is honest where guessing is not.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.location import PackageLocation
from cyberre.core.models.observation import DependencyObservation
from cyberre.core.models.provenance import Provenance, ToolProvenance

TOOL_NAME = "deps"
PARSER_VERSION = "1.0.0"

#: Only an exact pin can be matched against an advisory range with
#: confidence. A range or a caret is recorded with no version rather than
#: with its lower bound, because resolving it requires the lock file.
_PINNED = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*==\s*([^\s;#]+)")
_UNPINNED = re.compile(r"^\s*([A-Za-z0-9._\-]+)\s*(?:[<>!~^]=?|$)")


@dataclass(frozen=True)
class DeclaredDependency:
    ecosystem: str
    name: str
    version: str | None
    direct: bool
    manifest_path: str


class ManifestParseError(ValueError):
    """A manifest could not be read.

    An error rather than an empty result: silently treating an unparseable
    manifest as "no dependencies" would report an unscanned project as clean.
    """


def parse_requirements_txt(text: str, *, manifest_path: str) -> list[DeclaredDependency]:
    """Parse a pip requirements file."""
    found: list[DeclaredDependency] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            # Options and -r includes. Includes are not followed here; the
            # caller walks the tree and will meet the referenced file itself.
            continue

        pinned = _PINNED.match(line)
        if pinned:
            found.append(
                DeclaredDependency(
                    ecosystem="pypi",
                    name=pinned.group(1).lower(),
                    version=pinned.group(2),
                    direct=True,
                    manifest_path=manifest_path,
                )
            )
            continue

        unpinned = _UNPINNED.match(line)
        if unpinned:
            found.append(
                DeclaredDependency(
                    ecosystem="pypi",
                    name=unpinned.group(1).lower(),
                    version=None,
                    direct=True,
                    manifest_path=manifest_path,
                )
            )
    return found


def parse_pyproject(text: str, *, manifest_path: str) -> list[DeclaredDependency]:
    """Parse PEP 621 dependencies from pyproject.toml."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ManifestParseError(f"{manifest_path}: not valid TOML: {error}") from error

    project = document.get("project")
    if not isinstance(project, dict):
        return []

    specs: list[str] = []
    declared = project.get("dependencies")
    if isinstance(declared, list):
        specs.extend(str(item) for item in declared)

    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                specs.extend(str(item) for item in group)

    found: list[DeclaredDependency] = []
    for spec in specs:
        base = spec.split(";", 1)[0].split("[", 1)[0].strip()
        pinned = _PINNED.match(base)
        unpinned = _UNPINNED.match(base)
        if pinned:
            found.append(
                DeclaredDependency(
                    "pypi", pinned.group(1).lower(), pinned.group(2), True, manifest_path
                )
            )
        elif unpinned:
            found.append(
                DeclaredDependency("pypi", unpinned.group(1).lower(), None, True, manifest_path)
            )
    return found


def parse_package_json(text: str, *, manifest_path: str) -> list[DeclaredDependency]:
    """Parse an npm package.json."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ManifestParseError(f"{manifest_path}: not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise ManifestParseError(f"{manifest_path}: not a JSON object")

    found: list[DeclaredDependency] = []
    for section in ("dependencies", "devDependencies"):
        block = document.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in sorted(block.items()):
            text_spec = str(spec).strip()
            # Only an exact version is a pin. "^1.2.3" permits 1.9.0, so
            # recording 1.2.3 would invite an advisory match against a
            # version that may not be installed.
            exact = re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?", text_spec)
            found.append(
                DeclaredDependency(
                    ecosystem="npm",
                    name=str(name),
                    version=text_spec if exact else None,
                    direct=True,
                    manifest_path=manifest_path,
                )
            )
    return found


def parse_package_lock(text: str, *, manifest_path: str) -> list[DeclaredDependency]:
    """Parse an npm lock file, which does carry resolved versions."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as error:
        raise ManifestParseError(f"{manifest_path}: not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise ManifestParseError(f"{manifest_path}: not a JSON object")

    found: list[DeclaredDependency] = []
    packages = document.get("packages")
    if isinstance(packages, dict):
        for path, entry in sorted(packages.items()):
            if not path or not isinstance(entry, dict):
                continue  # the empty key is the root project itself
            name = str(entry.get("name") or path.rsplit("node_modules/", 1)[-1])
            version = entry.get("version")
            found.append(
                DeclaredDependency(
                    ecosystem="npm",
                    name=name,
                    version=str(version) if version else None,
                    # A lock file lists the resolved tree, most of which is
                    # transitive. Direct dependencies come from package.json.
                    direct=False,
                    manifest_path=manifest_path,
                )
            )
    return found


#: Filename to parser. Lock files are listed because they carry resolved
#: versions, which is the only form an advisory can be matched against
#: reliably.
PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
}


def discover_manifests(root: Path) -> Iterator[Path]:
    """Manifests under `root`, deterministically ordered."""
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in PARSERS:
            continue
        if any(part in {"node_modules", ".venv", "venv", ".git"} for part in path.parts):
            continue
        yield path


def build_provenance(*, artefact_sha256: str, raw_output_ref: str | None = None) -> Provenance:
    return Provenance(
        tool=ToolProvenance(
            tool=TOOL_NAME,
            tool_version=PARSER_VERSION,
        ),
        artefact_sha256=artefact_sha256,
        raw_output_ref=raw_output_ref,
    )


def to_evidence(
    dependencies: list[DeclaredDependency],
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    provenance: Provenance,
) -> list[Evidence]:
    evidence: list[Evidence] = []
    for dependency in dependencies:
        location = PackageLocation(
            ecosystem=dependency.ecosystem,
            name=dependency.name,
            version=dependency.version,
            manifest_path=dependency.manifest_path,
        )
        observation = DependencyObservation(
            ecosystem=dependency.ecosystem,
            name=dependency.name,
            version=dependency.version,
            direct=dependency.direct,
        )
        evidence.append(
            Evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=EvidenceType.DEPENDENCY,
                observation=observation,
                location=location,
                provenance=provenance,
                independence_key=derive_independence_key(
                    TOOL_NAME, artefact_sha256, str(location), observation.kind
                ),
                # A manifest is an exact record of what was declared, so the
                # observation is reliable. Whether what was declared is what
                # is installed is a different question.
                source_reliability=0.9,
            )
        )
    return evidence


def scan_tree(
    root: Path,
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
) -> tuple[list[Evidence], list[str]]:
    """Parse every manifest under `root`.

    Returns evidence and a list of manifests that failed to parse, so an
    unreadable manifest is reported rather than counting as no dependencies.
    """
    provenance = build_provenance(artefact_sha256=artefact_sha256)
    dependencies: list[DeclaredDependency] = []
    failures: list[str] = []

    for path in discover_manifests(root):
        relative = path.relative_to(root).as_posix()
        parser = PARSERS[path.name]
        try:
            dependencies.extend(parser(path.read_text(encoding="utf-8"), manifest_path=relative))
        except (ManifestParseError, OSError, UnicodeDecodeError) as error:
            failures.append(f"{relative}: {error}")

    return (
        to_evidence(
            dependencies,
            investigation_id=investigation_id,
            artefact_id=artefact_id,
            artefact_sha256=artefact_sha256,
            provenance=provenance,
        ),
        failures,
    )
