"""Artefact ingestion: a path on disk becomes an identified artefact.

Identity is the content hash, never the path (M1). A path can change under
us, two paths can hold the same bytes, and a report that identifies its
subject by filename cannot be checked later.

Type detection reads magic bytes before it trusts an extension, because the
extension is attacker-controlled on exactly the artefacts where it matters
most. An unrecognised file is `UNKNOWN` rather than guessed: a wrong type
selects the wrong profile and the wrong capabilities, which fails quietly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from cyberre.core.contracts.storage import ObjectStore
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import ArtefactType

#: Magic signatures, checked before any extension.
MAGIC: tuple[tuple[bytes, ArtefactType], ...] = (
    (b"MZ", ArtefactType.PE),
    (b"\x7fELF", ArtefactType.ELF),
    (b"\xfe\xed\xfa\xce", ArtefactType.MACHO),
    (b"\xfe\xed\xfa\xcf", ArtefactType.MACHO),
    (b"\xce\xfa\xed\xfe", ArtefactType.MACHO),
    (b"\xcf\xfa\xed\xfe", ArtefactType.MACHO),
    (b"\xca\xfe\xba\xbe", ArtefactType.MACHO),
    (b"PK\x03\x04", ArtefactType.ARCHIVE),
    (b"\x1f\x8b", ArtefactType.ARCHIVE),
    (b"%PDF-", ArtefactType.DOCUMENT),
)

#: Filenames that identify a dependency manifest regardless of extension.
MANIFEST_NAMES = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "go.mod",
        "Cargo.toml",
        "pom.xml",
        "build.gradle",
    }
)

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".cs",
        ".rs",
        ".kt",
        ".swift",
        ".scala",
        ".sh",
        ".ps1",
        ".sql",
    }
)

CONFIG_SUFFIXES = frozenset({".yaml", ".yml", ".ini", ".cfg", ".conf", ".env", ".toml"})

#: Read enough to match the longest signature and no more.
MAGIC_BYTES = 16

#: Files above this are hashed in chunks rather than read whole. A binary
#: large enough to matter is large enough to exhaust memory if read naively.
CHUNK_SIZE = 1024 * 1024


class IngestionError(ValueError):
    """The path cannot be ingested.

    An error rather than an empty result: a mistyped path that silently
    produced no artefacts would look like a clean investigation.
    """


def detect_type(path: Path) -> ArtefactType:
    """Identify what a file is.

    Magic bytes first. The extension is only consulted when the content
    does not identify itself, because on a hostile artefact the extension
    is whatever the author chose.
    """
    if path.is_dir():
        return ArtefactType.SOURCE_TREE

    try:
        with path.open("rb") as handle:
            head = handle.read(MAGIC_BYTES)
    except OSError as error:
        raise IngestionError(f"{path}: cannot be read: {error}") from error

    for signature, artefact_type in MAGIC:
        if head.startswith(signature):
            return artefact_type

    if path.name in MANIFEST_NAMES:
        return ArtefactType.DEPENDENCY_MANIFEST

    suffix = path.suffix.lower()
    if suffix in SOURCE_SUFFIXES:
        return ArtefactType.SOURCE_FILE
    if suffix in CONFIG_SUFFIXES:
        return ArtefactType.CONFIGURATION

    return ArtefactType.UNKNOWN


def hash_file(path: Path) -> tuple[str, int]:
    """SHA-256 and size, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise IngestionError(f"{path}: cannot be read: {error}") from error
    return digest.hexdigest(), size


#: Directories never descended into when hashing a tree. Vendored and
#: generated content is not what the investigation is about, and including
#: it would make the tree hash change on every dependency install.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    }
)


def iter_tree(root: Path) -> Iterator[Path]:
    """Files in a tree worth considering, deterministically ordered."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def hash_tree(root: Path) -> tuple[str, int]:
    """A content hash for a directory.

    Over relative paths and per-file digests, so the same tree in a
    different location hashes the same - which is what makes a cached
    analysis and a replayed investigation agree across machines.
    """
    digest = hashlib.sha256()
    total = 0
    for path in iter_tree(root):
        file_digest, size = hash_file(path)
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        total += size
    return digest.hexdigest(), total


@dataclass
class IngestionResult:
    artefacts: list[Artefact] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def artefact_types(self) -> set[ArtefactType]:
        return {artefact.artefact_type for artefact in self.artefacts}


class ArtefactIngestor:
    """Turns paths into artefacts, storing bytes where appropriate."""

    def __init__(self, object_store: ObjectStore | None = None) -> None:
        self._object_store = object_store

    def ingest(self, path: Path) -> IngestionResult:
        """Ingest one path, which may be a file or a directory."""
        resolved = Path(path).expanduser()
        if not resolved.exists():
            raise IngestionError(f"{resolved} does not exist")

        result = IngestionResult()
        if resolved.is_dir():
            result.artefacts.append(self._ingest_tree(resolved))
        else:
            result.artefacts.append(self._ingest_file(resolved))
        return result

    def _ingest_tree(self, root: Path) -> Artefact:
        sha256, size = hash_tree(root)
        return Artefact(
            sha256=sha256,
            size_bytes=size,
            artefact_type=ArtefactType.SOURCE_TREE,
            display_name=root.name or str(root),
            # A tree is analysed in place; storing it as one blob would
            # make per-file provenance impossible (the model refuses it).
            object_store_ref=None,
        )

    def _ingest_file(self, path: Path) -> Artefact:
        sha256, size = hash_file(path)
        artefact_type = detect_type(path)

        reference: str | None = None
        if self._object_store is not None and artefact_type in {
            ArtefactType.PE,
            ArtefactType.ELF,
            ArtefactType.MACHO,
            ArtefactType.ARCHIVE,
            ArtefactType.DOCUMENT,
        }:
            # Binaries are retained so a finding can be re-examined against
            # the exact bytes. Source files are not: they are usually under
            # version control already, and copying a customer's source into
            # an object store is a data-handling decision nobody asked for.
            reference = self._object_store.put(path.read_bytes())

        return Artefact(
            sha256=sha256,
            size_bytes=size,
            artefact_type=artefact_type,
            display_name=path.name,
            object_store_ref=reference,
        )
