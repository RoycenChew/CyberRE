"""Driving Ghidra headless, and caching what it produced.

Ghidra runs as a subprocess (ADR-004): `analyzeHeadless` imports the binary
into an ephemeral project, analyses it, and runs our export script. Nothing
of Ghidra's object model crosses back - only a JSON document - which is what
keeps Ghidra replaceable.

Analysing a binary is the most expensive thing CyberRE does, so results are
cached on everything that could change them: the bytes, the Ghidra version,
the script version and the analysis configuration. Omit any one of those and
a stale export gets served as though it were current.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cyberre.core.models.base import stable_digest

#: Where the export script lives, relative to this package.
SCRIPT_DIR = Path(__file__).parent / "scripts"
EXPORT_SCRIPT = "CyberREExport.java"

#: Must match SCRIPT_VERSION in the export script. Checked on parse, because
#: a cached document from an older script is not the same evidence.
#: 3.0.0 is the Java port (ADR-023). 1.0.0 was Jython, which Ghidra 12 does
#: not bundle; 2.0.0 was PyGhidra, which headless only enables through a
#: separate launcher with Python and JPype inside Ghidra's process.
EXPECTED_SCRIPT_VERSION = "3.0.0"
EXPECTED_SCHEMA_VERSION = 1


class GhidraUnavailableError(RuntimeError):
    """Ghidra is not installed, or the installation is unusable.

    Distinct from an analysis failure. "We could not look" and "we looked and
    found nothing" must never be confused, and the caller turns this into a
    ToolFailure rather than into evidence.
    """


class GhidraAnalysisError(RuntimeError):
    """Ghidra ran and did not produce a usable export."""


@dataclass(frozen=True)
class AnalysisConfig:
    """Knobs that change what the analysis produces.

    Part of the cache key, so two different configurations do not share a
    cached result.
    """

    timeout_seconds: int = 1800
    analysis_timeout_seconds: int = 1200
    extra_analyzer_options: tuple[str, ...] = ()

    def digest(self) -> str:
        return stable_digest(
            str(self.timeout_seconds),
            str(self.analysis_timeout_seconds),
            "|".join(self.extra_analyzer_options),
        )


@dataclass(frozen=True)
class GhidraInstallation:
    """A located Ghidra installation."""

    root: Path
    version: str

    @property
    def headless(self) -> Path:
        name = "analyzeHeadless.bat" if _is_windows() else "analyzeHeadless"
        return self.root / "support" / name


def _is_windows() -> bool:
    import os

    return os.name == "nt"


def _read_version(root: Path) -> str:
    """Read the Ghidra version from the installation.

    Refuses to guess. The version goes into provenance and into the cache
    key, so an inaccurate one would silently corrupt both.
    """
    properties = root / "Ghidra" / "application.properties"
    if not properties.is_file():
        raise GhidraUnavailableError(
            f"{root} does not look like a Ghidra installation (no Ghidra/application.properties)"
        )
    for line in properties.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*application\.version\s*=\s*(\S+)", line)
        if match:
            return match.group(1)
    raise GhidraUnavailableError(f"{properties} does not declare application.version")


def locate_ghidra(install_dir: Path | str | None = None) -> GhidraInstallation:
    """Find a usable Ghidra installation.

    Args:
        install_dir: An explicit path. When omitted, ``GHIDRA_INSTALL_DIR``
            is used.

    Raises:
        GhidraUnavailableError: if no installation is found or it is
            incomplete. Callers degrade the investigation to PARTIAL rather
            than continuing as though the binary had been analysed.
    """
    import os

    raw = install_dir if install_dir is not None else os.environ.get("GHIDRA_INSTALL_DIR")
    if not raw:
        raise GhidraUnavailableError(
            "GHIDRA_INSTALL_DIR is not set and no installation path was given"
        )

    root = Path(raw)
    if not root.is_dir():
        raise GhidraUnavailableError(f"{root} does not exist")

    installation = GhidraInstallation(root=root, version=_read_version(root))
    if not installation.headless.is_file():
        raise GhidraUnavailableError(
            f"{installation.headless} is missing; the installation is incomplete"
        )
    return installation


def cache_key(*, artefact_sha256: str, ghidra_version: str, config: AnalysisConfig) -> str:
    """Identity of an analysis result.

    Every input that could change the output is included. Dropping any one of
    them would let a stale export be served as current - the quiet kind of
    reproducibility failure, where nothing errors and the answer is wrong.
    """
    return stable_digest(artefact_sha256, ghidra_version, EXPECTED_SCRIPT_VERSION, config.digest())


class ExportCache:
    """Analysis results on disk, keyed by :func:`cache_key`."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def path_for(self, key: str) -> Path:
        return self._root / f"{key}.json"

    def get(self, key: str) -> dict[str, object] | None:
        path = self.path_for(key)
        if not path.is_file():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # A corrupt cache entry is a miss, not a failure: re-analysing is
            # always correct, and refusing to run because a cache file is
            # damaged would be the wrong trade.
            path.unlink(missing_ok=True)
            return None
        return loaded if isinstance(loaded, dict) else None

    def put(self, key: str, document: dict[str, object]) -> None:
        self.path_for(key).write_text(json.dumps(document), encoding="utf-8")


class GhidraHeadlessRunner:
    """Runs `analyzeHeadless` and returns the exported document."""

    def __init__(
        self,
        installation: GhidraInstallation,
        *,
        cache: ExportCache | None = None,
        config: AnalysisConfig | None = None,
    ) -> None:
        self._installation = installation
        self._cache = cache
        self._config = config if config is not None else AnalysisConfig()

    @property
    def version(self) -> str:
        return self._installation.version

    @property
    def config(self) -> AnalysisConfig:
        return self._config

    def analyse(self, binary: Path, *, artefact_sha256: str) -> dict[str, object]:
        """Analyse `binary`, returning the export document.

        Raises:
            GhidraAnalysisError: if the run produced no usable export.
        """
        key = cache_key(
            artefact_sha256=artefact_sha256,
            ghidra_version=self._installation.version,
            config=self._config,
        )
        if self._cache is not None:
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        document = self._run(binary)

        if self._cache is not None:
            self._cache.put(key, document)
        return document

    def _run(self, binary: Path) -> dict[str, object]:
        # An ephemeral project directory per run: Ghidra projects accumulate
        # state, and a reused one would make the analysis depend on what was
        # analysed before it.
        workspace = Path(tempfile.mkdtemp(prefix="cyberre-ghidra-"))
        output = workspace / "export.json"
        # analyzeHeadless takes an existing directory plus a project name;
        # it does not create the directory itself and aborts with
        # "Directory not found" if it is missing. Found by the real-tool
        # tier, which is the kind of thing recorded fixtures cannot catch.
        project_dir = workspace / "project"
        project_dir.mkdir(parents=True, exist_ok=True)
        try:
            command = [
                str(self._installation.headless),
                str(project_dir),
                "cyberre",
                "-import",
                str(binary),
                "-readOnly",
                "-scriptPath",
                str(SCRIPT_DIR),
                "-postScript",
                EXPORT_SCRIPT,
                str(output),
                "-analysisTimeoutPerFile",
                str(self._config.analysis_timeout_seconds),
                "-deleteProject",
                *self._config.extra_analyzer_options,
            ]

            try:
                completed = subprocess.run(  # fixed argv list, shell=False
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self._config.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise GhidraAnalysisError(
                    f"Ghidra timed out after {self._config.timeout_seconds}s on {binary.name}"
                ) from error
            except OSError as error:
                raise GhidraUnavailableError(
                    f"could not execute {self._installation.headless}: {error}"
                ) from error

            if not output.is_file():
                raise GhidraAnalysisError(
                    f"Ghidra produced no export for {binary.name} "
                    f"(exit {completed.returncode}): "
                    f"{_tail(completed.stderr) or _tail(completed.stdout)}"
                )

            try:
                document = json.loads(output.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise GhidraAnalysisError(
                    f"Ghidra export for {binary.name} is not valid JSON: {error}"
                ) from error

            if not isinstance(document, dict):
                raise GhidraAnalysisError("Ghidra export is not a JSON object")
            return document
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


def _tail(text: str | None, lines: int = 10) -> str:
    if not text:
        return ""
    return "\n".join(text.strip().splitlines()[-lines:])
