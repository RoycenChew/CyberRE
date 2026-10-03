"""Live Ghidra. The only tier that proves the integration works.

Written now and **not yet executed** - Ghidra is not installed on the
development machine, and the project says so rather than letting fixture
tests look like proof (ADR-004).

Everything here is skipped unless `GHIDRA_INSTALL_DIR` points at a real
installation. The skip is deliberately loud in the reason string: a silently
skipped tier is indistinguishable from a passing one in a CI summary, and
that is precisely the confusion this tier exists to prevent.

To run:

    export GHIDRA_INSTALL_DIR=/opt/ghidra_11.1.2_PUBLIC
    pytest -m realtool
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cyberre.adapters.ghidra.parser import build_provenance, parse_export
from cyberre.adapters.ghidra.runner import (
    EXPECTED_SCRIPT_VERSION,
    AnalysisConfig,
    ExportCache,
    GhidraHeadlessRunner,
    locate_ghidra,
)
from cyberre.core.models.base import sha256_hex
from cyberre.core.models.enums import EvidenceType

pytestmark = [pytest.mark.realtool, pytest.mark.requires_ghidra]


def _ghidra_or_skip() -> object:
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        pytest.skip(
            "REAL-TOOL TIER NOT RUN: GHIDRA_INSTALL_DIR is unset. Fixture tests "
            "prove the parser only; the Ghidra integration remains unverified."
        )
    return locate_ghidra()


@pytest.fixture(scope="module")
def installation() -> object:
    return _ghidra_or_skip()


@pytest.fixture(scope="module")
def sample_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A small binary compiled here, so no third-party sample is involved.

    Compiled rather than committed: a binary in the repository is a binary
    somebody has to trust, and this one can be rebuilt from two lines of C.
    """
    compiler = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("no C compiler available to build a sample binary")

    directory = tmp_path_factory.mktemp("ghidra-sample")
    source = directory / "sample.c"
    source.write_text(
        "#include <stdio.h>\n"
        "#include <string.h>\n"
        'static void greet(const char *name) { printf("hello %s\\n", name); }\n'
        "int main(int argc, char **argv) {\n"
        "    char buffer[32];\n"
        "    if (argc > 1) { strcpy(buffer, argv[1]); greet(buffer); }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    binary = directory / ("sample.exe" if os.name == "nt" else "sample")
    result = subprocess.run(  # fixed argv list, shell=False
        [compiler, "-O0", "-g", str(source), "-o", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not binary.is_file():
        pytest.skip(f"could not compile the sample binary: {result.stderr.strip()[:200]}")
    return binary


class TestRealGhidraAnalysis:
    def test_headless_analysis_produces_a_parseable_export(
        self, installation: object, sample_binary: Path, tmp_path: Path
    ) -> None:
        """The claim fixtures cannot make: that Ghidra emits what we assume."""
        runner = GhidraHeadlessRunner(
            installation,  # type: ignore[arg-type]
            cache=ExportCache(tmp_path / "cache"),
            config=AnalysisConfig(timeout_seconds=900, analysis_timeout_seconds=600),
        )
        sha = sha256_hex(sample_binary.read_bytes())

        document = runner.analyse(sample_binary, artefact_sha256=sha)

        report = parse_export(
            document,
            investigation_id="inv-real",
            artefact_id="ar-real",
            artefact_sha256=sha,
            provenance=build_provenance(
                document, artefact_sha256=sha, config_hash="real", raw_output_ref=None
            ),
            expected_script_version=EXPECTED_SCRIPT_VERSION,
        )

        assert report.evidence, "a real analysis should produce evidence"

        kinds = {e.evidence_type for e in report.evidence}
        assert EvidenceType.BINARY_METADATA in kinds
        assert EvidenceType.FUNCTION in kinds

        functions = {
            e.observation.name  # type: ignore[union-attr]
            for e in report.evidence
            if e.evidence_type is EvidenceType.FUNCTION
        }
        assert "main" in functions, f"expected 'main' among {sorted(functions)[:20]}"

    def test_the_export_script_version_matches_the_parser(
        self, installation: object, sample_binary: Path, tmp_path: Path
    ) -> None:
        """Catches the script and parser drifting apart - the failure the
        cache key cannot catch, because both sides would be consistent with
        themselves."""
        runner = GhidraHeadlessRunner(installation, cache=ExportCache(tmp_path))  # type: ignore[arg-type]
        document = runner.analyse(
            sample_binary, artefact_sha256=sha256_hex(sample_binary.read_bytes())
        )
        assert document["script_version"] == EXPECTED_SCRIPT_VERSION

    def test_the_reported_version_matches_the_installation(
        self, installation: object, sample_binary: Path, tmp_path: Path
    ) -> None:
        """Provenance records the version we read from disk; this confirms
        Ghidra agrees with it."""
        runner = GhidraHeadlessRunner(installation, cache=ExportCache(tmp_path))  # type: ignore[arg-type]
        document = runner.analyse(
            sample_binary, artefact_sha256=sha256_hex(sample_binary.read_bytes())
        )
        assert str(document["ghidra_version"]).startswith(
            installation.version.split("-")[0]  # type: ignore[attr-defined]
        )

    def test_the_second_run_is_served_from_cache(
        self, installation: object, sample_binary: Path, tmp_path: Path
    ) -> None:
        cache = ExportCache(tmp_path / "cache")
        runner = GhidraHeadlessRunner(installation, cache=cache)  # type: ignore[arg-type]
        sha = sha256_hex(sample_binary.read_bytes())

        first = runner.analyse(sample_binary, artefact_sha256=sha)
        second = runner.analyse(sample_binary, artefact_sha256=sha)
        assert first == second
