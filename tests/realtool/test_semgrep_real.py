"""Live Semgrep.

Skipped unless Semgrep is installed, with a reason that says the integration
is unverified - the same discipline as the Ghidra tier (ADR-004). Parsing
fixtures proves we read Semgrep's output correctly; only this proves Semgrep
emits what we think it does.

To run:

    pip install semgrep
    pytest -m realtool
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from cyberre.adapters.semgrep.parser import build_provenance, parse_semgrep, ruleset_digest
from cyberre.adapters.semgrep.runner import SemgrepConfig, SemgrepRunner, semgrep_version
from cyberre.core.models.enums import EvidenceType

pytestmark = [pytest.mark.realtool, pytest.mark.requires_semgrep]

SHA = "a" * 64


def _semgrep_or_skip() -> str:
    path = shutil.which("semgrep")
    if path is None:
        pytest.skip(
            "REAL-TOOL TIER NOT RUN: semgrep is not installed. Fixture tests "
            "prove the parser only; the Semgrep integration remains unverified."
        )
    return path


@pytest.fixture(scope="module")
def semgrep() -> str:
    return _semgrep_or_skip()


@pytest.fixture
def vulnerable_tree(tmp_path: Path) -> Path:
    """A tiny project with one real issue and one false-positive trap.

    Both matter. The scanner should find the first; the second is here so a
    regression that starts reporting parameterised SQL as injectable is
    caught at the adapter rather than at the reviewer.
    """
    app = tmp_path / "app"
    app.mkdir()
    (app / "views.py").write_text(
        "import subprocess\n"
        "\n"
        "def ping(host):\n"
        "    # genuinely injectable: shell=True with interpolated input\n"
        "    return subprocess.call('ping -c 1 ' + host, shell=True)\n",
        encoding="utf-8",
    )
    (app / "safe.py").write_text(
        "def lookup(cursor, report_id):\n"
        "    # parameterised: looks like SQL construction, is not injectable\n"
        "    cursor.execute('SELECT * FROM report WHERE id = %s', [report_id])\n",
        encoding="utf-8",
    )
    return tmp_path


class TestRealSemgrep:
    def test_the_version_can_be_determined(self, semgrep: str) -> None:
        """It goes into provenance; a wrong version there makes a finding
        unreproducible in a way nothing detects."""
        assert semgrep_version(semgrep)

    def test_a_scan_produces_parseable_output(self, semgrep: str, vulnerable_tree: Path) -> None:
        runner = SemgrepRunner(executable=semgrep, config=SemgrepConfig(ruleset="p/python"))
        document = runner.scan(vulnerable_tree)

        report = parse_semgrep(
            document,
            investigation_id="inv-real",
            artefact_id="ar-real",
            artefact_sha256=SHA,
            provenance=build_provenance(
                semgrep_version=runner.version,
                ruleset_version=runner.config.ruleset,
                ruleset_hash=ruleset_digest([]),
                artefact_sha256=SHA,
                raw_output_ref=None,
            ),
            scope_root=str(vulnerable_tree),
        )

        assert all(e.evidence_type is EvidenceType.SCANNER_FINDING for e in report.evidence)
        assert all(not str(e.location).startswith("/") for e in report.evidence), (
            "locations must be relative to the scope root"
        )

    def test_findings_are_found_in_a_known_vulnerable_file(
        self, semgrep: str, vulnerable_tree: Path
    ) -> None:
        """A recall check. If the ruleset stops firing on shell=True with
        interpolated input, the source slice has quietly lost its teeth."""
        runner = SemgrepRunner(executable=semgrep, config=SemgrepConfig(ruleset="p/python"))
        document = runner.scan(vulnerable_tree)
        report = parse_semgrep(
            document,
            investigation_id="inv-real",
            artefact_id="ar-real",
            artefact_sha256=SHA,
            provenance=build_provenance(
                semgrep_version=runner.version,
                ruleset_version=runner.config.ruleset,
                ruleset_hash=ruleset_digest([]),
                artefact_sha256=SHA,
                raw_output_ref=None,
            ),
            scope_root=str(vulnerable_tree),
        )
        paths = {str(e.location).split(":")[0] for e in report.evidence}
        assert "app/views.py" in paths, (
            f"expected a finding in the injectable file; got {sorted(paths)}"
        )

    def test_a_finding_is_not_the_same_as_a_vulnerability(
        self, semgrep: str, vulnerable_tree: Path
    ) -> None:
        """Whatever Semgrep says about the parameterised query, it arrives as
        a ScannerFinding with middling reliability - never as a conclusion."""
        runner = SemgrepRunner(executable=semgrep, config=SemgrepConfig(ruleset="p/python"))
        document = runner.scan(vulnerable_tree)
        report = parse_semgrep(
            document,
            investigation_id="inv-real",
            artefact_id="ar-real",
            artefact_sha256=SHA,
            provenance=build_provenance(
                semgrep_version=runner.version,
                ruleset_version=runner.config.ruleset,
                ruleset_hash=ruleset_digest([]),
                artefact_sha256=SHA,
                raw_output_ref=None,
            ),
            scope_root=str(vulnerable_tree),
        )
        assert all(e.source_reliability <= 0.75 for e in report.evidence)
