"""The investigation service: a path in, a report out.

Integration tier - real ingestion, real capabilities, real storage, real
validation. The model is absent or replayed; nothing that decides an
outcome depends on it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.core.models.enums import ArtefactType, Depth, InvestigationStatus
from cyberre.runtime.ingest import ArtefactIngestor, IngestionError, detect_type, hash_tree
from cyberre.runtime.investigation import InvestigationService

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]

VULNERABLE_SOURCE = """
import subprocess

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def ping(host):
    return subprocess.call("ping " + host, shell=True)
"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    app = tmp_path / "app"
    app.mkdir()
    (app / "views.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.25.0\nflask>=2.0\n", encoding="utf-8")
    return tmp_path


class TestIngestion:
    def test_a_directory_is_a_source_tree(self, project: Path) -> None:
        result = ArtefactIngestor().ingest(project)
        assert result.artefacts[0].artefact_type is ArtefactType.SOURCE_TREE

    def test_identity_is_content_not_path(self, tmp_path: Path) -> None:
        """Two copies of the same tree in different places are the same
        artefact, which is what makes a cached analysis safe."""
        for name in ("a", "b"):
            directory = tmp_path / name
            directory.mkdir()
            (directory / "x.py").write_text("print(1)\n", encoding="utf-8")
        assert hash_tree(tmp_path / "a") == hash_tree(tmp_path / "b")

    def test_magic_bytes_beat_the_extension(self, tmp_path: Path) -> None:
        """The extension is attacker-controlled on exactly the artefacts
        where it matters most."""
        disguised = tmp_path / "notes.txt"
        disguised.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
        assert detect_type(disguised) is ArtefactType.PE

    def test_an_unrecognised_file_is_unknown_not_guessed(self, tmp_path: Path) -> None:
        mystery = tmp_path / "blob.dat"
        mystery.write_bytes(b"\x01\x02\x03\x04")
        assert detect_type(mystery) is ArtefactType.UNKNOWN

    def test_a_manifest_is_recognised_by_name(self, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==1.0\n", encoding="utf-8")
        assert detect_type(manifest) is ArtefactType.DEPENDENCY_MANIFEST

    def test_vendored_directories_do_not_change_the_hash(self, tmp_path: Path) -> None:
        """Otherwise the tree hash changes on every dependency install."""
        (tmp_path / "x.py").write_text("print(1)\n", encoding="utf-8")
        before, _ = hash_tree(tmp_path)
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
        after, _ = hash_tree(tmp_path)
        assert before == after

    def test_a_missing_path_is_an_error(self, tmp_path: Path) -> None:
        """A mistyped path that produced no artefacts would look like a
        clean investigation."""
        with pytest.raises(IngestionError, match="does not exist"):
            ArtefactIngestor().ingest(tmp_path / "absent")


class TestTheServiceOffline:
    def test_it_collects_evidence_without_a_model(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(
            project, question="Are there vulnerabilities?", depth=Depth.STANDARD
        )
        assert outcome.evidence, "the deterministic half should still run"

    def test_it_finds_the_embedded_credential(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(
            project, question="Are there secrets?"
        )
        kinds = {e.evidence_type.value for e in outcome.evidence}
        assert "secret_match" in kinds

    def test_it_reads_the_dependency_manifest(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(
            project, question="What does this depend on?"
        )
        kinds = {e.evidence_type.value for e in outcome.evidence}
        assert "dependency" in kinds

    def test_it_selects_the_source_profile(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert [p.value for p in outcome.state.profiles] == ["source_security"]

    def test_it_says_nothing_was_validated(self, project: Path) -> None:
        """The most important caveat on an offline run."""
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert any("nothing was validated" in note for note in outcome.notes)
        assert outcome.report is not None
        assert "nothing was validated" in outcome.report.markdown

    def test_it_produces_no_findings_without_a_model(self, project: Path) -> None:
        """No reasoner means no hypotheses, and no hypotheses means no
        findings. It does not mean the project is clean."""
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert outcome.findings == []
        assert outcome.report is not None
        assert "no hypotheses" in outcome.report.markdown.lower()

    def test_the_secret_is_not_reprinted_in_the_report(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert outcome.report is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in outcome.report.markdown

    def test_a_missing_tool_makes_the_run_partial(self, project: Path) -> None:
        """A tool that could not run must be reported, not skipped.

        Branches on the adapter's own lookup rather than `shutil.which`:
        the adapter also looks beside the interpreter, so a probe that
        disagreed with it would assert the wrong half of this test.
        """
        from cyberre.adapters.semgrep.runner import (
            SemgrepUnavailableError,
            locate_semgrep,
        )

        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")

        try:
            locate_semgrep()
        except SemgrepUnavailableError:
            assert outcome.state.status is InvestigationStatus.PARTIAL
            assert any("semgrep" in note for note in outcome.notes)
        else:
            assert outcome.state.status is InvestigationStatus.COMPLETE

    def test_capabilities_that_ran_are_reported(self, project: Path) -> None:
        """A tool that ran and found nothing must be distinguishable from a
        tool that never ran. The manifest records only tools that produced
        evidence, so the report carries this separately."""
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert outcome.report is not None
        assert "Capabilities run:" in outcome.report.markdown
        assert "secrets.scan" in outcome.report.markdown

    def test_the_manifest_records_what_ran(self, project: Path) -> None:
        outcome = InvestigationService(config_root=ROOT).investigate(project, question="q")
        assert outcome.manifest is not None
        assert "secrets" in outcome.manifest.tool_versions
        assert outcome.manifest.evidence_set_digest

    def test_two_runs_over_the_same_tree_agree(self, project: Path) -> None:
        """Invariant 20 through the whole service, not only the digest."""
        service = InvestigationService(config_root=ROOT)
        first = service.investigate(project, question="q")
        second = service.investigate(project, question="q")
        assert first.manifest is not None and second.manifest is not None
        assert first.manifest.evidence_set_digest == second.manifest.evidence_set_digest
