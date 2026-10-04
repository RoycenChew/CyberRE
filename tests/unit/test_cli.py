"""The CLI.

Thin by design, so these tests mostly check that it reports honestly: that
it lists what does not work alongside what does, that a partial run is
distinguishable from a clean one, and that a secret it finds is not a
secret it prints.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.cli.main import EXIT_OK, EXIT_PARTIAL, EXIT_USAGE, main

pytestmark = pytest.mark.unit

ROOT = str(Path(__file__).resolve().parents[2])

#: A file with one genuine issue and one embedded credential, so an
#: investigation over it has something real to find.
VULNERABLE_SOURCE = """
import subprocess

KEY = "AKIAIOSFODNN7EXAMPLE"


def ping(host):
    return subprocess.call("ping " + host, shell=True)
"""

TRIVIAL_SOURCE = "x = 1\n"


def run(*args: str) -> int:
    return main(["--root", ROOT, *args])


class TestCapabilities:
    def test_it_lists_profiles_and_requirement_sets(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run("capabilities") == EXIT_OK
        out = capsys.readouterr().out
        assert "binary_re" in out
        assert "req.cwe.78" in out
        assert "Knowledge records:" in out

    def test_it_lists_the_shipped_capabilities(self, capsys: pytest.CaptureFixture[str]) -> None:
        run("capabilities")
        out = capsys.readouterr().out
        assert "semgrep.scan" in out
        assert "ghidra.analyze_binary" in out

    def test_it_names_what_is_not_implemented(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A tool that lists only its working features leaves the reader to
        find the gaps by hitting them."""
        run("capabilities")
        out = capsys.readouterr().out
        assert "NOT IMPLEMENTED" in out
        assert "threat_hunting" in out


class TestProfiles:
    def test_a_binary_selects_reverse_engineering(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run("profiles", "pe") == EXIT_OK
        assert "binary_re" in capsys.readouterr().out

    def test_a_source_tree_selects_source_security(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        run("profiles", "source_tree")
        assert "source_security" in capsys.readouterr().out

    def test_an_unknown_artefact_type_is_a_usage_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert run("profiles", "nonsense") == EXIT_USAGE
        assert "unknown artefact type" in capsys.readouterr().err


class TestKnowledge:
    def test_an_api_lookup_shows_the_record(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run("knowledge", "VirtualAllocEx") == EXIT_OK
        out = capsys.readouterr().out
        assert "win.api.VirtualAllocEx" in out
        assert "Microsoft Learn" in out

    def test_the_innocent_reading_is_shown_by_default(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Most uses of most dangerous APIs are legitimate; a lookup that
        omits that is misleading."""
        run("knowledge", "VirtualAllocEx")
        assert "innocent reading" in capsys.readouterr().out

    def test_the_companions_are_shown(self, capsys: pytest.CaptureFixture[str]) -> None:
        """They are why one import is not a finding."""
        run("knowledge", "CreateRemoteThread")
        assert "companions" in capsys.readouterr().out

    def test_a_miss_suggests_rather_than_guessing(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run("knowledge", "injection") == EXIT_OK
        out = capsys.readouterr().out
        assert "no exact match" in out or "no record" in out

    def test_an_unknown_term_is_not_an_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run("knowledge", "ZzzNotARealApi") == EXIT_OK
        capsys.readouterr()


class TestInvestigate:
    def test_a_missing_path_is_a_usage_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert run("investigate", "find vulns") == EXIT_USAGE
        assert "nothing to investigate" in capsys.readouterr().err

    def test_a_nonexistent_path_is_a_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A mistyped path must not look like a clean investigation."""
        assert (
            run("investigate", "q", "--path", str(tmp_path / "absent"), "--offline") == EXIT_USAGE
        )
        assert "cannot ingest" in capsys.readouterr().err

    def test_it_investigates_a_source_tree(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        app = tmp_path / "app"
        app.mkdir()
        (app / "views.py").write_text(VULNERABLE_SOURCE, encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")

        code = run("investigate", "q", "--path", str(tmp_path), "--offline")
        out = capsys.readouterr().out

        assert code in {EXIT_OK, EXIT_PARTIAL}
        assert "# Investigation" in out
        assert "## Reproducibility" in out

    def test_offline_says_nothing_was_validated(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Running without a model must not look like a clean result."""
        (tmp_path / "app.py").write_text(TRIVIAL_SOURCE, encoding="utf-8")
        run("investigate", "q", "--path", str(tmp_path), "--offline")
        assert "nothing was validated" in capsys.readouterr().out

    def test_a_partial_run_exits_non_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Absence of a finding in a partial run is not evidence of absence,
        and a green exit code would tell a pipeline otherwise."""
        (tmp_path / "app.py").write_text(TRIVIAL_SOURCE, encoding="utf-8")
        code = run("investigate", "q", "--path", str(tmp_path), "--offline")
        capsys.readouterr()
        assert code == EXIT_PARTIAL

    def test_a_secret_is_not_disclosed_in_the_report(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The scanner finds it; the report must not reprint it."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        (tmp_path / "config.py").write_text('KEY = "' + secret + '"\n', encoding="utf-8")
        run("investigate", "q", "--path", str(tmp_path), "--offline")
        assert secret not in capsys.readouterr().out

    def test_the_report_can_be_written_to_a_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "app.py").write_text(TRIVIAL_SOURCE, encoding="utf-8")
        destination = tmp_path / "report.md"
        run(
            "investigate",
            "q",
            "--path",
            str(tmp_path),
            "--offline",
            "--output",
            str(destination),
        )
        capsys.readouterr()
        assert destination.is_file()
        assert "# Investigation" in destination.read_text(encoding="utf-8")

    def test_an_unimplemented_profile_is_refused(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "app.py").write_text(TRIVIAL_SOURCE, encoding="utf-8")
        code = run(
            "investigate",
            "q",
            "--path",
            str(tmp_path),
            "--offline",
            "--profile",
            "threat_hunting",
        )
        assert code == EXIT_USAGE
        assert "not implemented" in capsys.readouterr().err

    def test_a_missing_tool_is_reported_in_the_report(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """ "Semgrep is not installed" and "Semgrep found nothing" must never
        look the same. This only asserts the shape when Semgrep is absent."""
        import shutil

        (tmp_path / "app.py").write_text(TRIVIAL_SOURCE, encoding="utf-8")
        run("investigate", "q", "--path", str(tmp_path), "--offline")
        out = capsys.readouterr().out
        if shutil.which("semgrep") is None:
            assert "semgrep" in out
            assert "## Limitations" in out


class TestParser:
    def test_no_command_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as exit_info:
            main([])
        assert exit_info.value.code == EXIT_USAGE
