"""The CLI.

Thin by design, so these tests mostly check that it reports honestly: that
it lists what does not work alongside what does, and that "not wired up
yet" is distinguishable from "you asked wrongly".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.cli.main import EXIT_NOT_READY, EXIT_OK, EXIT_USAGE, main

pytestmark = pytest.mark.unit

ROOT = str(Path(__file__).resolve().parents[2])


class TestCapabilities:
    def test_it_lists_profiles_and_requirement_sets(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--root", ROOT, "capabilities"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "binary_re" in out
        assert "req.cwe.78" in out
        assert "Knowledge records:" in out

    def test_it_names_what_is_not_implemented(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A tool that lists only its working features leaves the reader to
        find the gaps by hitting them."""
        main(["--root", ROOT, "capabilities"])
        out = capsys.readouterr().out
        assert "NOT IMPLEMENTED" in out
        assert "threat_hunting" in out

    def test_it_says_when_no_capability_is_registered(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(["--root", ROOT, "capabilities"])
        assert "none registered in this build" in capsys.readouterr().out


class TestProfiles:
    def test_a_binary_selects_reverse_engineering(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--root", ROOT, "profiles", "pe"]) == EXIT_OK
        assert "binary_re" in capsys.readouterr().out

    def test_a_source_tree_selects_source_security(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(["--root", ROOT, "profiles", "source_tree"])
        assert "source_security" in capsys.readouterr().out

    def test_an_unknown_artefact_type_is_a_usage_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--root", ROOT, "profiles", "nonsense"]) == EXIT_USAGE
        assert "unknown artefact type" in capsys.readouterr().err


class TestKnowledge:
    def test_an_api_lookup_shows_the_record(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--root", ROOT, "knowledge", "VirtualAllocEx"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "win.api.VirtualAllocEx" in out
        assert "Microsoft Learn" in out

    def test_the_innocent_reading_is_shown_by_default(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Most uses of most dangerous APIs are legitimate; a lookup that
        omits that is misleading."""
        main(["--root", ROOT, "knowledge", "VirtualAllocEx"])
        assert "innocent reading" in capsys.readouterr().out

    def test_the_companions_are_shown(self, capsys: pytest.CaptureFixture[str]) -> None:
        """They are why one import is not a finding."""
        main(["--root", ROOT, "knowledge", "CreateRemoteThread"])
        assert "companions" in capsys.readouterr().out

    def test_a_miss_suggests_rather_than_guessing(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--root", ROOT, "knowledge", "injection"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "no exact match" in out or "no record" in out

    def test_an_unknown_term_is_not_an_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--root", ROOT, "knowledge", "ZzzNotARealApi"]) == EXIT_OK


class TestInvestigate:
    def test_it_reports_that_it_is_not_wired_up(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A command that half-works is worse than one that says so."""
        assert main(["--root", ROOT, "investigate", "find vulns"]) == EXIT_NOT_READY
        err = capsys.readouterr().err
        assert "not available in this build" in err

    def test_not_ready_is_distinct_from_a_usage_error(self) -> None:
        """'You asked wrongly' and 'this is not wired up yet' should not
        look the same to a script."""
        assert EXIT_NOT_READY != EXIT_USAGE

    def test_it_points_at_what_does_work(self, capsys: pytest.CaptureFixture[str]) -> None:
        main(["--root", ROOT, "investigate", "find vulns"])
        assert "pytest -m evaluation" in capsys.readouterr().err


class TestParser:
    def test_no_command_is_a_usage_error(self) -> None:
        with pytest.raises(SystemExit) as exit_info:
            main([])
        assert exit_info.value.code == EXIT_USAGE
