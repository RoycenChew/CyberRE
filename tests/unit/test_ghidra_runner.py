"""The headless runner's logic, without running Ghidra.

Cache keying is the part worth testing hardest: an incomplete key serves a
stale export as though it were current, which is the quiet kind of
reproducibility failure where nothing errors and the answer is wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.adapters.ghidra.runner import (
    EXPECTED_SCRIPT_VERSION,
    AnalysisConfig,
    ExportCache,
    GhidraInstallation,
    GhidraUnavailableError,
    cache_key,
    locate_ghidra,
)

pytestmark = pytest.mark.unit

SHA = "a" * 64


class TestCacheKey:
    def test_the_same_inputs_give_the_same_key(self) -> None:
        config = AnalysisConfig()
        assert cache_key(artefact_sha256=SHA, ghidra_version="12.1.2", config=config) == cache_key(
            artefact_sha256=SHA, ghidra_version="12.1.2", config=config
        )

    def test_different_bytes_give_a_different_key(self) -> None:
        config = AnalysisConfig()
        assert cache_key(artefact_sha256=SHA, ghidra_version="12.1.2", config=config) != cache_key(
            artefact_sha256="b" * 64, ghidra_version="12.1.2", config=config
        )

    def test_a_ghidra_upgrade_invalidates_the_cache(self) -> None:
        """A newer decompiler finds different things."""
        config = AnalysisConfig()
        assert cache_key(artefact_sha256=SHA, ghidra_version="12.1.2", config=config) != cache_key(
            artefact_sha256=SHA, ghidra_version="11.2.0", config=config
        )

    def test_a_configuration_change_invalidates_the_cache(self) -> None:
        assert cache_key(
            artefact_sha256=SHA, ghidra_version="12.1.2", config=AnalysisConfig()
        ) != cache_key(
            artefact_sha256=SHA,
            ghidra_version="12.1.2",
            config=AnalysisConfig(analysis_timeout_seconds=60),
        )

    def test_extra_analyzer_options_are_part_of_the_key(self) -> None:
        assert (
            AnalysisConfig().digest()
            != AnalysisConfig(extra_analyzer_options=("-processor", "x86:LE:64:default")).digest()
        )

    def test_the_script_version_is_part_of_the_key(self) -> None:
        """Without it, an export from an older script would be served as
        current - which the parser then refuses, loudly, as a bug."""
        key = cache_key(artefact_sha256=SHA, ghidra_version="12.1.2", config=AnalysisConfig())
        assert EXPECTED_SCRIPT_VERSION
        # Changing the constant must change every key; proven by construction
        # rather than by mutating a module global mid-test.
        from cyberre.core.models.base import stable_digest

        assert key == stable_digest(
            SHA, "12.1.2", EXPECTED_SCRIPT_VERSION, AnalysisConfig().digest()
        )


class TestExportCache:
    def test_round_trip(self, tmp_path: Path) -> None:
        cache = ExportCache(tmp_path)
        cache.put("k1", {"schema_version": 1})
        assert cache.get("k1") == {"schema_version": 1}

    def test_a_miss_returns_none(self, tmp_path: Path) -> None:
        assert ExportCache(tmp_path).get("absent") is None

    def test_a_corrupt_entry_is_a_miss_not_a_failure(self, tmp_path: Path) -> None:
        """Re-analysing is always correct; refusing to run because a cache
        file is damaged would be the wrong trade."""
        cache = ExportCache(tmp_path)
        cache.path_for("k1").write_text("{ truncated", encoding="utf-8")
        assert cache.get("k1") is None
        assert not cache.path_for("k1").exists()

    def test_a_non_object_entry_is_a_miss(self, tmp_path: Path) -> None:
        cache = ExportCache(tmp_path)
        cache.path_for("k1").write_text("[1, 2, 3]", encoding="utf-8")
        assert cache.get("k1") is None


class TestLocatingGhidra:
    def test_an_unset_environment_is_reported_clearly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        with pytest.raises(GhidraUnavailableError, match="GHIDRA_INSTALL_DIR"):
            locate_ghidra()

    def test_a_missing_directory_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(GhidraUnavailableError, match="does not exist"):
            locate_ghidra(tmp_path / "nowhere")

    def test_a_directory_that_is_not_ghidra_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(GhidraUnavailableError, match="does not look like"):
            locate_ghidra(tmp_path)

    def test_the_version_is_read_rather_than_guessed(self, tmp_path: Path) -> None:
        """It goes into provenance and the cache key; a guess corrupts both."""
        properties = tmp_path / "Ghidra" / "application.properties"
        properties.parent.mkdir(parents=True)
        properties.write_text(
            "application.name=Ghidra\napplication.version=12.1.2\n", encoding="utf-8"
        )
        support = tmp_path / "support"
        support.mkdir()
        for name in ("analyzeHeadless", "analyzeHeadless.bat"):
            (support / name).write_text("", encoding="utf-8")

        installation = locate_ghidra(tmp_path)
        assert installation.version == "12.1.2"

    def test_an_installation_without_a_version_is_refused(self, tmp_path: Path) -> None:
        properties = tmp_path / "Ghidra" / "application.properties"
        properties.parent.mkdir(parents=True)
        properties.write_text("application.name=Ghidra\n", encoding="utf-8")
        with pytest.raises(GhidraUnavailableError, match=r"application\.version"):
            locate_ghidra(tmp_path)

    def test_an_incomplete_installation_is_refused(self, tmp_path: Path) -> None:
        properties = tmp_path / "Ghidra" / "application.properties"
        properties.parent.mkdir(parents=True)
        properties.write_text("application.version=12.1.2\n", encoding="utf-8")
        with pytest.raises(GhidraUnavailableError, match="incomplete"):
            locate_ghidra(tmp_path)


class TestUnavailableIsNotFailure:
    def test_the_two_errors_are_distinct_types(self) -> None:
        """'We could not look' and 'we looked and found nothing' must never
        be confused: one is a ToolFailure, the other is evidence."""
        from cyberre.adapters.ghidra.runner import GhidraAnalysisError

        assert not issubclass(GhidraUnavailableError, GhidraAnalysisError)
        assert not issubclass(GhidraAnalysisError, GhidraUnavailableError)


class TestInstallationPaths:
    def test_the_headless_launcher_is_platform_appropriate(self, tmp_path: Path) -> None:
        installation = GhidraInstallation(root=tmp_path, version="12.1.2")
        assert installation.headless.name.startswith("analyzeHeadless")
        assert installation.headless.parent.name == "support"
