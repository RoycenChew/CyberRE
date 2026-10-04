"""Source security adapters: Semgrep, secrets and dependency manifests.

The secret-scanner tests are the ones to read first. A tool that finds leaked
credentials and then stores them has made the problem worse, so several tests
exist purely to assert that the secret never reaches evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cyberre.adapters.deps.manifests import (
    ManifestParseError,
    discover_manifests,
    parse_package_json,
    parse_package_lock,
    parse_pyproject,
    parse_requirements_txt,
)
from cyberre.adapters.deps.manifests import scan_tree as scan_dependencies
from cyberre.adapters.secrets.scanner import (
    looks_like_placeholder,
    redact,
    scan_text,
    shannon_entropy,
)
from cyberre.adapters.secrets.scanner import scan_tree as scan_secrets
from cyberre.adapters.semgrep.parser import (
    SemgrepOutputError,
    build_provenance,
    parse_semgrep,
    ruleset_digest,
)
from cyberre.core.models.enums import EvidenceType

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "semgrep"
SHA = "a" * 64


def semgrep_report(name: str = "vulnerable_app.json", **overrides: Any) -> Any:
    document: dict[str, Any] = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    document.update(overrides)
    return parse_semgrep(
        document,
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=SHA,
        provenance=build_provenance(
            semgrep_version="1.52.0",
            ruleset_version="p/security-audit",
            ruleset_hash=ruleset_digest(["a", "b"]),
            artefact_sha256=SHA,
            raw_output_ref="obj/semgrep",
        ),
    )


class TestSemgrepParsing:
    def test_findings_become_evidence(self) -> None:
        report = semgrep_report()
        assert len(report.evidence) == 3
        assert all(e.evidence_type is EvidenceType.SCANNER_FINDING for e in report.evidence)

    def test_the_scanner_severity_is_recorded_not_adopted(self) -> None:
        """Importing a scanner's rating would smuggle an unvalidated
        judgement into the finding."""
        report = semgrep_report()
        observation = report.evidence[0].observation
        assert observation.severity_reported == "ERROR"  # type: ignore[union-attr]
        # Nothing on the evidence carries a CyberRE severity.
        assert "severity" not in type(report.evidence[0]).model_fields

    def test_a_match_is_a_weak_signal(self) -> None:
        """A pattern fired. That is an observation about the code, not
        evidence that anything is exploitable."""
        report = semgrep_report()
        assert all(e.source_reliability <= 0.75 for e in report.evidence)

    def test_cwe_metadata_is_captured(self) -> None:
        report = semgrep_report()
        cwes = [c for e in report.evidence for c in e.observation.cwe]  # type: ignore[union-attr]
        assert any("CWE-78" in c for c in cwes)

    def test_locations_are_relative_to_the_scope_root(self) -> None:
        """An absolute path leaks the analyst's filesystem into a report and
        makes the digest machine-specific."""
        document = json.loads((FIXTURES / "vulnerable_app.json").read_text(encoding="utf-8"))
        document["results"][0]["path"] = "/home/analyst/project/app/views.py"
        report = parse_semgrep(
            document,
            investigation_id="inv-1",
            artefact_id="ar-1",
            artefact_sha256=SHA,
            provenance=build_provenance(
                semgrep_version="1.52.0",
                ruleset_version="p/x",
                ruleset_hash="h",
                artefact_sha256=SHA,
                raw_output_ref=None,
            ),
            scope_root="/home/analyst/project",
        )
        assert str(report.evidence[0].location) == "app/views.py:42"

    def test_the_ruleset_is_recorded_in_provenance(self) -> None:
        report = semgrep_report()
        tool = report.evidence[0].provenance.tool
        assert tool.ruleset_version == "p/security-audit"
        assert tool.config_hash

    def test_the_ruleset_digest_is_order_independent(self) -> None:
        assert ruleset_digest(["b", "a"]) == ruleset_digest(["a", "b"])


class TestSemgrepPartialResults:
    def test_inline_errors_make_the_scan_partial(self) -> None:
        """Semgrep reports per-file errors and still exits zero; treating
        that as clean would let a parse failure in the one interesting file
        read as 'no findings'."""
        report = semgrep_report()
        assert report.is_partial is True
        assert any("generated_pb2" in e for e in report.scan_errors)

    def test_skipped_files_are_counted(self) -> None:
        report = semgrep_report()
        assert report.skipped >= 1

    def test_malformed_results_are_counted_not_dropped(self) -> None:
        report = semgrep_report()
        # The fixture holds one result with no message; it must be counted.
        assert report.skipped >= 2

    def test_a_clean_scan_is_not_partial(self) -> None:
        report = semgrep_report("clean_app.json")
        assert report.evidence == []
        assert report.is_partial is False

    def test_missing_results_key_is_an_error(self) -> None:
        with pytest.raises(SemgrepOutputError, match="results"):
            semgrep_report(results=None) if False else parse_semgrep(
                {"version": "1.52.0"},
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256=SHA,
                provenance=build_provenance(
                    semgrep_version="1.52.0",
                    ruleset_version="p/x",
                    ruleset_hash="h",
                    artefact_sha256=SHA,
                    raw_output_ref=None,
                ),
            )


class TestSecretsNeverReachEvidence:
    """The property that governs the whole module."""

    def test_the_secret_value_is_not_stored(self, tmp_path: Path) -> None:
        secret = "AKIAIOSFODNN7EXAMPLE"
        (tmp_path / "config.py").write_text(f'AWS_KEY = "{secret}"\n', encoding="utf-8")

        evidence, _ = scan_secrets(
            tmp_path, investigation_id="inv-1", artefact_id="ar-1", artefact_sha256=SHA
        )

        assert evidence, "the key should be detected"
        serialised = "".join(e.model_dump_json() for e in evidence)
        assert secret not in serialised, "the credential must never reach evidence"

    def test_the_preview_identifies_without_disclosing(self) -> None:
        preview = redact("AKIAIOSFODNN7EXAMPLE")
        assert preview.startswith("AKIA")
        assert "EXAMPLE" not in preview
        assert preview.endswith("*")

    def test_a_short_value_is_fully_masked(self) -> None:
        assert redact("abc123") == "******"

    def test_no_raw_output_reference_is_kept_by_default(self, tmp_path: Path) -> None:
        """The raw output of a secret scanner is the secrets."""
        (tmp_path / "c.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        evidence, _ = scan_secrets(
            tmp_path, investigation_id="inv-1", artefact_id="ar-1", artefact_sha256=SHA
        )
        assert evidence[0].provenance.raw_output_ref is None


class TestSecretDetection:
    @pytest.mark.parametrize(
        ("content", "detector"),
        [
            ('k = "AKIAIOSFODNN7EXAMPLE"', "aws_access_key_id"),
            ('t = "ghp_' + "a" * 36 + '"', "github_token"),
            ('s = "xoxb-123456789012-abcdefghijkl"', "slack_token"),
            ('g = "AIza' + "B" * 35 + '"', "google_api_key"),
            ('p = "sk_live_abcdefghij1234"', "stripe_key"),
            ("-----BEGIN RSA PRIVATE KEY-----", "private_key_block"),
        ],
    )
    def test_known_credential_shapes_are_found(self, content: str, detector: str) -> None:
        assert any(c.detector == detector for c in scan_text(content))

    def test_prefixed_tokens_score_higher_than_generic_shapes(self) -> None:
        """A loose pattern produces findings a reviewer rejects one by one,
        which costs more analyst time than the occasional miss."""
        specific = scan_text('k = "AKIAIOSFODNN7EXAMPLE"')[0]
        generic = scan_text('password = "hunter2hunter2hunter2"')[0]
        assert specific.confidence > generic.confidence

    @pytest.mark.parametrize(
        "value",
        [
            'api_key = "your_api_key_here"',
            'password = "XXXXXXXXXXXXXXXX"',
            'secret = "<your-secret-here>"',
            'token = "${ENV_TOKEN_VALUE}"',
            'password = "changeme1234"',
        ],
    )
    def test_placeholders_are_not_reported(self, value: str) -> None:
        """Example configuration is where generic patterns fire most."""
        assert scan_text(value) == []

    def test_placeholder_detection_is_case_insensitive(self) -> None:
        assert looks_like_placeholder("CHANGEME")
        assert looks_like_placeholder("Placeholder")

    def test_entropy_is_computed_correctly(self) -> None:
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("abcd") == pytest.approx(2.0)
        assert shannon_entropy("") == 0.0

    def test_high_entropy_alone_is_low_confidence(self) -> None:
        """Plenty of high-entropy strings are hashes, UUIDs or minified code."""
        found = scan_text("blob = 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MFFXRVJUWXVpb3A='")
        if found:
            assert all(c.confidence <= 0.4 for c in found if c.detector == "high_entropy_string")

    def test_results_are_deterministic(self) -> None:
        text = 'a = "AKIAIOSFODNN7EXAMPLE"\nb = "sk_live_abcdefghij1234"\n'
        assert [c.detector for c in scan_text(text)] == [c.detector for c in scan_text(text)]

    def test_an_unreadable_file_is_reported_not_skipped_silently(self, tmp_path: Path) -> None:
        (tmp_path / "binary.dat").write_bytes(b"\xff\xfe\x00\x01not utf8\xc3\x28")
        _, unreadable = scan_secrets(
            tmp_path, investigation_id="inv-1", artefact_id="ar-1", artefact_sha256=SHA
        )
        assert unreadable == ["binary.dat"]


class TestDependencyManifests:
    def test_pinned_requirements_are_captured(self) -> None:
        found = parse_requirements_txt(
            "requests==2.25.0\nflask == 2.0.1  # comment\n", manifest_path="requirements.txt"
        )
        assert [(d.name, d.version) for d in found] == [
            ("requests", "2.25.0"),
            ("flask", "2.0.1"),
        ]

    def test_an_unpinned_requirement_records_no_version(self) -> None:
        """Recording a lower bound would invite an advisory match against a
        version that may not be installed."""
        found = parse_requirements_txt("django>=3.2\n", manifest_path="requirements.txt")
        assert found[0].version is None

    def test_comments_and_options_are_ignored(self) -> None:
        found = parse_requirements_txt(
            "# a comment\n-r other.txt\n--index-url https://x\nrequests==1.0\n",
            manifest_path="requirements.txt",
        )
        assert len(found) == 1

    def test_pyproject_dependencies_are_captured(self) -> None:
        text = (
            '[project]\nname = "x"\ndependencies = ["pydantic>=2.7", "httpx==0.27.0"]\n'
            '[project.optional-dependencies]\ndev = ["pytest==8.0.0"]\n'
        )
        found = parse_pyproject(text, manifest_path="pyproject.toml")
        assert {(d.name, d.version) for d in found} == {
            ("pydantic", None),
            ("httpx", "0.27.0"),
            ("pytest", "8.0.0"),
        }

    def test_a_caret_range_is_not_treated_as_a_pin(self) -> None:
        """'^1.2.3' permits 1.9.0."""
        found = parse_package_json(
            json.dumps({"dependencies": {"lodash": "^4.17.20", "left-pad": "1.3.0"}}),
            manifest_path="package.json",
        )
        versions = {d.name: d.version for d in found}
        assert versions["lodash"] is None
        assert versions["left-pad"] == "1.3.0"

    def test_lock_files_give_resolved_transitive_versions(self) -> None:
        document = {
            "packages": {
                "": {"name": "root"},
                "node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
            }
        }
        found = parse_package_lock(json.dumps(document), manifest_path="package-lock.json")
        assert [(d.name, d.version, d.direct) for d in found] == [("lodash", "4.17.21", False)]

    def test_malformed_json_is_an_error_not_an_empty_result(self) -> None:
        """Treating an unparseable manifest as 'no dependencies' would report
        an unscanned project as clean."""
        with pytest.raises(ManifestParseError, match="not valid JSON"):
            parse_package_json("{ broken", manifest_path="package.json")

    def test_malformed_toml_is_an_error(self) -> None:
        with pytest.raises(ManifestParseError, match="not valid TOML"):
            parse_pyproject("[project", manifest_path="pyproject.toml")

    def test_discovery_skips_vendored_trees(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==1.0\n", encoding="utf-8")
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "package.json").write_text("{}", encoding="utf-8")
        assert [p.name for p in discover_manifests(tmp_path)] == ["requirements.txt"]

    def test_scanning_a_tree_produces_evidence_and_reports_failures(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n", encoding="utf-8")
        (tmp_path / "package.json").write_text("{ not json", encoding="utf-8")

        evidence, failures = scan_dependencies(
            tmp_path, investigation_id="inv-1", artefact_id="ar-1", artefact_sha256=SHA
        )

        assert len(evidence) == 1
        assert evidence[0].evidence_type is EvidenceType.DEPENDENCY
        assert len(failures) == 1
        assert "package.json" in failures[0]

    def test_a_name_match_is_not_a_vulnerability(self, tmp_path: Path) -> None:
        """The adapter reports what is declared. Whether it is affected needs
        product, version range and configuration as separate requirements."""
        (tmp_path / "requirements.txt").write_text("log4j-shim==1.0.0\n", encoding="utf-8")
        evidence, _ = scan_dependencies(
            tmp_path, investigation_id="inv-1", artefact_id="ar-1", artefact_sha256=SHA
        )
        observation = evidence[0].observation
        assert observation.kind == "dependency"
        # No CVE, no severity, no verdict - just what the manifest said.
        assert not hasattr(observation, "cve")
