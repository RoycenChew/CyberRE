"""The Python taint and reachability analyser.

The false-negative tests matter as much as the positives. This analyser
produces the two evidence types every taint requirement set demands, so an
error here does not merely lose a finding - it decides whether a finding is
possible at all.

The tests that assert what it must *not* claim are the important ones: a
syntactic analyser that overstates reachability turns absence of evidence
into positive evidence of safety, which is the strongest negative the
system can assert.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.adapters.dataflow.evidence import report_evidence
from cyberre.adapters.dataflow.python_taint import (
    analyse_source,
    analyse_tree,
    propagate,
    reachable_functions,
)
from cyberre.core.models.enums import EvidenceType

pytestmark = pytest.mark.unit


def analyse(source: str) -> object:
    analysis = analyse_source(source, path="app.py")
    propagate(analysis)
    return analysis


def flows(source: str) -> list[object]:
    return list(analyse(source).flows)  # type: ignore[attr-defined]


class TestSources:
    @pytest.mark.parametrize(
        "expression",
        [
            "request.args.get('h')",
            "request.form.get('h')",
            "request.cookies.get('h')",
            "request.headers.get('h')",
            "input()",
            "os.environ.get('H')",
        ],
    )
    def test_known_sources_taint(self, expression: str) -> None:
        found = flows(
            f"import subprocess\ndef f():\n    subprocess.call('x ' + {expression}, shell=True)\n"
        )
        assert found, expression

    def test_a_literal_does_not_taint(self) -> None:
        assert (
            flows(
                "import subprocess\ndef f():\n    subprocess.call('ping localhost', shell=True)\n"
            )
            == []
        )

    def test_an_aliased_import_still_matches(self) -> None:
        """Matching is tail-first, because the import style varies."""
        assert flows(
            "import subprocess\nimport flask\n"
            "def f():\n    subprocess.call('x ' + flask.request.args.get('h'), shell=True)\n"
        )


class TestSanitisers:
    def test_shlex_quote_is_recorded(self) -> None:
        found = flows(
            "import subprocess, shlex\nfrom flask import request\n"
            "def f():\n"
            "    subprocess.call('ping ' + shlex.quote(request.args.get('h')), shell=True)\n"
        )
        assert found
        assert "shlex.quote" in found[0].sanitisers  # type: ignore[attr-defined]

    def test_int_coercion_is_recorded(self) -> None:
        found = flows(
            "import subprocess\nfrom flask import request\n"
            "def f():\n    subprocess.call('sleep ' + str(int(request.args.get('n'))), shell=True)\n"
        )
        assert found
        assert "int()" in found[0].sanitisers  # type: ignore[attr-defined]

    def test_a_parameterised_query_is_recorded_as_sanitised(self) -> None:
        """The false-positive trap. The flow is reported, with the binding
        named, because a reviewer asking 'is this injectable?' needs to see
        that it was checked rather than missed."""
        found = flows(
            "from flask import request\n"
            "def f(cursor):\n"
            "    cursor.execute('SELECT * FROM t WHERE id = %s', [request.args.get('id')])\n"
        )
        assert found
        assert found[0].sanitisers == ("parameterised query",)  # type: ignore[attr-defined]

    def test_a_concatenated_query_is_not_sanitised(self) -> None:
        found = flows(
            "from flask import request\n"
            "def f(cursor):\n"
            "    cursor.execute('SELECT * FROM t WHERE id = ' + request.args.get('id'))\n"
        )
        assert found
        assert found[0].sanitisers == ()  # type: ignore[attr-defined]


class TestHowTheValueReachesTheSink:
    """The fact that decides whether a command sink is exploitable."""

    def test_concatenation_into_a_command_is_recorded(self) -> None:
        found = flows(
            "import subprocess\nfrom flask import request\n"
            "def f():\n    subprocess.call('ping ' + request.args.get('h'), shell=True)\n"
        )
        steps = found[0].steps  # type: ignore[attr-defined]
        assert "string concatenation into the command" in steps
        assert "shell=True" in steps

    def test_an_argv_element_is_recorded_differently(self) -> None:
        found = flows(
            "import subprocess\nfrom flask import request\n"
            "def f():\n    subprocess.call(['ping', request.args.get('h')], shell=False)\n"
        )
        steps = found[0].steps  # type: ignore[attr-defined]
        assert "separate argument vector element" in steps
        assert "shell=False" in steps

    def test_an_f_string_is_recorded(self) -> None:
        found = flows(
            "import subprocess\nfrom flask import request\n"
            "def f():\n    subprocess.call(f\"ping {request.args.get('h')}\", shell=True)\n"
        )
        assert "f-string interpolation into the command" in found[0].steps  # type: ignore[attr-defined]

    def test_the_sink_line_is_captured(self) -> None:
        """A label is a claim about code; the line is the code."""
        found = flows(
            "import subprocess\nfrom flask import request\n"
            "def f():\n    subprocess.call('ping ' + request.args.get('h'), shell=True)\n"
        )
        assert "subprocess.call" in (found[0].excerpt or "")  # type: ignore[attr-defined]


class TestPropagation:
    SOURCE = (
        "import subprocess\nfrom flask import request\n"
        "@app.route('/p')\n"
        "def route_ping():\n"
        "    return ping(request.args.get('host'))\n"
        "def ping(host):\n"
        "    return subprocess.call('ping ' + host, shell=True)\n"
    )

    def test_the_callers_source_is_carried_through(self) -> None:
        """A flow reading "parameter 'host'" does not establish attacker
        influence; one reading "HTTP query parameter" does."""
        found = flows(self.SOURCE)
        assert found
        assert found[0].source == "HTTP query parameter"  # type: ignore[attr-defined]

    def test_the_call_path_is_recorded(self) -> None:
        found = flows(self.SOURCE)
        assert found[0].steps[:2] == ("route_ping", "ping")  # type: ignore[attr-defined]

    def test_an_untainted_caller_does_not_promote_the_helper(self) -> None:
        """Only a caller that actually passes tainted data promotes it."""
        found = flows(
            "import subprocess\n"
            "@app.route('/p')\n"
            "def route():\n"
            "    return ping('localhost')\n"
            "def ping(host):\n"
            "    return subprocess.call('ping ' + host, shell=True)\n"
        )
        assert found
        assert found[0].source.startswith("parameter")  # type: ignore[attr-defined]


class TestReachability:
    SOURCE = (
        "import subprocess\nfrom flask import request\n"
        "@app.route('/p')\n"
        "def route_ping():\n"
        "    return ping(request.args.get('host'))\n"
        "def ping(host):\n"
        "    return subprocess.call('ping ' + host, shell=True)\n"
        "def unused(host):\n"
        "    return subprocess.call('tr ' + host, shell=True)\n"
    )

    def test_a_decorated_function_is_an_entry_point(self) -> None:
        """A route handler is an entry point whether or not anything in the
        file calls it - the case a naive call-graph walk gets wrong."""
        analysis = analyse(self.SOURCE)
        assert analysis.functions["route_ping"].is_entry  # type: ignore[attr-defined]

    def test_a_called_helper_is_reachable(self) -> None:
        assert "ping" in reachable_functions(analyse(self.SOURCE))  # type: ignore[arg-type]

    def test_an_uncalled_function_is_not(self) -> None:
        assert "unused" not in reachable_functions(analyse(self.SOURCE))  # type: ignore[arg-type]

    def test_main_is_an_entry_point(self) -> None:
        analysis = analyse("def main():\n    pass\n")
        assert analysis.functions["main"].is_entry  # type: ignore[attr-defined]


class TestItDoesNotOverclaim:
    def test_no_entry_points_means_no_reachability_claim(self, tmp_path: Path) -> None:
        """ "We found no entry point" is not "no path reaches this".

        Emitting reachable=False here would turn absence of evidence into
        the strongest negative the system can assert.
        """
        (tmp_path / "a.py").write_text(
            "import subprocess\ndef f(h):\n    subprocess.call('ping ' + h, shell=True)\n",
            encoding="utf-8",
        )
        evidence = report_evidence(
            analyse_tree(tmp_path),
            investigation_id="inv-1",
            artefact_id="ar-1",
            artefact_sha256="a" * 64,
        )
        kinds = {e.evidence_type for e in evidence}
        assert EvidenceType.DATA_FLOW in kinds
        assert EvidenceType.REACHABILITY not in kinds

    def test_with_an_entry_point_both_outcomes_are_claimed(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(TestReachability.SOURCE, encoding="utf-8")
        evidence = report_evidence(
            analyse_tree(tmp_path),
            investigation_id="inv-1",
            artefact_id="ar-1",
            artefact_sha256="a" * 64,
        )
        reachability = [e for e in evidence if e.evidence_type is EvidenceType.REACHABILITY]
        assert {bool(e.observation.reachable) for e in reachability} == {True, False}  # type: ignore[union-attr]

    def test_its_evidence_is_not_highly_reliable(self, tmp_path: Path) -> None:
        """A syntactic analyser narrows an investigation; it does not
        settle one, and the confidence engine should see that."""
        (tmp_path / "a.py").write_text(TestReachability.SOURCE, encoding="utf-8")
        evidence = report_evidence(
            analyse_tree(tmp_path),
            investigation_id="inv-1",
            artefact_id="ar-1",
            artefact_sha256="a" * 64,
        )
        assert all(e.source_reliability <= 0.7 for e in evidence)


class TestRobustness:
    def test_a_syntax_error_is_reported_not_swallowed(self) -> None:
        """A file that could not be parsed was not analysed, and that is a
        coverage gap rather than a clean file."""
        analysis = analyse_source("def broken(:\n", path="bad.py")
        assert analysis.parse_error is not None
        assert analysis.flows == []

    def test_an_unparseable_file_makes_the_run_partial(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
        assert analyse_tree(tmp_path).is_partial

    def test_vendored_directories_are_skipped(self, tmp_path: Path) -> None:
        vendored = tmp_path / "node_modules"
        vendored.mkdir()
        (vendored / "x.py").write_text(
            "import subprocess\ndef f(h):\n    subprocess.call(h, shell=True)\n",
            encoding="utf-8",
        )
        assert analyse_tree(tmp_path).modules == []

    def test_analysis_is_deterministic(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(TestReachability.SOURCE, encoding="utf-8")
        first = [f.source for m in analyse_tree(tmp_path).modules for f in m.flows]
        second = [f.source for m in analyse_tree(tmp_path).modules for f in m.flows]
        assert first == second


class TestEndToEndAgainstRequirements:
    """The analyser exists to satisfy the taint requirement sets. These
    check it actually does, without a model involved."""

    def test_a_genuine_injection_satisfies_every_cwe78_requirement(self, tmp_path: Path) -> None:
        from cyberre.core.evidence.builder import build_graph
        from cyberre.core.findings.requirements import RequirementRegistry
        from cyberre.core.findings.validation import ValidationEngine
        from cyberre.core.models.enums import FindingStatus
        from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass

        (tmp_path / "a.py").write_text(TestPropagation.SOURCE, encoding="utf-8")
        evidence = list(
            report_evidence(
                analyse_tree(tmp_path),
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256="a" * 64,
            )
        )

        outcome = ValidationEngine().validate(
            Hypothesis(
                investigation_id="inv-1",
                statement="command injection",
                hypothesis_class=HypothesisClass(taxonomy="cwe", identifier="78"),
                created_by="test",
            ),
            RequirementRegistry().for_class("cwe:78"),
            evidence=evidence,
            graph=build_graph(evidence),
        )

        assert outcome.status is FindingStatus.VALIDATED, outcome.explanation

    def test_a_sanitised_flow_does_not(self, tmp_path: Path) -> None:
        from cyberre.core.evidence.builder import build_graph
        from cyberre.core.findings.requirements import RequirementRegistry
        from cyberre.core.findings.validation import ValidationEngine
        from cyberre.core.models.enums import FindingStatus
        from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass

        (tmp_path / "a.py").write_text(
            "import subprocess, shlex\nfrom flask import request\n"
            "@app.route('/p')\n"
            "def route():\n"
            "    return ping(shlex.quote(request.args.get('host')))\n"
            "def ping(host):\n"
            "    return subprocess.call('ping ' + host, shell=True)\n",
            encoding="utf-8",
        )
        evidence = list(
            report_evidence(
                analyse_tree(tmp_path),
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256="a" * 64,
            )
        )
        outcome = ValidationEngine().validate(
            Hypothesis(
                investigation_id="inv-1",
                statement="command injection",
                hypothesis_class=HypothesisClass(taxonomy="cwe", identifier="78"),
                created_by="test",
            ),
            RequirementRegistry().for_class("cwe:78"),
            evidence=evidence,
            graph=build_graph(evidence),
        )
        assert outcome.status is not FindingStatus.VALIDATED


class TestReachabilityIsTiedToItsSite:
    """Reachability must be about the site it is attached to.

    Matching on the sink name alone let a reachable call to
    subprocess.call in one function satisfy the requirement for an
    entirely different call in another. Adversarial review flagged it
    twice before it was fixed, which is the argument for the reviewer in
    one example.
    """

    SOURCE = (
        "import subprocess\n"
        "from flask import request\n"
        "@app.route('/p')\n"
        "def route_ping():\n"
        "    return ping(request.args.get('host'))\n"
        "def ping(host):\n"
        "    return subprocess.call('ping ' + host, shell=True)\n"
        "def unused_helper(host):\n"
        "    return subprocess.call('traceroute ' + host, shell=True)\n"
    )

    def _validate(self, tmp_path: Path) -> object:
        from cyberre.core.evidence.builder import build_graph
        from cyberre.core.findings.predicates import PredicateContext

        (tmp_path / "a.py").write_text(self.SOURCE, encoding="utf-8")
        evidence = list(
            report_evidence(
                analyse_tree(tmp_path),
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256="a" * 64,
            )
        )
        return PredicateContext(evidence=evidence, graph=build_graph(evidence))

    def test_flow_sites_are_identified(self, tmp_path: Path) -> None:
        from cyberre.core.findings.requirements import _SUBPROCESS_SINKS

        context = self._validate(tmp_path)
        sites = context.flow_sites(_SUBPROCESS_SINKS)  # type: ignore[attr-defined]
        assert {"ping", "unused_helper"} <= sites

    def test_the_unreachable_helper_does_not_validate(self, tmp_path: Path) -> None:
        """The reachable call elsewhere in the file must not satisfy it."""
        from cyberre.core.evidence.builder import build_graph
        from cyberre.core.findings.requirements import RequirementRegistry
        from cyberre.core.findings.validation import ValidationEngine
        from cyberre.core.models.enums import FindingStatus
        from cyberre.core.models.hypothesis import Hypothesis, HypothesisClass

        (tmp_path / "a.py").write_text(self.SOURCE, encoding="utf-8")
        report = analyse_tree(tmp_path)
        # Only the unreachable site's evidence, as a hypothesis about it
        # would cite.
        evidence = [
            e
            for e in report_evidence(
                report,
                investigation_id="inv-1",
                artefact_id="ar-1",
                artefact_sha256="a" * 64,
            )
            if getattr(e.location, "symbol", None) == "unused_helper"
        ]
        assert evidence, "the unreachable site should still produce a flow"

        outcome = ValidationEngine().validate(
            Hypothesis(
                investigation_id="inv-1",
                statement="command injection in unused_helper",
                hypothesis_class=HypothesisClass(taxonomy="cwe", identifier="78"),
                created_by="test",
            ),
            RequirementRegistry().for_class("cwe:78"),
            evidence=evidence,
            graph=build_graph(evidence),
        )
        assert outcome.status is not FindingStatus.VALIDATED
