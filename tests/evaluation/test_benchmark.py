"""The detection benchmark (ADR-025).

Two jobs. The first is a regression floor: a change that makes detection
worse fails here rather than in someone's investigation. The second is
to keep the benchmark itself honest - a benchmark that overstates is
worse than none, and most of these tests are about the machinery
refusing to overstate.

The thresholds below are floors, not targets. They are set at the
measured values minus a margin, so a genuine improvement never fails a
test and a regression always does.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.core.findings.confidence import ConfidenceConfig
from cyberre.evaluation.corpus import Corpus, Split
from cyberre.evaluation.harness import run_benchmark, run_case
from cyberre.evaluation.metrics import (
    Outcome,
    calibration_metrics,
    detection_metrics,
    distinguishable,
    evaluate,
)
from cyberre.evaluation.report import render

pytestmark = pytest.mark.evaluation

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "benchmark" / "corpus.toml"
CONFIG = ROOT / "config" / "confidence.toml"


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return Corpus.load(CORPUS)


@pytest.fixture(scope="module")
def config() -> ConfidenceConfig:
    return ConfidenceConfig.load(CONFIG)


@pytest.fixture(scope="module")
def result(corpus: Corpus, config: ConfidenceConfig):  # type: ignore[no-untyped-def]
    return run_benchmark(corpus, config=config, label="full")


class TestTheCorpus:
    def test_it_loads(self, corpus: Corpus) -> None:
        assert len(corpus.cases) >= 20

    def test_it_is_roughly_balanced(self, corpus: Corpus) -> None:
        """A corpus that is 90% negative makes precision look wonderful."""
        ratio = corpus.positives / len(corpus.cases)
        assert 0.35 <= ratio <= 0.65, f"corpus is unbalanced: {ratio:.2f} positive"

    def test_every_label_carries_a_reason(self, corpus: Corpus) -> None:
        """An unexplained label cannot be reviewed, and a mislabelled case
        is indistinguishable from a broken analyser."""
        for case in corpus.cases:
            assert len(case.why) > 30, f"{case.case_id} has no real justification"

    def test_the_negatives_are_hard(self, corpus: Corpus) -> None:
        """Half the negatives must contain a sink or a tainted value.

        A corpus of empty files would score perfectly and prove nothing.
        These are the cases that decide whether the analyser is any good.
        """
        negatives = [case for case in corpus.cases if not case.vulnerable]
        interesting = [
            case
            for case in negatives
            if any(
                marker in case.path.read_text(encoding="utf-8")
                for marker in ("request.", "subprocess", "os.system", "execute", "yaml")
            )
        ]
        assert len(interesting) >= len(negatives) * 0.75

    def test_splits_are_stable_under_addition(self, corpus: Corpus) -> None:
        """Assignment is by hash of the id, so adding a case cannot move
        an existing one and invalidate every earlier measurement."""
        before = {case.case_id: case.split for case in corpus.cases}
        again = Corpus.load(CORPUS)
        assert {case.case_id: case.split for case in again.cases} == before

    def test_both_splits_are_populated(self, corpus: Corpus) -> None:
        assert corpus.split(Split.TRAIN)
        assert corpus.split(Split.HOLDOUT)

    def test_a_missing_case_file_is_an_error(self, tmp_path: Path) -> None:
        """Silently skipping cases it cannot find would let a benchmark
        improve its score by losing the hard ones."""
        manifest = tmp_path / "corpus.toml"
        manifest.write_text(
            '[[case]]\nid="x"\nfile="nope.py"\nvulnerable=true\nwhy="because"\n',
            encoding="utf-8",
        )
        with pytest.raises(FileNotFoundError):
            Corpus.load(manifest)


class TestDetectionQuality:
    """Floors. Set below the measured values so improvement never fails."""

    def test_recall_floor(self, result) -> None:  # type: ignore[no-untyped-def]
        assert result.detection.recall >= 0.90

    def test_precision_floor(self, result) -> None:  # type: ignore[no-untyped-def]
        assert result.detection.precision >= 0.90

    def test_false_positive_rate_ceiling(self, result) -> None:  # type: ignore[no-untyped-def]
        """The number that decides whether an analyst keeps using it."""
        assert result.detection.false_positive_rate <= 0.10

    def test_the_hard_negatives_are_not_flagged(self, result) -> None:  # type: ignore[no-untyped-def]
        """Named individually, because each is a specific trap and a
        regression in one should say which."""
        reported = {outcome.case_id for outcome in result.outcomes if outcome.reported_vulnerable}
        for case_id in (
            "tn_parameterised_query",
            "tn_shlex_quote_applied",
            "tn_sanitiser_applied_by_caller",
            "tn_unreachable_flow",
            "tn_internal_constant_source",
            "tn_subprocess_list_no_shell",
        ):
            assert case_id not in reported, f"{case_id} was flagged"

    def test_the_genuine_injections_are_found(self, result) -> None:  # type: ignore[no-untyped-def]
        missed = [
            outcome.case_id
            for outcome in result.outcomes
            if outcome.expected_vulnerable and not outcome.reported_vulnerable
        ]
        assert not missed, f"missed: {missed}"


class TestCalibration:
    def test_it_is_not_overconfident(self, result) -> None:  # type: ignore[no-untyped-def]
        """Overconfidence costs an analyst time; underconfidence costs
        the tool nothing. The asymmetry is deliberate."""
        assert result.calibration.overconfidence <= 0.10

    def test_calibration_error_ceiling(self, result) -> None:  # type: ignore[no-untyped-def]
        assert result.calibration.expected_calibration_error <= 0.20

    def test_an_absent_finding_is_not_a_confident_denial(self, corpus: Corpus, config) -> None:  # type: ignore[no-untyped-def]
        """A clean verdict is reported at confidence 0, not 1.

        Scoring silence as certainty would reward an analyser that found
        nothing at all.
        """
        from cyberre.core.findings.confidence import ConfidenceEngine

        clean = next(case for case in corpus.cases if case.case_id == "tn_safe_yaml_load")
        outcome = run_case(clean, engine=ConfidenceEngine(config))
        assert outcome.reported_vulnerable is False
        assert outcome.confidence == 0.0


class TestTheMetricsThemselves:
    def test_precision_is_vacuous_when_nothing_is_flagged(self) -> None:
        """1.0 by convention - and the recall beside it is what exposes
        a detector that reports nothing."""
        metrics = detection_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=True,
                    reported_vulnerable=False,
                    confidence=0.0,
                )
            ]
        )
        assert metrics.precision == 1.0
        assert metrics.recall == 0.0

    def test_a_confident_wrong_answer_scores_worse_than_a_hedged_one(self) -> None:
        """The property that makes calibration worth measuring."""
        confident = calibration_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=False,
                    reported_vulnerable=True,
                    confidence=0.99,
                )
            ]
        )
        hedged = calibration_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=False,
                    reported_vulnerable=True,
                    confidence=0.55,
                )
            ]
        )
        assert confident.brier_score > hedged.brier_score

    def test_overconfidence_is_signed(self) -> None:
        over = calibration_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=False,
                    reported_vulnerable=True,
                    confidence=0.9,
                )
            ]
        )
        under = calibration_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=True,
                    reported_vulnerable=True,
                    confidence=0.3,
                )
            ]
        )
        assert over.overconfidence > 0
        assert under.overconfidence < 0

    def test_a_confidence_of_exactly_one_lands_in_a_bin(self) -> None:
        """The top bin is closed. An open one silently drops every
        maximally confident case from the calibration figure."""
        metrics = calibration_metrics(
            [
                Outcome(
                    case_id="a",
                    expected_vulnerable=True,
                    reported_vulnerable=True,
                    confidence=1.0,
                )
            ]
        )
        assert sum(count for _, count, _ in metrics.bins) == 1

    def test_results_inside_the_margin_are_not_distinguishable(self) -> None:
        """The guard against the benchmark producing confident nonsense."""
        outcomes = [
            Outcome(
                case_id=f"c{i}",
                expected_vulnerable=i % 2 == 0,
                reported_vulnerable=i % 2 == 0,
                confidence=0.8 if i % 2 == 0 else 0.0,
            )
            for i in range(10)
        ]
        left = evaluate("a", outcomes)
        right = evaluate("b", outcomes)
        assert not distinguishable(left, right)

    def test_empty_input_does_not_crash(self) -> None:
        assert calibration_metrics([]).brier_score == 0.0
        assert detection_metrics([]).total == 0


class TestDeterminism:
    def test_two_runs_agree_exactly(self, corpus: Corpus, config) -> None:  # type: ignore[no-untyped-def]
        """No model is in the loop, so the result is reproducible. A
        benchmark whose number moves between runs cannot detect a
        regression smaller than its own jitter.
        """
        first = run_benchmark(corpus, config=config, label="a")
        second = run_benchmark(corpus, config=config, label="b")
        assert [o.model_dump() for o in first.outcomes] == [o.model_dump() for o in second.outcomes]


class TestTheReport:
    def test_it_renders_ascii_only(self, result, corpus: Corpus) -> None:  # type: ignore[no-untyped-def]
        """A Windows console in the default code page mangles anything
        else, and a report nobody can read is not a report."""
        text = render(result, corpus=corpus)
        assert text.isascii()

    def test_a_perfect_score_is_reported_as_a_floor_not_a_claim(
        self, result, corpus: Corpus
    ) -> None:  # type: ignore[no-untyped-def]
        text = render(result, corpus=corpus)
        if not result.failures():
            assert "regression floor" in text


class TestTheTuner:
    """The tuner's job is to refuse bad results, not to produce good ones."""

    def test_it_rejects_a_gain_the_corpus_cannot_identify(self, corpus: Corpus, config) -> None:  # type: ignore[no-untyped-def]
        """The first real run of this tuner proposed raising every
        confidence from 0.885 to 0.954: +0.03 on the objective,
        holdout-confirmed, F1 unchanged. On a corpus where nothing is
        flagged incorrectly the calibration term is maximised by
        confidence alone, so the gain was a property of the corpus.
        """
        from cyberre.evaluation.tuning import tune

        result = tune(corpus, baseline_config=config, max_candidates=200)

        if result.best.score <= result.baseline.score:
            pytest.skip("no higher-scoring weight set in this slice of the grid")

        # Detection cannot improve on a corpus it already gets right, so
        # any gain here is calibration-only and unidentifiable. Either
        # refusal is correct: the guard rejects it outright, or it falls
        # inside the noise margin first. What must never happen is the
        # tuner calling it an improvement.
        assert result.improved is False
        assert "REJECTED" in result.verdict or "noise margin" in result.verdict

    def test_it_never_writes_the_config(self, corpus: Corpus, config, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
        """A weight set that changed itself would mean a finding's score
        depended on when it was run."""
        from cyberre.evaluation.tuning import tune

        before = CONFIG.read_bytes()
        tune(corpus, baseline_config=config, max_candidates=50)
        assert CONFIG.read_bytes() == before

    def test_it_tunes_on_training_only(self, corpus: Corpus, config) -> None:  # type: ignore[no-untyped-def]
        """A tuner allowed to see the holdout makes the holdout check
        meaningless."""
        from cyberre.evaluation.tuning import tune

        result = tune(corpus, baseline_config=config, max_candidates=1)
        assert result.baseline.detection.total == len(corpus.split(Split.TRAIN))
