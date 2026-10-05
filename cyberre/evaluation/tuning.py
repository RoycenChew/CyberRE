"""Tuning the confidence weights against the corpus.

The tuner proposes; it never writes. A weight set that changed itself
would mean a finding's score depended on when it was run, and two
analysts comparing notes would be comparing different systems.

It also refuses to claim an improvement it cannot support. With a corpus
of this size most differences are inside the noise, and a benchmark that
ranks on them produces confident nonsense - which, in a tool built to
stop exactly that, would be a poor joke.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator, Sequence

from cyberre.core.findings.confidence import ConfidenceConfig
from cyberre.core.models.base import DomainModel
from cyberre.evaluation.corpus import Corpus, Split
from cyberre.evaluation.harness import run_benchmark
from cyberre.evaluation.metrics import BenchmarkResult, distinguishable

#: Values each weight may take. Coarse deliberately: a finer grid on 22
#: cases would fit noise with more decimal places, not more truth.
GRID: tuple[float, ...] = (0.05, 0.10, 0.15, 0.20, 0.30)

#: Weights held fixed. Completeness dominates by design (a finding
#: missing half its requirements is half a finding), and searching it
#: would let the tuner discard that reasoning to chase two cases.
PINNED: dict[str, float] = {"evidence_completeness": 0.30}


class TuningResult(DomainModel):
    """What a search found, and whether it means anything."""

    baseline: BenchmarkResult
    best: BenchmarkResult
    best_weights: dict[str, float]
    candidates_evaluated: int
    improved: bool
    """True only if the improvement exceeds the corpus's noise margin."""

    verdict: str

    def render(self) -> str:
        lines = [
            f"Baseline score {self.baseline.score:.4f} "
            f"(F1 {self.baseline.detection.f1:.3f}, "
            f"ECE {self.baseline.calibration.expected_calibration_error:.4f})",
            f"Best     score {self.best.score:.4f} "
            f"(F1 {self.best.detection.f1:.3f}, "
            f"ECE {self.best.calibration.expected_calibration_error:.4f})",
            f"Candidates evaluated: {self.candidates_evaluated}",
            f"Noise margin: +/-{self.baseline.margin:.4f}",
            "",
            self.verdict,
        ]
        return "\n".join(lines)


def _candidates(names: Sequence[str]) -> Iterator[dict[str, float]]:
    """Every grid assignment over the unpinned weights."""
    free = [name for name in names if name not in PINNED]
    for combination in itertools.product(GRID, repeat=len(free)):
        yield {**PINNED, **dict(zip(free, combination, strict=True))}


def tune(
    corpus: Corpus,
    *,
    baseline_config: ConfidenceConfig,
    max_candidates: int = 4000,
) -> TuningResult:
    """Search for weights that score better on the training split.

    Training only. The holdout exists so that a claimed improvement can
    be checked against cases the search never saw, and a tuner allowed
    to look at them would make that check meaningless.
    """
    train = Split.TRAIN
    baseline = run_benchmark(corpus, config=baseline_config, split=train, label="baseline")

    best = baseline
    best_weights = dict(baseline_config.weights)
    evaluated = 0

    for weights in _candidates(list(baseline_config.weights)):
        if evaluated >= max_candidates:
            break
        evaluated += 1
        candidate_config = baseline_config.model_copy(update={"weights": weights})
        result = run_benchmark(corpus, config=candidate_config, split=train, label="candidate")
        if result.score > best.score:
            best, best_weights = result, weights

    improved = distinguishable(best, baseline) and best.score > baseline.score

    # A corpus on which every flagged case is correct cannot tell a
    # well-calibrated scorer from a maximally confident one: raising
    # every confidence to 1.0 drives the calibration error to zero and
    # looks like a win. The first run of this tuner proposed exactly
    # that - +0.03 on the objective, holdout-confirmed, and achieved
    # entirely by moving every positive from 0.885 to 0.954 with F1
    # unchanged. The guard refuses the result rather than the corpus.
    unidentifiable = (
        improved
        and baseline.detection.false_positives == 0
        and best.detection.f1 <= baseline.detection.f1
    )
    if unidentifiable:
        improved = False

    if unidentifiable:
        verdict = (
            f"A weight set scores {best.score - baseline.score:+.4f} higher, but "
            f"detection did not improve (F1 {baseline.detection.f1:.3f} either "
            f"way) and the corpus flags no case incorrectly. On such a corpus "
            f"the calibration term is maximised by raising every confidence, "
            f"so this is a property of the corpus, not a better scorer. "
            f"REJECTED. Add positives that should score low - a flow behind a "
            f"weak sanitiser, evidence from one tool only - before tuning "
            f"calibration again."
        )
    elif not improved and best.score > baseline.score:
        verdict = (
            f"A better-scoring weight set exists (+{best.score - baseline.score:.4f}) "
            f"but the difference is inside this corpus's noise margin "
            f"(+/-{baseline.margin:.4f}). Not a result. Grow the corpus before "
            f"changing the weights on this evidence."
        )
    elif not improved:
        verdict = (
            "No weight set in the grid beats the current one. The weights in "
            "config/confidence.toml stand."
        )
    else:
        verdict = (
            f"A weight set scores {best.score - baseline.score:+.4f} above the "
            f"current one, beyond the noise margin. Verify it on the holdout "
            f"split before adopting it, and bump the config version if you do."
        )

    return TuningResult(
        baseline=baseline,
        best=best,
        best_weights=best_weights,
        candidates_evaluated=evaluated,
        improved=improved,
        verdict=verdict,
    )


def confirm_on_holdout(
    corpus: Corpus, *, baseline_config: ConfidenceConfig, weights: dict[str, float]
) -> tuple[BenchmarkResult, BenchmarkResult, bool]:
    """Re-check a candidate on cases the search never saw.

    Returns (baseline, candidate, held_up). A candidate that wins on
    training and not on holdout was fitted to the training cases, and
    adopting it would make the system worse at everything else.
    """
    baseline = run_benchmark(
        corpus, config=baseline_config, split=Split.HOLDOUT, label="holdout-baseline"
    )
    candidate = run_benchmark(
        corpus,
        config=baseline_config.model_copy(update={"weights": weights}),
        split=Split.HOLDOUT,
        label="holdout-candidate",
    )
    return baseline, candidate, candidate.score >= baseline.score
