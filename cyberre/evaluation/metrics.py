"""Benchmark metrics.

Two families, and the second is the one that matters here.

**Detection** - precision, recall, F1 - asks whether the right cases were
flagged. Familiar, and on its own misleading for this system: CyberRE does
not emit booleans, it emits confidences, and a detector that is right 90%
of the time while saying 0.99 every time scores identically to a
well-calibrated one.

**Calibration** - Brier score, expected calibration error - asks whether
the numbers mean anything. If the cases scored around 0.9 turn out to be
true about 90% of the time, a reader can act on 0.9. If not, the number is
decoration, and every downstream decision built on it is unfounded.

A small corpus cannot resolve small differences, so each result carries a
margin and :func:`distinguishable` refuses to rank two results inside it.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from cyberre.core.models.base import DomainModel

#: Confidence bins for calibration. Ten would be finer, but with a corpus
#: of this size most bins would hold one case and the error estimate would
#: be dominated by which bin a single case fell into.
CALIBRATION_BINS = 5


class Outcome(DomainModel):
    """What the pipeline concluded about one case, against its label."""

    case_id: str
    expected_vulnerable: bool
    reported_vulnerable: bool
    confidence: float
    """The score attached. Zero when nothing was reported - an absent
    finding is a confident claim of absence only if the system says so,
    and this system does not."""

    note: str = ""

    @property
    def correct(self) -> bool:
        return self.reported_vulnerable == self.expected_vulnerable

    @property
    def kind(self) -> str:
        if self.expected_vulnerable:
            return "true_positive" if self.reported_vulnerable else "false_negative"
        return "false_positive" if self.reported_vulnerable else "true_negative"


class DetectionMetrics(DomainModel):
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )

    @property
    def precision(self) -> float:
        """Of what was flagged, how much was real.

        One when nothing was flagged: vacuously perfect, and the recall
        figure next to it is what exposes that.
        """
        flagged = self.true_positives + self.false_positives
        return 1.0 if flagged == 0 else self.true_positives / flagged

    @property
    def recall(self) -> float:
        actual = self.true_positives + self.false_negatives
        return 1.0 if actual == 0 else self.true_positives / actual

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @property
    def false_positive_rate(self) -> float:
        """The number an analyst actually feels.

        Recall sells a scanner; the false-positive rate decides whether
        anyone keeps using it.
        """
        clean = self.true_negatives + self.false_positives
        return 0.0 if clean == 0 else self.false_positives / clean


class CalibrationMetrics(DomainModel):
    brier_score: float
    """Mean squared error between confidence and truth. Lower is better;
    0.25 is what you get by saying 0.5 to everything."""

    expected_calibration_error: float
    """Mean gap between stated confidence and observed accuracy, over
    bins. Lower is better. This is the number that says whether a 0.9
    means anything."""

    overconfidence: float
    """Signed: positive means the system claims more certainty than it
    earns. Worse than the symmetric error, because an overconfident
    finding wastes an analyst's time while an underconfident one only
    wastes the tool's."""

    bins: tuple[tuple[float, int, float], ...] = ()
    """(bin midpoint, count, observed accuracy) for reporting."""


class BenchmarkResult(DomainModel):
    """Everything one run measured."""

    label: str
    detection: DetectionMetrics
    calibration: CalibrationMetrics
    outcomes: tuple[Outcome, ...]

    @property
    def score(self) -> float:
        """The tuner's objective.

        F1 and calibration together, deliberately. Optimising F1 alone
        lets the tuner raise every score to buy recall, which improves
        detection and destroys the meaning of the number; subtracting
        calibration error prices that in.
        """
        return self.detection.f1 - self.calibration.expected_calibration_error

    @property
    def margin(self) -> float:
        """Roughly how much of `score` is noise at this corpus size.

        A binomial standard error on the accuracy. Crude, and far better
        than pretending a 22-case corpus resolves 0.01 of F1.
        """
        n = max(1, self.detection.total)
        correct = self.detection.true_positives + self.detection.true_negatives
        p = correct / n
        return math.sqrt(max(p * (1 - p), 0.01) / n)

    def failures(self) -> tuple[Outcome, ...]:
        """The cases that went wrong - the only interesting ones."""
        return tuple(outcome for outcome in self.outcomes if not outcome.correct)


def detection_metrics(outcomes: Sequence[Outcome]) -> DetectionMetrics:
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
    }
    for outcome in outcomes:
        counts[outcome.kind] += 1
    return DetectionMetrics(
        true_positives=counts["true_positive"],
        false_positives=counts["false_positive"],
        true_negatives=counts["true_negative"],
        false_negatives=counts["false_negative"],
    )


def calibration_metrics(
    outcomes: Sequence[Outcome], *, bin_count: int = CALIBRATION_BINS
) -> CalibrationMetrics:
    """Measure whether the confidences mean what they say."""
    if not outcomes:
        return CalibrationMetrics(
            brier_score=0.0, expected_calibration_error=0.0, overconfidence=0.0
        )

    truth = [1.0 if outcome.expected_vulnerable else 0.0 for outcome in outcomes]
    stated = [outcome.confidence for outcome in outcomes]

    brier = sum((s - t) ** 2 for s, t in zip(stated, truth, strict=True)) / len(outcomes)

    bins: list[tuple[float, int, float]] = []
    error = 0.0
    signed = 0.0
    for index in range(bin_count):
        low = index / bin_count
        high = (index + 1) / bin_count
        # The top bin is closed so a confidence of exactly 1.0 lands
        # somewhere rather than being dropped.
        members = [
            (s, t)
            for s, t in zip(stated, truth, strict=True)
            if (low <= s < high) or (index == bin_count - 1 and s == 1.0)
        ]
        if not members:
            continue
        mean_confidence = sum(s for s, _ in members) / len(members)
        observed = sum(t for _, t in members) / len(members)
        weight = len(members) / len(outcomes)
        error += weight * abs(mean_confidence - observed)
        signed += weight * (mean_confidence - observed)
        bins.append((round((low + high) / 2, 4), len(members), round(observed, 4)))

    return CalibrationMetrics(
        brier_score=round(brier, 6),
        expected_calibration_error=round(error, 6),
        overconfidence=round(signed, 6),
        bins=tuple(bins),
    )


def evaluate(label: str, outcomes: Sequence[Outcome]) -> BenchmarkResult:
    return BenchmarkResult(
        label=label,
        detection=detection_metrics(outcomes),
        calibration=calibration_metrics(outcomes),
        outcomes=tuple(outcomes),
    )


def distinguishable(left: BenchmarkResult, right: BenchmarkResult) -> bool:
    """Whether two results differ by more than the noise.

    Exists so the harness can say "these are the same, as far as this
    corpus can tell" instead of ranking them. Declaring a winner inside
    the margin is how a benchmark starts producing confident nonsense -
    which would be an unusually direct way to undermine this project.
    """
    return abs(left.score - right.score) > max(left.margin, right.margin)
