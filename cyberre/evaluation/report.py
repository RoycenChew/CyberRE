"""Rendering a benchmark result.

ASCII only, like the investigation report: a Windows console in the
default code page turns box-drawing characters into mojibake, and a
report an analyst cannot read is not a report.
"""

from __future__ import annotations

from cyberre.evaluation.corpus import Corpus, Split, describe_balance
from cyberre.evaluation.metrics import BenchmarkResult

SEPARATOR = "=" * 70
RULE = "-" * 70


def render(result: BenchmarkResult, *, corpus: Corpus | None = None) -> str:
    detection = result.detection
    calibration = result.calibration

    lines = [
        SEPARATOR,
        f"BENCHMARK: {result.label}",
        SEPARATOR,
    ]

    if corpus is not None:
        lines += [
            f"Corpus {corpus.version} via {corpus.analyser}: {describe_balance(corpus.cases)}",
            f"  train {len(corpus.split(Split.TRAIN))}, holdout {len(corpus.split(Split.HOLDOUT))}",
            "",
        ]

    lines += [
        "DETECTION",
        f"  true positives  {detection.true_positives:3d}    "
        f"false positives {detection.false_positives:3d}",
        f"  true negatives  {detection.true_negatives:3d}    "
        f"false negatives {detection.false_negatives:3d}",
        f"  precision {detection.precision:.3f}   recall {detection.recall:.3f}   "
        f"F1 {detection.f1:.3f}",
        f"  false-positive rate {detection.false_positive_rate:.3f}",
        "",
        "CALIBRATION",
        f"  Brier score                {calibration.brier_score:.4f}  (lower is better)",
        f"  expected calibration error {calibration.expected_calibration_error:.4f}",
        f"  overconfidence             {calibration.overconfidence:+.4f}  "
        f"({'claims more than it earns' if calibration.overconfidence > 0.02 else 'not overconfident'})",
    ]

    if calibration.bins:
        lines.append("  bins (midpoint, n, observed):")
        for midpoint, count, observed in calibration.bins:
            lines.append(f"    {midpoint:.1f}  n={count:<3d} observed={observed:.2f}")

    lines += [
        "",
        f"SCORE {result.score:.4f}  (F1 - calibration error), noise margin +/-{result.margin:.4f}",
    ]

    failures = result.failures()
    lines += ["", RULE]
    if not failures:
        lines.append("No incorrect cases.")
        lines.append(
            "A perfect score on a corpus this size is a regression floor, not "
            "a claim about field accuracy. It means the corpus can no longer"
        )
        lines.append("distinguish between weight sets - grow it before trusting it to rank them.")
    else:
        lines.append(f"{len(failures)} INCORRECT:")
        for outcome in failures:
            lines.append(
                f"  {outcome.kind:<15} {outcome.case_id:<40} conf={outcome.confidence:.3f}"
            )
            if outcome.note:
                lines.append(f"      {outcome.note}")

    lines.append(SEPARATOR)
    return "\n".join(lines)
