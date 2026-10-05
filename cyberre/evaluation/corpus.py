"""The labelled benchmark corpus (ADR-025).

Ground truth is a human judgement, so a case carries the reason for its
label alongside the label. A corpus nobody can argue with is a corpus
nobody can check, and a mislabelled case is indistinguishable from a
broken analyser when the numbers come out wrong.
"""

from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path

from cyberre.core.models.base import DomainModel, NonEmptyStr

DEFAULT_CORPUS_PATH = Path("benchmark") / "corpus.toml"

#: Fraction of cases held out from tuning. A third is small in absolute
#: terms at this corpus size, which the harness reports rather than hides.
HOLDOUT_FRACTION = 1 / 3


class Split(StrEnum):
    TRAIN = "train"
    HOLDOUT = "holdout"


class Case(DomainModel):
    """One labelled artefact."""

    case_id: NonEmptyStr
    path: Path
    vulnerable: bool
    why: NonEmptyStr
    """Why a human says so. Required: an unexplained label cannot be
    reviewed, and a corpus is only as good as its review."""

    cwe: str | None = None

    @property
    def split(self) -> Split:
        """Which split this case belongs to.

        Derived from a hash of the id rather than from position or a
        shuffle, so the assignment is stable: adding a case cannot move
        an existing one from holdout into training, which would quietly
        invalidate every previous measurement.
        """
        digest = hashlib.sha256(self.case_id.encode("utf-8")).digest()
        bucket = int.from_bytes(digest[:8], "big") / float(1 << 64)
        return Split.HOLDOUT if bucket < HOLDOUT_FRACTION else Split.TRAIN


class Corpus(DomainModel):
    """A versioned set of labelled cases."""

    version: NonEmptyStr
    analyser: NonEmptyStr
    cases: tuple[Case, ...]

    def split(self, split: Split) -> tuple[Case, ...]:
        return tuple(case for case in self.cases if case.split is split)

    @property
    def positives(self) -> int:
        return sum(1 for case in self.cases if case.vulnerable)

    @property
    def negatives(self) -> int:
        return len(self.cases) - self.positives

    @classmethod
    def load(cls, path: Path = DEFAULT_CORPUS_PATH) -> Corpus:
        """Read the manifest, resolving case paths against its directory.

        A missing case file raises. A benchmark that silently skips the
        cases it cannot find reports a better score for having lost them.
        """
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        root = path.parent

        cases: list[Case] = []
        seen: set[str] = set()
        for entry in document.get("case", []):
            case_id = str(entry["id"])
            if case_id in seen:
                raise ValueError(f"duplicate case id in corpus: {case_id}")
            seen.add(case_id)

            case_path = root / str(entry["file"])
            if not case_path.is_file():
                raise FileNotFoundError(f"corpus case '{case_id}' is missing: {case_path}")

            cases.append(
                Case(
                    case_id=case_id,
                    path=case_path,
                    vulnerable=bool(entry["vulnerable"]),
                    why=str(entry["why"]),
                    cwe=str(entry["cwe"]) if entry.get("cwe") else None,
                )
            )

        if not cases:
            raise ValueError(f"corpus at {path} contains no cases")

        return cls(
            version=str(document.get("version", "v1")),
            analyser=str(document.get("analyser", "python_taint")),
            cases=tuple(cases),
        )


def describe_balance(cases: Sequence[Case]) -> str:
    """A one-line summary, printed with every result.

    Shown because a precision figure means something different on a
    corpus that is 90% negative, and the reader should not have to go
    looking for the ratio.
    """
    positives = sum(1 for case in cases if case.vulnerable)
    return f"{len(cases)} cases ({positives} vulnerable, {len(cases) - positives} clean)"
