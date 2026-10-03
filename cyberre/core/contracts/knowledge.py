"""Knowledge source contract.

Structured and semantic knowledge expose the same interface but are not
interchangeable: `is_authoritative` distinguishes a deterministic lookup from a
similarity search, and only authoritative sources may contribute evidence that
satisfies a validation requirement (ADR-017).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from cyberre.core.models.base import NonEmptyStr
from cyberre.core.models.observation import KnowledgeRecord


@runtime_checkable
class KnowledgeSource(Protocol):
    """A body of security knowledge."""

    @property
    def source_id(self) -> str: ...

    @property
    def version(self) -> str:
        """Recorded in provenance, so a finding that leaned on a knowledge
        claim can be revisited when that claim is revised."""
        ...

    @property
    def is_authoritative(self) -> bool:
        """True for deterministic structured lookup.

        False for semantic retrieval, which may inform a hypothesis but may
        never satisfy a validation requirement - a passage that reads as
        relevant is not the same as a fact that applies.
        """
        ...

    def lookup(self, key: NonEmptyStr) -> KnowledgeRecord | None:
        """Exact lookup. Returns ``None`` on a miss, never a guess."""
        ...

    def search(self, query: NonEmptyStr, *, limit: int = 10) -> Sequence[KnowledgeRecord]:
        """Find candidate records.

        For a structured source this is a filtered scan; for a semantic source
        it is similarity. Either way the results are candidates, and the
        caller must respect :attr:`is_authoritative` when using them.
        """
        ...
