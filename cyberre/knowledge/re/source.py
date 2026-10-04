"""The structured RE knowledge source.

Deterministic lookup over versioned data files. No embeddings, no similarity,
no model: the same query returns the same record, which is what lets a
knowledge-derived finding be reproduced and re-examined.

`is_authoritative` is True here. The semantic layer (M16) will answer the same
protocol with False, and the validation engine treats the two differently -
a passage that reads as relevant is not a fact that applies (ADR-017).
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from cyberre.core.models.base import NonEmptyStr, stable_digest
from cyberre.core.models.observation import KnowledgeRecord
from cyberre.knowledge.re.schema import (
    Applicability,
    DangerClass,
    KnowledgeDomain,
    KnowledgeEntry,
)

DEFAULT_DATA_DIR = Path(__file__).parent / "data"


class KnowledgeLoadError(ValueError):
    """A knowledge file is malformed, or two records claim the same id.

    Loading is strict. These records become evidence, and evidence built from
    a half-understood file would carry provenance implying more care than was
    taken.
    """


def _entry_from(raw: dict[str, Any], *, domain: KnowledgeDomain, path: Path) -> KnowledgeEntry:
    data = dict(raw)
    data.setdefault("domain", domain.value)

    for key in ("aliases", "companions", "attack", "cwe", "indicators"):
        if key in data:
            data[key] = tuple(data[key])

    applicability = data.get("applicability")
    if isinstance(applicability, dict):
        data["applicability"] = Applicability(
            os=frozenset(str(v).lower() for v in applicability.get("os", [])),
            architectures=frozenset(str(v).lower() for v in applicability.get("architectures", [])),
            formats=frozenset(str(v).lower() for v in applicability.get("formats", [])),
            min_version=applicability.get("min_version"),
        )

    try:
        return KnowledgeEntry.model_validate(data)
    except ValueError as error:
        identifier = raw.get("id", "<no id>")
        raise KnowledgeLoadError(f"{path}: record '{identifier}': {error}") from error


def load_file(path: Path) -> list[KnowledgeEntry]:
    """Load every record in one data file."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise KnowledgeLoadError(f"{path}: not valid TOML: {error}") from error
    except OSError as error:
        raise KnowledgeLoadError(f"{path}: cannot be read: {error}") from error

    raw_domain = document.get("domain")
    if raw_domain is None:
        raise KnowledgeLoadError(f"{path}: the file must declare a 'domain'")
    try:
        domain = KnowledgeDomain(raw_domain)
    except ValueError as error:
        raise KnowledgeLoadError(f"{path}: unknown domain '{raw_domain}'") from error

    records = document.get("record", [])
    if not isinstance(records, list):
        raise KnowledgeLoadError(f"{path}: 'record' must be an array of tables")

    return [_entry_from(raw, domain=domain, path=path) for raw in records]


class StructuredKnowledgeSource:
    """Deterministic lookup over the loaded RE knowledge.

    Satisfies :class:`~cyberre.core.contracts.knowledge.KnowledgeSource`.
    """

    def __init__(
        self, entries: Iterable[KnowledgeEntry], *, source_id: str = "knowledge.re"
    ) -> None:
        self._source_id = source_id
        self._by_id: dict[str, KnowledgeEntry] = {}
        self._by_alias: dict[str, KnowledgeEntry] = {}

        for entry in entries:
            if entry.id in self._by_id:
                raise KnowledgeLoadError(f"duplicate knowledge record id '{entry.id}'")
            self._by_id[entry.id] = entry

            for name in (_leaf(entry.id), *entry.aliases):
                key = name.lower()
                # First writer wins, and collisions are an error rather than a
                # silent overwrite: two records answering to one symbol would
                # make lookup depend on file ordering.
                if key in self._by_alias and self._by_alias[key].id != entry.id:
                    raise KnowledgeLoadError(
                        f"'{name}' resolves to both '{self._by_alias[key].id}' and '{entry.id}'"
                    )
                self._by_alias[key] = entry

    @classmethod
    def from_directory(cls, directory: Path = DEFAULT_DATA_DIR) -> StructuredKnowledgeSource:
        if not directory.is_dir():
            raise KnowledgeLoadError(f"no knowledge directory at {directory}")
        entries: list[KnowledgeEntry] = []
        for path in sorted(directory.glob("*.toml")):
            entries.extend(load_file(path))
        return cls(entries)

    # ------------------------------------------------------------ protocol

    @property
    def source_id(self) -> str:
        return self._source_id

    @property
    def version(self) -> str:
        """A digest over every record, so the knowledge set is pinnable.

        A file-count or a date would not change when a record's content did.
        This changes whenever any claim changes, which is what provenance
        needs in order to be re-examinable.
        """
        parts = [f"{entry.id}@{entry.version}" for entry in self.all_entries()]
        return stable_digest(*parts)[:16]

    @property
    def is_authoritative(self) -> bool:
        """Deterministic lookup, so this may satisfy a requirement.

        The semantic layer answers False here and may not (ADR-017).
        """
        return True

    def lookup(self, key: NonEmptyStr) -> KnowledgeRecord | None:
        """Exact lookup by record id, symbol name or alias.

        Returns ``None`` on a miss, never an approximation. A knowledge base
        that guesses is worse than one that is silent, because the guess
        arrives wearing the same provenance as a fact.
        """
        entry = self.entry(key)
        return None if entry is None else self.to_record(entry)

    def search(self, query: NonEmptyStr, *, limit: int = 10) -> Sequence[KnowledgeRecord]:
        """Substring scan over ids, aliases and statements.

        A filtered scan, not similarity. Ordering is deterministic: exact
        matches first, then by id, so repeated runs agree.
        """
        needle = query.lower()
        exact: list[KnowledgeEntry] = []
        partial: list[KnowledgeEntry] = []
        for entry in self.all_entries():
            names = {_leaf(entry.id).lower(), *(a.lower() for a in entry.aliases)}
            if needle in names:
                exact.append(entry)
            elif needle in entry.id.lower() or needle in entry.statement.lower():
                partial.append(entry)
        return [self.to_record(e) for e in (exact + partial)[:limit]]

    # ------------------------------------------------------------- queries

    def entry(self, key: str) -> KnowledgeEntry | None:
        """The typed entry, for callers that need the domain-specific fields."""
        if key in self._by_id:
            return self._by_id[key]
        return self._by_alias.get(key.lower())

    def all_entries(self) -> Sequence[KnowledgeEntry]:
        return [self._by_id[key] for key in sorted(self._by_id)]

    def in_domain(self, domain: KnowledgeDomain) -> Sequence[KnowledgeEntry]:
        return [e for e in self.all_entries() if e.domain is domain]

    def with_danger_class(self, danger_class: DangerClass) -> Sequence[KnowledgeEntry]:
        return [e for e in self.all_entries() if e.danger_class is danger_class]

    def applicable(
        self,
        entries: Iterable[KnowledgeEntry],
        *,
        os_name: str | None = None,
        architecture: str | None = None,
        binary_format: str | None = None,
    ) -> Sequence[KnowledgeEntry]:
        return [
            entry
            for entry in entries
            if entry.applicability.matches(
                os_name=os_name, architecture=architecture, binary_format=binary_format
            )
        ]

    def to_record(self, entry: KnowledgeEntry) -> KnowledgeRecord:
        """Convert to the observation form that becomes evidence."""
        return KnowledgeRecord(
            record_id=entry.id,
            record_version=entry.version,
            statement=entry.statement,
            source_ref=entry.source_ref,
            source_confidence=entry.confidence,
            applicability=_applicability_map(entry.applicability),
        )

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and self.entry(key) is not None


def _leaf(record_id: str) -> str:
    """The last dotted component, which is how a symbol is usually named."""
    return record_id.rsplit(".", 1)[-1]


def _applicability_map(applicability: Applicability) -> dict[str, str]:
    result: dict[str, str] = {}
    if applicability.os:
        result["os"] = ",".join(sorted(applicability.os))
    if applicability.architectures:
        result["architectures"] = ",".join(sorted(applicability.architectures))
    if applicability.formats:
        result["formats"] = ",".join(sorted(applicability.formats))
    if applicability.min_version:
        result["min_version"] = applicability.min_version
    return result
