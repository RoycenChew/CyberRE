"""SQLite implementation of the evidence and investigation stores."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from pathlib import Path
from types import TracebackType

from cyberre.adapters.storage.sqlite.schema import migrate
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.evidence import AgentClaimRecord, Evidence, ToolFailure
from cyberre.core.models.finding import CandidateFinding, Finding
from cyberre.core.models.hypothesis import Hypothesis
from cyberre.core.models.state import InvestigationState
from pydantic import BaseModel

#: In-memory database path, for tests and for replay runs that should leave
#: nothing behind.
MEMORY = ":memory:"


class SqliteStore:
    """Evidence and investigation storage in one SQLite database.

    Satisfies both :class:`~cyberre.core.contracts.storage.EvidenceStore` and
    :class:`~cyberre.core.contracts.storage.InvestigationStore`. They are
    separate protocols because they are separate concerns, but splitting one
    investigation's records across two databases would buy nothing and make
    consistency harder.

    Writes are idempotent: storing the same record twice replaces it rather
    than failing. Re-running a capability after a crash should converge, not
    error.
    """

    def __init__(self, path: Path | str = MEMORY) -> None:
        self._connection = sqlite3.connect(str(path))
        self._connection.row_factory = sqlite3.Row
        # Enforced per connection, not per database, so it is set here rather
        # than assumed.
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        migrate(self._connection)

    # ------------------------------------------------------------ lifecycle

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SqliteStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -------------------------------------------------------------- helpers

    def _upsert(self, table: str, columns: dict[str, object]) -> None:
        names = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        with self._connection:
            self._connection.execute(
                f"INSERT OR REPLACE INTO {table} ({names}) VALUES ({placeholders})",
                tuple(columns.values()),
            )

    def _fetch_one[ModelT: BaseModel](
        self, table: str, key_column: str, key: str, model: type[ModelT]
    ) -> ModelT:
        row = self._connection.execute(
            f"SELECT payload FROM {table} WHERE {key_column} = ?", (key,)
        ).fetchone()
        if row is None:
            raise KeyError(f"no row '{key}' in {table}")
        return model.model_validate_json(row["payload"])

    def _fetch_for_investigation[ModelT: BaseModel](
        self, table: str, investigation_id: str, model: type[ModelT], order_by: str
    ) -> Sequence[ModelT]:
        rows = self._connection.execute(
            f"SELECT payload FROM {table} WHERE investigation_id = ? ORDER BY {order_by}",
            (investigation_id,),
        ).fetchall()
        return [model.model_validate_json(row["payload"]) for row in rows]

    # ------------------------------------------------------- EvidenceStore

    def add_evidence(self, evidence: Evidence) -> None:
        self._upsert(
            "evidence",
            {
                "evidence_id": evidence.evidence_id,
                "investigation_id": evidence.investigation_id,
                "artefact_id": evidence.artefact_id,
                "evidence_type": evidence.evidence_type.value,
                "independence_key": evidence.independence_key,
                "created_at": evidence.created_at.isoformat(),
                "payload": evidence.model_dump_json(),
            },
        )

    def add_many(self, evidence: Iterable[Evidence]) -> None:
        for item in evidence:
            self.add_evidence(item)

    def get_evidence(self, evidence_id: str) -> Evidence:
        return self._fetch_one("evidence", "evidence_id", evidence_id, Evidence)

    def list_evidence(self, investigation_id: str) -> Sequence[Evidence]:
        # Ordered by creation then id: creation order is what an analyst
        # expects, and the id tiebreak keeps replay byte-identical when two
        # records share a timestamp.
        return self._fetch_for_investigation(
            "evidence", investigation_id, Evidence, "created_at, evidence_id"
        )

    def add_agent_claim(self, claim: AgentClaimRecord) -> None:
        self._upsert(
            "agent_claims",
            {
                "claim_id": claim.claim_id,
                "investigation_id": claim.investigation_id,
                "agent": claim.agent,
                "created_at": claim.created_at.isoformat(),
                "payload": claim.model_dump_json(),
            },
        )

    def list_agent_claims(self, investigation_id: str) -> Sequence[AgentClaimRecord]:
        return self._fetch_for_investigation(
            "agent_claims", investigation_id, AgentClaimRecord, "created_at, claim_id"
        )

    def add_tool_failure(self, failure: ToolFailure) -> None:
        self._upsert(
            "tool_failures",
            {
                "failure_id": failure.failure_id,
                "investigation_id": failure.investigation_id,
                "capability_id": failure.capability_id,
                "occurred_at": failure.occurred_at.isoformat(),
                "payload": failure.model_dump_json(),
            },
        )

    def list_tool_failures(self, investigation_id: str) -> Sequence[ToolFailure]:
        return self._fetch_for_investigation(
            "tool_failures", investigation_id, ToolFailure, "occurred_at, failure_id"
        )

    # -------------------------------------------------- InvestigationStore

    def save_state(self, state: InvestigationState) -> None:
        state.check_size()
        self._upsert(
            "investigations",
            {
                "investigation_id": state.investigation_id,
                "status": state.status.value,
                "updated_at": state.updated_at.isoformat(),
                "payload": state.model_dump_json(),
            },
        )

    def load_state(self, investigation_id: str) -> InvestigationState:
        return self._fetch_one(
            "investigations", "investigation_id", investigation_id, InvestigationState
        )

    def add_artefact(self, artefact: Artefact) -> None:
        self._upsert(
            "artefacts",
            {
                "artefact_id": artefact.artefact_id,
                "sha256": artefact.sha256,
                "payload": artefact.model_dump_json(),
            },
        )

    def get_artefact(self, artefact_id: str) -> Artefact:
        return self._fetch_one("artefacts", "artefact_id", artefact_id, Artefact)

    def find_artefact_by_hash(self, sha256: str) -> Artefact | None:
        """Look an artefact up by content.

        Content addressing is what makes caching safe: the same bytes are the
        same artefact, whatever path they arrived by.
        """
        row = self._connection.execute(
            "SELECT payload FROM artefacts WHERE sha256 = ? ORDER BY artefact_id LIMIT 1",
            (sha256,),
        ).fetchone()
        return None if row is None else Artefact.model_validate_json(row["payload"])

    def save_hypothesis(self, hypothesis: Hypothesis) -> None:
        self._upsert(
            "hypotheses",
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "investigation_id": hypothesis.investigation_id,
                "status": hypothesis.status.value,
                "payload": hypothesis.model_dump_json(),
            },
        )

    def list_hypotheses(self, investigation_id: str) -> Sequence[Hypothesis]:
        return self._fetch_for_investigation(
            "hypotheses", investigation_id, Hypothesis, "hypothesis_id"
        )

    def save_candidate(self, candidate: CandidateFinding) -> None:
        self._upsert(
            "candidate_findings",
            {
                "candidate_id": candidate.candidate_id,
                "investigation_id": candidate.investigation_id,
                "hypothesis_id": candidate.hypothesis_id,
                "payload": candidate.model_dump_json(),
            },
        )

    def list_candidates(self, investigation_id: str) -> Sequence[CandidateFinding]:
        return self._fetch_for_investigation(
            "candidate_findings", investigation_id, CandidateFinding, "candidate_id"
        )

    def save_finding(self, finding: Finding) -> None:
        self._upsert(
            "findings",
            {
                "finding_id": finding.finding_id,
                "investigation_id": finding.investigation_id,
                "hypothesis_id": finding.hypothesis_id,
                "status": finding.status.value,
                "payload": finding.model_dump_json(),
            },
        )

    def list_findings(self, investigation_id: str) -> Sequence[Finding]:
        return self._fetch_for_investigation("findings", investigation_id, Finding, "finding_id")
