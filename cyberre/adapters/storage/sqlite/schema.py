"""SQLite schema and migrations.

Ordered statements applied against a ``schema_version`` table (ADR-020). Each
record is stored as validated JSON in ``payload``, with the fields actually
queried promoted to indexed columns. The domain models already serialise
themselves, so mapping them field by field would buy nothing and would add a
second place for the schema to drift from the models.
"""

from __future__ import annotations

import sqlite3
from typing import Final

#: Migrations in order. Append only - never edit a shipped migration, because
#: a database somewhere has already applied it and would not see the change.
MIGRATIONS: Final[tuple[tuple[int, str], ...]] = (
    (
        1,
        """
        CREATE TABLE investigations (
            investigation_id TEXT PRIMARY KEY,
            status           TEXT NOT NULL,
            updated_at       TEXT NOT NULL,
            payload          TEXT NOT NULL
        );

        CREATE TABLE artefacts (
            artefact_id TEXT PRIMARY KEY,
            sha256      TEXT NOT NULL,
            payload     TEXT NOT NULL
        );
        CREATE INDEX idx_artefacts_sha256 ON artefacts (sha256);

        -- Evidence, agent claims and tool failures are separate tables, not
        -- one table with a discriminator. Invariant 2 says an agent claim can
        -- never satisfy a validation requirement, and the cheapest way to
        -- guarantee that at the storage layer is to make "select the evidence"
        -- physically unable to return one.
        CREATE TABLE evidence (
            evidence_id      TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            artefact_id      TEXT NOT NULL,
            evidence_type    TEXT NOT NULL,
            independence_key TEXT NOT NULL,
            created_at       TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_evidence_investigation ON evidence (investigation_id);
        CREATE INDEX idx_evidence_independence ON evidence (independence_key);

        CREATE TABLE agent_claims (
            claim_id         TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            agent            TEXT NOT NULL,
            created_at       TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_claims_investigation ON agent_claims (investigation_id);

        CREATE TABLE tool_failures (
            failure_id       TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            capability_id    TEXT NOT NULL,
            occurred_at      TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_failures_investigation ON tool_failures (investigation_id);

        CREATE TABLE hypotheses (
            hypothesis_id    TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            status           TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_hypotheses_investigation ON hypotheses (investigation_id);

        CREATE TABLE candidate_findings (
            candidate_id     TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            hypothesis_id    TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_candidates_investigation
            ON candidate_findings (investigation_id);

        CREATE TABLE findings (
            finding_id       TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            hypothesis_id    TEXT NOT NULL,
            status           TEXT NOT NULL,
            payload          TEXT NOT NULL
        );
        CREATE INDEX idx_findings_investigation ON findings (investigation_id);
        """,
    ),
)

#: The version a freshly migrated database reports.
LATEST_VERSION: Final[int] = max(version for version, _ in MIGRATIONS)


def current_version(connection: sqlite3.Connection) -> int:
    """Schema version of `connection`, or 0 for an empty database."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_version ("
        " version INTEGER PRIMARY KEY,"
        " applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    row = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def migrate(connection: sqlite3.Connection) -> int:
    """Apply outstanding migrations and return the resulting version.

    Each migration runs inside a transaction with its version row, so a
    failure leaves the database at the previous version rather than in a
    half-applied state that the next startup would mistake for complete.
    """
    version = current_version(connection)
    for target, statements in MIGRATIONS:
        if target <= version:
            continue
        with connection:
            connection.executescript(statements)
            connection.execute("INSERT INTO schema_version (version) VALUES (?)", (target,))
        version = target
    return version
