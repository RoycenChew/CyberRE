# ADR-020: Storage uses the standard library, not an ORM

## Status
Accepted. Narrows ADR-005, which named SQLAlchemy Core and Alembic.

## Context
ADR-005 settled the important question - storage sits behind protocols, SQLite
now, PostgreSQL later - and then named SQLAlchemy and Alembic as the means. On
building it, the means look heavier than the job.

What CyberRE stores is a small number of record types with a stable shape:
evidence, claims, failures, artefacts, hypotheses, findings, state. Queries are
by primary key and by `investigation_id`. There are no joins worth optimising,
no lazy loading, and no object graph to map - the domain objects are already
Pydantic models that serialise themselves.

The portability argument for an ORM does not apply here either, because the
portability boundary is the protocol, not the SQL. A PostgreSQL implementation
satisfies `EvidenceStore` and passes the same contract suite; whether it shares
a query builder with the SQLite one is an implementation detail, and the ~60
lines of SQL involved are not where the difficulty lies.

## Decision
Implement storage with `sqlite3` from the standard library. Persist each domain
object as validated JSON in a `payload` column, with the fields that are
actually queried promoted to indexed columns. Migrations are ordered SQL
statements applied against a `schema_version` table, in the adapter.

`sqlite3` is added to the vendor-confinement table, so it cannot be imported
outside `cyberre.adapters.storage` even though it is stdlib. Being bundled with
Python does not make it less of an engine choice.

## Consequences
No ORM, no migration framework, and no runtime dependency for storage. The
schema is readable in one file.

The cost is that a PostgreSQL adapter writes its own SQL rather than inheriting
a dialect layer. That is a known, bounded cost at M16, and it buys a core that
depends on nothing but Pydantic.

If the data model later grows relationships worth querying relationally -
rather than traversing in the evidence graph - this decision should be revisited
in a superseding ADR rather than worked around.
