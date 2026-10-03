"""Shared model configuration and identifier helpers."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

#: A lowercase hex SHA-256 digest.
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: A non-empty, stripped string. Used wherever an empty value would be a bug
#: rather than a legitimate absence.
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]


class DomainModel(BaseModel):
    """Base for every domain object.

    Frozen and strict by construction:

    * ``frozen`` - domain objects are records of something that happened.
      A correction is a new object, not a mutation of the old one, because
      an audit trail that can be edited in place is not an audit trail.
    * ``extra="forbid"`` - an unexpected field is a typo or a schema drift,
      and silently keeping it loses the error.
    * ``validate_assignment`` is unnecessary given ``frozen``.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        use_enum_values=False,
        validate_default=True,
    )


def new_id(prefix: str) -> str:
    """Generate a readable unique identifier, e.g. ``ev-3f2a...``.

    Prefixed so an identifier is self-describing in a log line or a report.
    """
    return f"{prefix}-{uuid.uuid4().hex}"


def utcnow() -> datetime:
    """Timezone-aware current time.

    Naive datetimes are a reproducibility hazard: an investigation replayed in
    another timezone must produce the same record.
    """
    return datetime.now(UTC)


def sha256_hex(data: bytes) -> str:
    """SHA-256 of `data` as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


def stable_digest(*parts: str) -> str:
    """A deterministic digest over `parts`, used for content-derived keys.

    Parts are joined with a separator that cannot appear in them unescaped, so
    ``("a", "bc")`` and ``("ab", "c")`` do not collide.
    """
    joined = "\x1f".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


TimestampField = Field(default_factory=utcnow)
