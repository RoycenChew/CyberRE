"""Artefacts: the things under analysis, identified by content."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from cyberre.core.models.base import DomainModel, NonEmptyStr, Sha256, TimestampField, new_id
from cyberre.core.models.enums import ArtefactType


class Artefact(DomainModel):
    """Something submitted for analysis.

    Identified by SHA-256 rather than by path, so that caching, provenance and
    replay all key off the exact bytes examined. A path is metadata; it can
    change under us, and two different files can share one.
    """

    artefact_id: str = Field(default_factory=lambda: new_id("ar"))
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    artefact_type: ArtefactType
    display_name: NonEmptyStr
    """A name for reports. Never used to locate the artefact."""

    object_store_ref: str | None = None
    """Where the bytes live. ``None`` for a directory tree analysed in place."""

    media_type: str | None = None
    parent_artefact_id: str | None = None
    """Set for an artefact extracted from another, e.g. a file in an archive."""

    is_untrusted: bool = True
    """Everything submitted is hostile until shown otherwise.

    Defaulting to trusted would make the safe path the one requiring an extra
    step, which is how analysis platforms end up executing samples on the host.
    """

    ingested_at: datetime = TimestampField

    @model_validator(mode="after")
    def _source_trees_have_no_blob(self) -> Artefact:
        if self.artefact_type is ArtefactType.SOURCE_TREE and self.object_store_ref is not None:
            raise ValueError(
                "a source tree is analysed in place; storing it as a single blob "
                "would make per-file provenance impossible"
            )
        return self
