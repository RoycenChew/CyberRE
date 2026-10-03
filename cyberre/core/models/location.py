"""Where an observation was made.

A discriminated union rather than a string, because "line 42" and "address
0x401230" and "package lodash@4.17.20" are not the same kind of thing, and
validation needs to compare them structurally.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from cyberre.core.models.base import DomainModel, NonEmptyStr


class SourceLocation(DomainModel):
    kind: Literal["source"] = "source"
    path: NonEmptyStr
    """Path relative to the scope root. Never absolute - an absolute path leaks
    the analyst's filesystem into a report and breaks reproducibility."""

    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = None

    def __str__(self) -> str:
        span = (
            f"{self.start_line}" if self.end_line is None else f"{self.start_line}-{self.end_line}"
        )
        return f"{self.path}:{span}"


class BinaryLocation(DomainModel):
    kind: Literal["binary"] = "binary"
    address: int = Field(ge=0)
    function: str | None = None
    section: str | None = None

    def __str__(self) -> str:
        where = f"0x{self.address:08x}"
        return f"{self.function}@{where}" if self.function else where


class PackageLocation(DomainModel):
    kind: Literal["package"] = "package"
    ecosystem: NonEmptyStr
    """e.g. ``pypi``, ``npm``, ``maven``."""

    name: NonEmptyStr
    version: str | None = None
    manifest_path: str | None = None

    def __str__(self) -> str:
        version = self.version or "unpinned"
        return f"{self.ecosystem}:{self.name}@{version}"


class ArtefactLocation(DomainModel):
    """The artefact as a whole - for observations with no finer position."""

    kind: Literal["artefact"] = "artefact"
    detail: str | None = None

    def __str__(self) -> str:
        return self.detail or "artefact"


class RuntimeLocation(DomainModel):
    """A point in observed execution, for sandbox telemetry."""

    kind: Literal["runtime"] = "runtime"
    process: str | None = None
    api: str | None = None
    sequence: int | None = Field(default=None, ge=0)

    def __str__(self) -> str:
        return self.api or self.process or "runtime"


Location = Annotated[
    SourceLocation | BinaryLocation | PackageLocation | ArtefactLocation | RuntimeLocation,
    Field(discriminator="kind"),
]
