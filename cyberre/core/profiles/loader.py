"""Loading profiles from disk and selecting one for an investigation."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from cyberre.core.models.enums import ArtefactType, ProfileId
from cyberre.core.profiles.model import AnalysisProfile

#: Where profiles live, relative to the repository root.
DEFAULT_PROFILE_DIR = Path("profiles")


class ProfileLoadError(ValueError):
    """A profile file is malformed or contradicts another.

    Loading is strict. A profile decides what an investigation does and what
    evidence it demands; accepting a half-understood one would be a quiet way
    to change those answers.
    """


def _coerce(data: dict[str, Any]) -> dict[str, Any]:
    """Convert TOML's lists into the tuple and frozenset shapes the model uses.

    Done explicitly rather than by loosening the model, so the model keeps
    saying what it means.
    """
    converted = dict(data)
    for key in ("preferred_capabilities", "hypothesis_classes", "knowledge_sources"):
        if key in converted:
            converted[key] = tuple(converted[key])
    for key in ("forbidden_capabilities", "applicable_artefact_types"):
        if key in converted:
            converted[key] = frozenset(converted[key])
    return converted


def load_profile(path: Path) -> AnalysisProfile:
    """Load one profile from a TOML file."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ProfileLoadError(f"{path}: not valid TOML: {error}") from error
    except OSError as error:
        raise ProfileLoadError(f"{path}: cannot be read: {error}") from error

    try:
        return AnalysisProfile.model_validate(_coerce(raw))
    except ValueError as error:
        raise ProfileLoadError(f"{path}: {error}") from error


class ProfileRegistry:
    """The profiles available to this deployment."""

    def __init__(self, profiles: Iterable[AnalysisProfile]) -> None:
        self._profiles: dict[ProfileId, AnalysisProfile] = {}
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise ProfileLoadError(
                    f"profile '{profile.profile_id.value}' is defined more than once"
                )
            self._profiles[profile.profile_id] = profile

    @classmethod
    def from_directory(cls, directory: Path = DEFAULT_PROFILE_DIR) -> ProfileRegistry:
        if not directory.is_dir():
            raise ProfileLoadError(f"no profile directory at {directory}")
        return cls(load_profile(path) for path in sorted(directory.glob("*.toml")))

    def get(self, profile_id: ProfileId) -> AnalysisProfile:
        if profile_id not in self._profiles:
            raise KeyError(f"no profile '{profile_id.value}' is available")
        return self._profiles[profile_id]

    def all_profiles(self) -> Sequence[AnalysisProfile]:
        return [self._profiles[key] for key in sorted(self._profiles, key=lambda p: p.value)]

    def implemented(self) -> Sequence[AnalysisProfile]:
        return [p for p in self.all_profiles() if p.implemented]

    def declared_but_unimplemented(self) -> Sequence[AnalysisProfile]:
        """Visible on purpose, so the gap is known rather than discovered."""
        return [p for p in self.all_profiles() if not p.implemented]

    def for_artefact_type(self, artefact_type: ArtefactType) -> Sequence[AnalysisProfile]:
        return [p for p in self.implemented() if artefact_type in p.applicable_artefact_types]

    def __len__(self) -> int:
        return len(self._profiles)

    def __contains__(self, profile_id: object) -> bool:
        return profile_id in self._profiles


#: Which profile to prefer when an artefact type matches several. Ordered by
#: how specific the analysis is: a PE file is better served by binary reverse
#: engineering than by a dependency scan, even though both can run.
_SELECTION_PRIORITY: tuple[ProfileId, ...] = (
    ProfileId.BINARY_RE,
    ProfileId.SOURCE_SECURITY,
    ProfileId.DEPENDENCY_SECURITY,
    ProfileId.MALWARE_ANALYSIS,
)


def select_profiles(
    registry: ProfileRegistry,
    *,
    artefact_types: Iterable[ArtefactType],
    requested: Iterable[ProfileId] = (),
) -> list[AnalysisProfile]:
    """Choose the profiles for an investigation.

    An explicit request wins outright, including a request for something
    unimplemented - which then fails loudly. Guessing around an explicit
    instruction would be worse than refusing it.

    Otherwise one profile is inferred per artefact type, by the priority
    above. Inference is deterministic: the same inputs must choose the same
    profiles, or investigations stop being reproducible.
    """
    explicit = list(requested)
    if explicit:
        chosen = [registry.get(profile_id) for profile_id in explicit]
        for profile in chosen:
            profile.require_implemented()
        return chosen

    selected: list[AnalysisProfile] = []
    for artefact_type in artefact_types:
        candidates = registry.for_artefact_type(artefact_type)
        if not candidates:
            continue
        best = min(
            candidates,
            key=lambda p: (
                _SELECTION_PRIORITY.index(p.profile_id)
                if p.profile_id in _SELECTION_PRIORITY
                else len(_SELECTION_PRIORITY),
                p.profile_id.value,
            ),
        )
        if best not in selected:
            selected.append(best)
    return selected
