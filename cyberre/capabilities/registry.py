"""The capability registry.

Holds specifications, not implementations, so the planner can rank actions
without importing an adapter. Prerequisites are checked against evidence that
actually exists, which is what stops the planner asking to decompile a
function in a binary nobody has analysed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from cyberre.core.contracts.capability import CapabilitySpec
from cyberre.core.models.enums import ArtefactType, EvidenceType


class DuplicateCapabilityError(ValueError):
    """Two capabilities claimed the same id.

    An error rather than a last-one-wins overwrite: silently replacing a
    registration would change which tool runs, with no sign that it happened.
    """


class InMemoryCapabilityRegistry:
    """A registry built from a fixed set of specifications."""

    def __init__(self, specs: Iterable[CapabilitySpec] = ()) -> None:
        self._specs: dict[str, CapabilitySpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: CapabilitySpec) -> None:
        if spec.capability_id in self._specs:
            raise DuplicateCapabilityError(f"'{spec.capability_id}' is already registered")
        self._specs[spec.capability_id] = spec

    def get(self, capability_id: str) -> CapabilitySpec:
        if capability_id not in self._specs:
            raise KeyError(f"no capability '{capability_id}' is registered")
        return self._specs[capability_id]

    def all_specs(self) -> Sequence[CapabilitySpec]:
        # Sorted by id so planning order does not depend on registration
        # order, which would make an investigation unreproducible.
        return [self._specs[key] for key in sorted(self._specs)]

    def for_artefact_type(self, artefact_type: ArtefactType) -> Sequence[CapabilitySpec]:
        return [s for s in self.all_specs() if artefact_type in s.artefact_types]

    def producing(self, evidence_type: EvidenceType) -> Sequence[CapabilitySpec]:
        """Capabilities that can yield this kind of evidence.

        The planner's primary query. It asks "what would tell me the thing I
        am missing?" rather than "what tools exist?".
        """
        return [s for s in self.all_specs() if evidence_type in s.produces]

    def unmet_prerequisites(
        self, capability_id: str, *, satisfied: Iterable[str]
    ) -> tuple[str, ...]:
        """Prerequisites of `capability_id` not present in `satisfied`.

        `satisfied` is the set of capability ids that have already produced
        evidence in this investigation. Returning the unmet ones rather than
        a boolean lets the planner schedule them instead of giving up.
        """
        spec = self.get(capability_id)
        done = set(satisfied)
        return tuple(p for p in spec.prerequisites if p not in done)

    def is_runnable(self, capability_id: str, *, satisfied: Iterable[str]) -> bool:
        return not self.unmet_prerequisites(capability_id, satisfied=satisfied)

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, capability_id: object) -> bool:
        return capability_id in self._specs
