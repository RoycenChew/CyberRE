"""Analysis profiles: loading, selection and merging.

The invariant-3 tests live in `tests/security/test_profile_policy.py`, since
"a profile cannot grant permission" is a security control rather than a
modelling detail.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.core.models.enums import ArtefactType, Depth, ProfileId, RiskLevel
from cyberre.core.profiles.loader import (
    ProfileLoadError,
    ProfileRegistry,
    load_profile,
    select_profiles,
)
from cyberre.core.profiles.model import (
    AnalysisProfile,
    ProfileNotImplementedError,
    ProfilePolicyRequest,
    merge_profiles,
)

pytestmark = pytest.mark.unit

PROFILE_DIR = Path(__file__).resolve().parents[2] / "profiles"


@pytest.fixture(scope="module")
def registry() -> ProfileRegistry:
    return ProfileRegistry.from_directory(PROFILE_DIR)


def a_profile(**overrides: object) -> AnalysisProfile:
    defaults: dict[str, object] = {
        "profile_id": ProfileId.SOURCE_SECURITY,
        "name": "Test",
        "description": "Test profile",
    }
    return AnalysisProfile(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestShippedProfiles:
    def test_all_seven_are_declared(self, registry: ProfileRegistry) -> None:
        assert len(registry) == len(ProfileId)

    def test_four_are_implemented(self, registry: ProfileRegistry) -> None:
        assert {p.profile_id for p in registry.implemented()} == {
            ProfileId.BINARY_RE,
            ProfileId.SOURCE_SECURITY,
            ProfileId.DEPENDENCY_SECURITY,
            ProfileId.MALWARE_ANALYSIS,
        }

    def test_stubs_are_visible_not_hidden(self, registry: ProfileRegistry) -> None:
        """So the gap is known rather than discovered."""
        assert {p.profile_id for p in registry.declared_but_unimplemented()} == {
            ProfileId.VULNERABILITY_RESEARCH,
            ProfileId.THREAT_HUNTING,
            ProfileId.INCIDENT_INVESTIGATION,
        }

    def test_every_hypothesis_class_has_a_requirement_set(self, registry: ProfileRegistry) -> None:
        """A class with no requirements could never be validated, so a
        hypothesis of that class would hang in UNVALIDATED for ever."""
        for profile in registry.implemented():
            missing = [
                hypothesis_class
                for hypothesis_class in profile.hypothesis_classes
                if hypothesis_class not in profile.requirement_sets
            ]
            assert not missing, f"{profile.profile_id.value}: {missing}"

    def test_malware_analysis_is_static_only_in_v1(self, registry: ProfileRegistry) -> None:
        """Until the sandbox is hardened, this profile reads samples rather
        than running them (THREAT_MODEL.md)."""
        malware = registry.get(ProfileId.MALWARE_ANALYSIS)
        assert malware.policy.wants_sandbox is False
        assert malware.policy.max_risk_level is RiskLevel.L1_LOCAL_STATIC
        assert "sandbox.detonate" in malware.forbidden_capabilities

    def test_no_shipped_profile_requests_above_static_analysis(
        self, registry: ProfileRegistry
    ) -> None:
        for profile in registry.implemented():
            assert profile.policy.max_risk_level is RiskLevel.L1_LOCAL_STATIC

    def test_binary_re_prefers_cheap_facts_before_decompilation(
        self, registry: ProfileRegistry
    ) -> None:
        """Decompiling a whole binary up front is how these systems become
        unusable on anything large."""
        preferences = registry.get(ProfileId.BINARY_RE).preferred_capabilities
        assert preferences.index("binfmt.imports") < preferences.index("ghidra.decompile_function")


class TestStubsRefuse:
    def test_requesting_a_stub_raises(self, registry: ProfileRegistry) -> None:
        with pytest.raises(ProfileNotImplementedError, match="declared but not implemented"):
            registry.get(ProfileId.THREAT_HUNTING).require_implemented()

    def test_the_message_says_why_refusing_beats_falling_back(
        self, registry: ProfileRegistry
    ) -> None:
        with pytest.raises(ProfileNotImplementedError, match="looks like"):
            registry.get(ProfileId.VULNERABILITY_RESEARCH).require_implemented()

    def test_a_stub_may_not_declare_behaviour(self) -> None:
        """A stub carrying preferences reads as working."""
        with pytest.raises(ValueError, match="declares behaviour"):
            a_profile(implemented=False, preferred_capabilities=("semgrep.scan",))

    def test_stubs_are_excluded_from_inference(self, registry: ProfileRegistry) -> None:
        assert all(p.implemented for p in registry.for_artefact_type(ArtefactType.SOURCE_TREE))


class TestLoading:
    def test_malformed_toml_is_rejected_with_the_path(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("profile_id = [unclosed", encoding="utf-8")
        with pytest.raises(ProfileLoadError, match="not valid TOML"):
            load_profile(bad)

    def test_an_unknown_profile_id_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text(
            'profile_id = "quantum_divination"\nname = "x"\ndescription = "y"\n',
            encoding="utf-8",
        )
        with pytest.raises(ProfileLoadError):
            load_profile(bad)

    def test_a_missing_directory_is_an_error_not_an_empty_registry(self, tmp_path: Path) -> None:
        """An empty registry would silently disable every profile."""
        with pytest.raises(ProfileLoadError, match="no profile directory"):
            ProfileRegistry.from_directory(tmp_path / "absent")

    def test_duplicate_ids_are_rejected(self) -> None:
        with pytest.raises(ProfileLoadError, match="more than once"):
            ProfileRegistry([a_profile(), a_profile()])

    def test_an_unknown_profile_lookup_raises(self, registry: ProfileRegistry) -> None:
        empty = ProfileRegistry([])
        with pytest.raises(KeyError):
            empty.get(ProfileId.BINARY_RE)


class TestCoherence:
    def test_preferring_and_forbidding_the_same_capability_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="both prefers and forbids"):
            a_profile(
                preferred_capabilities=("x",),
                forbidden_capabilities=frozenset({"x"}),
            )

    def test_preference_rank_orders_the_planner_tiebreak(self) -> None:
        profile = a_profile(preferred_capabilities=("a", "b", "c"))
        assert profile.preference_rank("a") < profile.preference_rank("c")
        assert profile.preference_rank("unlisted") > profile.preference_rank("c")

    def test_preference_is_not_permission(self) -> None:
        """Preferring says 'try this first', never 'this is allowed'."""
        profile = a_profile(preferred_capabilities=("sandbox.detonate",))
        assert profile.prefers("sandbox.detonate")
        assert profile.policy.wants_sandbox is False


class TestSelection:
    def test_an_explicit_request_wins(self, registry: ProfileRegistry) -> None:
        chosen = select_profiles(
            registry,
            artefact_types=[ArtefactType.SOURCE_TREE],
            requested=[ProfileId.BINARY_RE],
        )
        assert [p.profile_id for p in chosen] == [ProfileId.BINARY_RE]

    def test_an_explicit_request_for_a_stub_fails_loudly(self, registry: ProfileRegistry) -> None:
        """Guessing around an explicit instruction is worse than refusing it."""
        with pytest.raises(ProfileNotImplementedError):
            select_profiles(
                registry,
                artefact_types=[ArtefactType.SOURCE_TREE],
                requested=[ProfileId.THREAT_HUNTING],
            )

    def test_a_binary_infers_reverse_engineering_over_dependency_scanning(
        self, registry: ProfileRegistry
    ) -> None:
        chosen = select_profiles(registry, artefact_types=[ArtefactType.PE])
        assert [p.profile_id for p in chosen] == [ProfileId.BINARY_RE]

    def test_a_source_tree_infers_source_security(self, registry: ProfileRegistry) -> None:
        chosen = select_profiles(registry, artefact_types=[ArtefactType.SOURCE_TREE])
        assert [p.profile_id for p in chosen] == [ProfileId.SOURCE_SECURITY]

    def test_a_repository_with_a_dropped_binary_selects_both(
        self, registry: ProfileRegistry
    ) -> None:
        chosen = select_profiles(
            registry, artefact_types=[ArtefactType.SOURCE_TREE, ArtefactType.PE]
        )
        assert {p.profile_id for p in chosen} == {
            ProfileId.SOURCE_SECURITY,
            ProfileId.BINARY_RE,
        }

    def test_selection_is_deterministic(self, registry: ProfileRegistry) -> None:
        """Or investigations stop being reproducible."""
        types = [ArtefactType.SOURCE_TREE, ArtefactType.PE, ArtefactType.ELF]
        first = [p.profile_id for p in select_profiles(registry, artefact_types=types)]
        second = [p.profile_id for p in select_profiles(registry, artefact_types=types)]
        assert first == second

    def test_an_unrecognised_artefact_type_selects_nothing(self, registry: ProfileRegistry) -> None:
        assert select_profiles(registry, artefact_types=[ArtefactType.UNKNOWN]) == []


class TestMerging:
    def test_merging_requires_at_least_one(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            merge_profiles([])

    def test_a_single_profile_is_returned_unchanged(self, registry: ProfileRegistry) -> None:
        source = registry.get(ProfileId.SOURCE_SECURITY)
        assert merge_profiles([source]) is source

    def test_requirements_union(self, registry: ProfileRegistry) -> None:
        """More things to check is always safe."""
        merged = merge_profiles(
            [
                registry.get(ProfileId.SOURCE_SECURITY),
                registry.get(ProfileId.BINARY_RE),
            ]
        )
        assert "cwe:78" in merged.requirement_sets
        assert "behaviour:process_injection" in merged.requirement_sets

    def test_prohibitions_union(self) -> None:
        merged = merge_profiles(
            [
                a_profile(
                    profile_id=ProfileId.BINARY_RE,
                    forbidden_capabilities=frozenset({"a"}),
                ),
                a_profile(forbidden_capabilities=frozenset({"b"})),
            ]
        )
        assert merged.forbidden_capabilities == frozenset({"a", "b"})

    def test_a_prohibition_beats_another_profiles_preference(self) -> None:
        """The combination must not be more permissive than either part."""
        merged = merge_profiles(
            [
                a_profile(profile_id=ProfileId.BINARY_RE, preferred_capabilities=("risky.op",)),
                a_profile(forbidden_capabilities=frozenset({"risky.op"})),
            ]
        )
        assert "risky.op" not in merged.preferred_capabilities
        assert "risky.op" in merged.forbidden_capabilities

    def test_the_first_profile_keeps_preference_priority(self) -> None:
        merged = merge_profiles(
            [
                a_profile(profile_id=ProfileId.BINARY_RE, preferred_capabilities=("a", "b")),
                a_profile(preferred_capabilities=("b", "c")),
            ]
        )
        assert merged.preferred_capabilities == ("a", "b", "c")

    def test_depth_takes_the_deepest(self, registry: ProfileRegistry) -> None:
        """The combined problem is at least as hard as its hardest part."""
        merged = merge_profiles(
            [
                registry.get(ProfileId.DEPENDENCY_SECURITY),  # fast
                registry.get(ProfileId.MALWARE_ANALYSIS),  # deep
            ]
        )
        assert merged.default_depth is Depth.DEEP

    def test_the_policy_request_intersects_rather_than_unions(self) -> None:
        """Merging must not accumulate permissions."""
        merged = merge_profiles(
            [
                a_profile(
                    profile_id=ProfileId.BINARY_RE,
                    policy=ProfilePolicyRequest(
                        max_risk_level=RiskLevel.L2_SANDBOX, wants_sandbox=True
                    ),
                ),
                a_profile(
                    policy=ProfilePolicyRequest(
                        max_risk_level=RiskLevel.L0_READ_ONLY, wants_sandbox=False
                    )
                ),
            ]
        )
        assert merged.policy.max_risk_level is RiskLevel.L0_READ_ONLY
        assert merged.policy.wants_sandbox is False

    def test_merging_a_stub_raises(self, registry: ProfileRegistry) -> None:
        with pytest.raises(ProfileNotImplementedError):
            merge_profiles(
                [
                    registry.get(ProfileId.SOURCE_SECURITY),
                    registry.get(ProfileId.THREAT_HUNTING),
                ]
            )
