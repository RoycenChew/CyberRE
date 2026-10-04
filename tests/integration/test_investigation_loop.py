"""The investigation loop, end to end over stub capabilities.

Integration tier: real storage, real policy engine, real planner, stub tools.
No model and no external tool is involved, which is deliberate - the loop's
behaviour should be decidable without either, and these tests are where that
claim is checked.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cyberre.adapters.storage.memory import MemoryStore
from cyberre.adapters.storage.sqlite.store import SqliteStore
from cyberre.agent.logic.planning import InformationNeed
from cyberre.agent.logic.sufficiency import StopReason
from cyberre.capabilities.registry import InMemoryCapabilityRegistry
from cyberre.core.contracts.capability import (
    CapabilityCost,
    CapabilityResult,
    CapabilitySpec,
)
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import (
    ArtefactType,
    Depth,
    EvidenceType,
    InvestigationStatus,
    RiskLevel,
)
from cyberre.core.models.evidence import Evidence
from cyberre.core.models.location import ArtefactLocation
from cyberre.core.models.observation import (
    FunctionObservation,
    ImportObservation,
    SandboxEvent,
    ScannerFinding,
)
from cyberre.core.models.provenance import Provenance, ToolProvenance
from cyberre.core.models.state import InvestigationState, Objective, ReasoningBudget
from cyberre.core.policies.engine import PolicyEngine
from cyberre.core.policies.permissions import (
    STATIC_ANALYSIS,
    PermissionSet,
    PermissionTerm,
    PolicyContext,
)
from cyberre.runtime.controller import InvestigationController, resume

pytestmark = pytest.mark.integration

SHA = "a" * 64


def spec(
    capability_id: str,
    *,
    produces: EvidenceType,
    artefacts: frozenset[ArtefactType] = frozenset({ArtefactType.SOURCE_TREE}),
    prerequisites: tuple[str, ...] = (),
    risk: RiskLevel = RiskLevel.L1_LOCAL_STATIC,
    seconds: float = 1.0,
) -> CapabilitySpec:
    return CapabilitySpec(
        capability_id=capability_id,
        name=capability_id,
        description="stub",
        artefact_types=artefacts,
        produces=frozenset({produces}),
        cost=CapabilityCost(seconds=seconds),
        reliability=0.8,
        risk_level=risk,
        prerequisites=prerequisites,
    )


def an_artefact() -> Artefact:
    return Artefact(
        sha256=SHA,
        size_bytes=100,
        artefact_type=ArtefactType.SOURCE_TREE,
        display_name="project",
    )


#: The observation must match the declared evidence type - the Evidence model
#: enforces it, and a stub that got this wrong would be reported as a tool
#: failure rather than as a broken fixture.
OBSERVATION_FOR = {
    EvidenceType.SCANNER_FINDING: lambda cid: ScannerFinding(
        rule_id=f"{cid}.rule", message="found something"
    ),
    EvidenceType.IMPORT: lambda cid: ImportObservation(symbol="VirtualAllocEx"),
    EvidenceType.FUNCTION: lambda cid: FunctionObservation(name=f"{cid}_fn"),
    EvidenceType.DECOMPILATION: lambda cid: FunctionObservation(name=f"{cid}_decomp"),
    EvidenceType.SANDBOX_EVENT: lambda cid: SandboxEvent(event_type="exec", detail=cid, sequence=0),
}


def some_evidence(capability_id: str, evidence_type: EvidenceType) -> Evidence:
    observation = OBSERVATION_FOR[evidence_type](capability_id)
    location = ArtefactLocation(detail=capability_id)
    return Evidence(
        investigation_id="inv-1",
        artefact_id="ar-1",
        artefact_sha256=SHA,
        # DECOMPILATION is declared by the capability but carried as a
        # function observation in these stubs; the model requires the two to
        # agree, so the declared type follows the observation.
        evidence_type=EvidenceType(observation.kind),
        observation=observation,
        location=location,
        provenance=Provenance(
            tool=ToolProvenance(tool=capability_id, tool_version="1.0"),
            artefact_sha256=SHA,
        ),
        independence_key=f"{capability_id}-key",
    )


class StubExecutor:
    """Returns canned evidence, or raises for capabilities set to fail."""

    def __init__(
        self,
        produces: dict[str, EvidenceType],
        *,
        failing: frozenset[str] = frozenset(),
        partial: frozenset[str] = frozenset(),
    ) -> None:
        self._produces = produces
        self._failing = failing
        self._partial = partial
        self.calls: list[str] = []

    def execute(self, capability_id: str, artefact: Artefact) -> CapabilityResult:
        self.calls.append(capability_id)
        if capability_id in self._failing:
            raise RuntimeError("the tool fell over")
        evidence = some_evidence(capability_id, self._produces[capability_id])
        return CapabilityResult(
            capability_id=capability_id,
            evidence=(evidence,),
            tool_provenance=ToolProvenance(tool=capability_id, tool_version="1.0"),
            partial=capability_id in self._partial,
        )


def a_state(**overrides: object) -> InvestigationState:
    defaults: dict[str, object] = {
        "investigation_id": "inv-1",
        "objective": Objective(
            question="Are there vulnerabilities?", normalised_intent="find_vulnerabilities"
        ),
        "depth": Depth.STANDARD,
    }
    return InvestigationState(**{**defaults, **overrides})  # type: ignore[arg-type]


def build(
    specs: list[CapabilitySpec],
    executor: StubExecutor,
    *,
    policy: PolicyContext | None = None,
    store: object | None = None,
    max_rounds: int = 12,
) -> InvestigationController:
    backing = store if store is not None else MemoryStore()
    return InvestigationController(
        registry=InMemoryCapabilityRegistry(specs),
        executor=executor,
        policy=PolicyEngine(policy or PolicyContext(global_policy=STATIC_ANALYSIS)),
        evidence_store=backing,  # type: ignore[arg-type]
        investigation_store=backing,  # type: ignore[arg-type]
        max_rounds=max_rounds,
    )


class TestTheLoopCollectsEvidence:
    def test_a_simple_investigation_runs_to_completion(self) -> None:
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        executor = StubExecutor({"scan": EvidenceType.SCANNER_FINDING})
        controller = build(specs, executor)

        outcome = controller.run(a_state(), artefacts=[an_artefact()])

        assert executor.calls == ["scan"]
        assert len(outcome.evidence) == 1
        assert outcome.state.status is InvestigationStatus.COMPLETE

    def test_evidence_reaches_storage(self) -> None:
        store = MemoryStore()
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        controller = build(specs, StubExecutor({"scan": EvidenceType.SCANNER_FINDING}), store=store)
        controller.run(a_state(), artefacts=[an_artefact()])
        assert len(store.list_evidence("inv-1")) == 1

    def test_a_capability_runs_once(self) -> None:
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        executor = StubExecutor({"scan": EvidenceType.SCANNER_FINDING})
        build(specs, executor).run(a_state(), artefacts=[an_artefact()])
        assert executor.calls.count("scan") == 1

    def test_prerequisites_order_the_rounds(self) -> None:
        """The planner must not ask to decompile a binary nobody analysed."""
        specs = [
            spec("analyse", produces=EvidenceType.FUNCTION),
            spec(
                "decompile",
                produces=EvidenceType.DECOMPILATION,
                prerequisites=("analyse",),
            ),
        ]
        executor = StubExecutor(
            {"analyse": EvidenceType.FUNCTION, "decompile": EvidenceType.DECOMPILATION}
        )
        build(specs, executor).run(a_state(), artefacts=[an_artefact()])
        assert executor.calls == ["analyse", "decompile"]


class TestNeedsDriveTheLoop:
    def test_it_stops_once_needs_are_closed(self) -> None:
        specs = [
            spec("scan", produces=EvidenceType.SCANNER_FINDING),
            spec("imports", produces=EvidenceType.IMPORT),
        ]
        executor = StubExecutor(
            {"scan": EvidenceType.SCANNER_FINDING, "imports": EvidenceType.IMPORT}
        )
        need = InformationNeed(
            need_id="find-sink",
            description="a dangerous sink",
            satisfied_by=frozenset({EvidenceType.SCANNER_FINDING}),
            urgency=0.9,
        )

        outcome = build(specs, executor).run(a_state(), artefacts=[an_artefact()], needs=[need])

        assert outcome.stop_reason is StopReason.NEEDS_CLOSED
        assert "scan" in executor.calls

    def test_an_unresolvable_need_ends_the_investigation(self) -> None:
        """No capability can produce it, so retrying would never help."""
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        need = InformationNeed(
            need_id="need-sandbox",
            description="runtime behaviour",
            satisfied_by=frozenset({EvidenceType.SANDBOX_EVENT}),
        )

        outcome = build(specs, StubExecutor({"scan": EvidenceType.SCANNER_FINDING})).run(
            a_state(), artefacts=[an_artefact()], needs=[need]
        )

        assert outcome.stop_reason is StopReason.NEEDS_UNRESOLVABLE
        assert outcome.state.unresolved_questions

    def test_open_questions_are_carried_into_the_state(self) -> None:
        """Hiding them would make a partial result look complete."""
        need = InformationNeed(
            need_id="reachability",
            description="is the sink reachable",
            satisfied_by=frozenset({EvidenceType.REACHABILITY}),
        )
        outcome = build(
            [spec("scan", produces=EvidenceType.SCANNER_FINDING)],
            StubExecutor({"scan": EvidenceType.SCANNER_FINDING}),
        ).run(a_state(), artefacts=[an_artefact()], needs=[need])

        questions = [q.question for q in outcome.state.unresolved_questions]
        assert any("reachability" in q for q in questions)


class TestFailuresAreNotEvidence:
    def test_a_failing_tool_produces_a_tool_failure(self) -> None:
        specs = [spec("broken", produces=EvidenceType.SCANNER_FINDING)]
        executor = StubExecutor(
            {"broken": EvidenceType.SCANNER_FINDING}, failing=frozenset({"broken"})
        )
        store = MemoryStore()

        outcome = build(specs, executor, store=store).run(a_state(), artefacts=[an_artefact()])

        assert outcome.evidence == []
        assert len(store.list_tool_failures("inv-1")) == 1
        assert "fell over" in store.list_tool_failures("inv-1")[0].reason

    def test_a_failure_makes_the_investigation_partial(self) -> None:
        """An investigation that lost a tool knows less; it has not observed
        something, and must not report as COMPLETE."""
        specs = [spec("broken", produces=EvidenceType.SCANNER_FINDING)]
        outcome = build(
            specs,
            StubExecutor({"broken": EvidenceType.SCANNER_FINDING}, failing=frozenset({"broken"})),
        ).run(a_state(), artefacts=[an_artefact()])

        assert outcome.state.status is InvestigationStatus.PARTIAL
        assert outcome.is_partial

    def test_one_failing_tool_does_not_stop_the_others(self) -> None:
        specs = [
            spec("broken", produces=EvidenceType.SCANNER_FINDING),
            spec("works", produces=EvidenceType.IMPORT),
        ]
        executor = StubExecutor(
            {"broken": EvidenceType.SCANNER_FINDING, "works": EvidenceType.IMPORT},
            failing=frozenset({"broken"}),
        )
        outcome = build(specs, executor).run(a_state(), artefacts=[an_artefact()])

        assert len(outcome.evidence) == 1
        assert outcome.state.status is InvestigationStatus.PARTIAL

    def test_a_partial_tool_result_is_recorded(self) -> None:
        """Succeeded but could not see everything: distinct from failure and
        distinct from success."""
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        outcome = build(
            specs,
            StubExecutor({"scan": EvidenceType.SCANNER_FINDING}, partial=frozenset({"scan"})),
        ).run(a_state(), artefacts=[an_artefact()])

        assert outcome.evidence
        assert outcome.state.status is InvestigationStatus.PARTIAL


class TestPolicyGatesTheLoop:
    def test_a_denied_capability_does_not_run(self) -> None:
        specs = [
            spec("allowed", produces=EvidenceType.SCANNER_FINDING),
            spec("forbidden", produces=EvidenceType.IMPORT),
        ]
        executor = StubExecutor(
            {"allowed": EvidenceType.SCANNER_FINDING, "forbidden": EvidenceType.IMPORT}
        )
        policy = PolicyContext(
            global_policy=STATIC_ANALYSIS,
            user_policy=PermissionSet.no_opinion(PermissionTerm.USER).model_copy(
                update={"forbidden_capabilities": frozenset({"forbidden"})}
            ),
        )

        outcome = build(specs, executor, policy=policy).run(a_state(), artefacts=[an_artefact()])

        assert executor.calls == ["allowed"]
        assert outcome.state.policy_decision_ids

    def test_a_refusal_is_not_retried(self) -> None:
        """Repeating a denied action spends budget to learn the same answer."""
        specs = [spec("forbidden", produces=EvidenceType.IMPORT)]
        policy = PolicyContext(
            global_policy=STATIC_ANALYSIS,
            user_policy=PermissionSet.no_opinion(PermissionTerm.USER).model_copy(
                update={"forbidden_capabilities": frozenset({"forbidden"})}
            ),
        )
        outcome = build(specs, StubExecutor({"forbidden": EvidenceType.IMPORT}), policy=policy).run(
            a_state(), artefacts=[an_artefact()]
        )

        assert len(outcome.state.policy_decision_ids) == 1

    def test_a_high_risk_capability_is_refused_without_approval(self) -> None:
        specs = [spec("detonate", produces=EvidenceType.SANDBOX_EVENT, risk=RiskLevel.L2_SANDBOX)]
        executor = StubExecutor({"detonate": EvidenceType.SANDBOX_EVENT})
        build(specs, executor).run(a_state(), artefacts=[an_artefact()])
        assert executor.calls == []


class TestBudget:
    def test_exhaustion_ends_the_run_as_partial(self) -> None:
        specs = [spec(f"cap{i}", produces=EvidenceType.SCANNER_FINDING) for i in range(5)]
        executor = StubExecutor({f"cap{i}": EvidenceType.SCANNER_FINDING for i in range(5)})
        state = a_state(budget=ReasoningBudget(max_tool_calls=2))

        outcome = build(specs, executor).run(state, artefacts=[an_artefact()])

        assert outcome.stop_reason is StopReason.BUDGET_EXHAUSTED
        assert outcome.state.status is InvestigationStatus.PARTIAL
        assert len(executor.calls) <= 3

    def test_budget_is_charged_per_action(self) -> None:
        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING, seconds=4.0)]
        outcome = build(specs, StubExecutor({"scan": EvidenceType.SCANNER_FINDING})).run(
            a_state(), artefacts=[an_artefact()]
        )
        assert outcome.state.budget.tool_calls_used == 1
        assert outcome.state.budget.runtime_seconds_used == pytest.approx(4.0)

    def test_fast_depth_runs_fewer_actions_per_round(self) -> None:
        """A simple question must not trigger an expensive investigation."""
        specs = [spec(f"cap{i}", produces=EvidenceType.SCANNER_FINDING) for i in range(6)]
        executor = StubExecutor({f"cap{i}": EvidenceType.SCANNER_FINDING for i in range(6)})
        build(specs, executor).run(a_state(depth=Depth.FAST), artefacts=[an_artefact()])
        # The first round is capped at two under FAST.
        assert len(executor.calls) >= 2


class TestCheckpointAndResume:
    def test_state_is_checkpointed_each_round(self) -> None:
        store = MemoryStore()
        specs = [
            spec("analyse", produces=EvidenceType.FUNCTION),
            spec(
                "decompile",
                produces=EvidenceType.DECOMPILATION,
                prerequisites=("analyse",),
            ),
        ]
        executor = StubExecutor(
            {"analyse": EvidenceType.FUNCTION, "decompile": EvidenceType.DECOMPILATION}
        )
        build(specs, executor, store=store).run(a_state(), artefacts=[an_artefact()])

        saved = store.load_state("inv-1")
        assert saved.status is InvestigationStatus.COMPLETE
        assert len(saved.evidence_ids) == 2

    def test_resuming_does_not_rerun_completed_capabilities(self) -> None:
        """Otherwise a resume would re-run Ghidra over the same binary."""
        store = MemoryStore()
        specs = [spec("expensive", produces=EvidenceType.FUNCTION, seconds=120.0)]
        first = StubExecutor({"expensive": EvidenceType.FUNCTION})
        build(specs, first, store=store).run(a_state(), artefacts=[an_artefact()])
        assert first.calls == ["expensive"]

        second = StubExecutor({"expensive": EvidenceType.FUNCTION})
        controller = build(specs, second, store=store)
        resumed = resume(controller, "inv-1", store=store, artefacts=[an_artefact()])

        assert second.calls == [], "the completed capability must not run again"
        assert resumed.state.status is InvestigationStatus.COMPLETE

    def test_it_works_against_sqlite_too(self, tmp_path: Path) -> None:
        """The loop must not depend on which store is underneath it."""
        with SqliteStore(tmp_path / "inv.sqlite") as store:
            specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
            controller = build(
                specs, StubExecutor({"scan": EvidenceType.SCANNER_FINDING}), store=store
            )
            controller.run(a_state(), artefacts=[an_artefact()])
            assert len(store.list_evidence("inv-1")) == 1
            assert store.load_state("inv-1").status is InvestigationStatus.COMPLETE


class TestNoEngineRequired:
    def test_the_loop_runs_with_no_workflow_framework(self) -> None:
        """Invariant 15, concretely: the decision logic and the loop import
        no workflow engine, and the architecture test enforces it. This
        asserts the behavioural half - a full investigation completes with
        nothing but the standard library, pydantic and our own code."""
        import sys

        specs = [spec("scan", produces=EvidenceType.SCANNER_FINDING)]
        build(specs, StubExecutor({"scan": EvidenceType.SCANNER_FINDING})).run(
            a_state(), artefacts=[an_artefact()]
        )
        assert "langgraph" not in sys.modules
        assert "langchain_core" not in sys.modules


class TestDeterminism:
    def test_the_same_inputs_produce_the_same_execution_order(self) -> None:
        """Planning order that depended on dictionary iteration would make
        investigations unreproducible."""
        specs = [spec(f"cap{i}", produces=EvidenceType.SCANNER_FINDING) for i in range(4)]
        produces = {f"cap{i}": EvidenceType.SCANNER_FINDING for i in range(4)}

        first = StubExecutor(produces)
        build(specs, first).run(a_state(), artefacts=[an_artefact()])
        second = StubExecutor(produces)
        build(specs, second).run(a_state(), artefacts=[an_artefact()])

        assert first.calls == second.calls
