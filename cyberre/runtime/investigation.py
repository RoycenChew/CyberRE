"""The investigation service: a path in, a report out.

Everything the CLI does goes through here, so the engine is equally usable
from Python, from the API later, and from a test. The CLI holds no logic of
its own.

The pipeline is the architecture, in order:

    ingest -> profile -> collect evidence -> interpret -> compile packet
           -> reason -> validate -> review -> score -> report

Reasoning and review need a model. Everything that *decides* an outcome -
validation, confidence, status resolution - does not, so an investigation
with no model configured still produces evidence, still runs validation on
any hypothesis it has, and says plainly what it could not do.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cyberre.adapters.storage.memory import MemoryObjectStore, MemoryStore
from cyberre.agent.logic.planning import InformationNeed
from cyberre.agent.reasoning.reasoner import ChiefSecurityReasoner, ReasoningResult
from cyberre.agent.reviewers.adversarial import AdversarialReviewer, build_packet
from cyberre.capabilities.builtin import BuiltinExecutor, available_specs
from cyberre.capabilities.registry import InMemoryCapabilityRegistry
from cyberre.core.contracts.model_provider import ModelProvider
from cyberre.core.contracts.storage import ObjectStore
from cyberre.core.evidence.builder import build_graph
from cyberre.core.evidence.compiler import EvidenceContextCompiler
from cyberre.core.evidence.digest import ReproducibilityManifest, build_manifest
from cyberre.core.findings.assembly import assemble
from cyberre.core.findings.confidence import ConfidenceConfig, ConfidenceEngine
from cyberre.core.findings.report import Report, ReportGenerator
from cyberre.core.findings.requirements import RequirementRegistry
from cyberre.core.findings.validation import ValidationEngine
from cyberre.core.models.artefact import Artefact
from cyberre.core.models.enums import (
    ArtefactType,
    Depth,
    EvidenceType,
    InvestigationStatus,
    ProfileId,
)
from cyberre.core.models.evidence import Evidence, ToolFailure
from cyberre.core.models.finding import Finding
from cyberre.core.models.interpretation import Interpretation
from cyberre.core.models.state import InvestigationState, Objective, ReasoningBudget
from cyberre.core.policies.engine import PolicyEngine
from cyberre.core.policies.permissions import STATIC_ANALYSIS, PolicyContext
from cyberre.core.profiles.loader import ProfileRegistry, select_profiles
from cyberre.core.profiles.model import AnalysisProfile
from cyberre.knowledge.re.interpret import interpret
from cyberre.knowledge.re.source import StructuredKnowledgeSource
from cyberre.runtime.controller import InvestigationController
from cyberre.runtime.ingest import ArtefactIngestor

CYBERRE_VERSION = "0.1.0.dev0"

#: Needs the investigation starts with, by artefact type. These are what
#: the planner works to close, and they are why it runs a data-flow tool
#: rather than whatever happens to be cheapest.
DEFAULT_NEEDS: dict[ArtefactType, tuple[InformationNeed, ...]] = {}


@dataclass
class InvestigationOutcome:
    """Everything one investigation produced."""

    state: InvestigationState
    evidence: list[Evidence] = field(default_factory=list)
    interpretations: list[Interpretation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    failures: list[ToolFailure] = field(default_factory=list)
    report: Report | None = None
    manifest: ReproducibilityManifest | None = None
    reasoning: ReasoningResult | None = None
    notes: list[str] = field(default_factory=list)
    """Things the reader should know about what was and was not done.

    Carried into the report's limitations. An investigation that could not
    reason, or could not review, must say so rather than presenting a
    smaller result as a complete one.
    """

    @property
    def is_partial(self) -> bool:
        return self.state.status is InvestigationStatus.PARTIAL


class InvestigationService:
    """Runs an investigation from a path on disk."""

    def __init__(
        self,
        *,
        model_provider: ModelProvider | None = None,
        object_store: ObjectStore | None = None,
        store: MemoryStore | None = None,
        profiles: ProfileRegistry | None = None,
        knowledge: StructuredKnowledgeSource | None = None,
        policy: PolicyContext | None = None,
        config_root: Path = Path("."),
    ) -> None:
        self._model = model_provider
        self._object_store = object_store if object_store is not None else MemoryObjectStore()
        self._store = store if store is not None else MemoryStore()
        self._profiles = (
            profiles
            if profiles is not None
            else ProfileRegistry.from_directory(config_root / "profiles")
        )
        self._knowledge = (
            knowledge if knowledge is not None else StructuredKnowledgeSource.from_directory()
        )
        self._policy = (
            policy if policy is not None else PolicyContext(global_policy=STATIC_ANALYSIS)
        )
        self._confidence = ConfidenceEngine(
            ConfidenceConfig.load(config_root / "config" / "confidence.toml")
        )
        self._requirements = RequirementRegistry()

    def investigate(
        self,
        path: Path,
        *,
        question: str,
        depth: Depth = Depth.STANDARD,
        requested_profiles: Sequence[ProfileId] = (),
        budget: ReasoningBudget | None = None,
    ) -> InvestigationOutcome:
        """Run the whole pipeline over `path`."""
        ingestion = ArtefactIngestor(self._object_store).ingest(path)
        artefacts = ingestion.artefacts
        roots = {artefact.artefact_id: Path(path) for artefact in artefacts}

        chosen = select_profiles(
            self._profiles,
            artefact_types=ingestion.artefact_types,
            requested=requested_profiles,
        )
        profile = chosen[0] if chosen else None

        state = InvestigationState(
            objective=Objective(
                question=question,
                normalised_intent=_normalise(question),
            ),
            depth=profile.default_depth if profile and not depth else depth,
            profiles=tuple(p.profile_id for p in chosen),
            artefact_ids=tuple(a.artefact_id for a in artefacts),
            budget=budget if budget is not None else ReasoningBudget(),
        )

        outcome = InvestigationOutcome(state=state)
        self._collect(outcome, artefacts=artefacts, roots=roots, profile=profile)
        self._interpret(outcome, artefacts=artefacts)
        self._reason_and_validate(outcome, question=question)
        self._finish(outcome)
        return outcome

    # ----------------------------------------------------------- stages

    def _collect(
        self,
        outcome: InvestigationOutcome,
        *,
        artefacts: list[Artefact],
        roots: dict[str, Path],
        profile: AnalysisProfile | None,
    ) -> None:
        registry = InMemoryCapabilityRegistry(available_specs())
        controller = InvestigationController(
            registry=registry,
            executor=BuiltinExecutor(
                investigation_id=outcome.state.investigation_id,
                roots=roots,
                object_store=self._object_store,
            ),
            policy=PolicyEngine(self._policy),
            evidence_store=self._store,
            investigation_store=self._store,
            profile=profile,
        )
        collected = controller.run(outcome.state, artefacts=artefacts)
        outcome.state = collected.state
        outcome.evidence = list(collected.evidence)
        outcome.failures = list(collected.failures)

        for failure in collected.failures:
            outcome.notes.append(f"{failure.capability_id} did not run: {failure.reason}")

    def _interpret(self, outcome: InvestigationOutcome, *, artefacts: list[Artefact]) -> None:
        if not outcome.evidence:
            return
        os_name = "windows" if any(a.artefact_type is ArtefactType.PE for a in artefacts) else None
        outcome.interpretations = interpret(
            outcome.evidence,
            self._knowledge,
            investigation_id=outcome.state.investigation_id,
            os_name=os_name,
        )

    def _reason_and_validate(self, outcome: InvestigationOutcome, *, question: str) -> None:
        if self._model is None:
            # Recorded before the evidence check, not after. This is the
            # most important caveat on an offline run and it must not
            # depend on whether evidence happened to be found - a report
            # that omits it reads as a clean result.
            outcome.notes.append(
                "no model provider is configured, so no hypotheses were formed "
                "and nothing was validated"
            )

        if not outcome.evidence:
            outcome.notes.append("no evidence was collected, so no hypothesis could be formed")
            return

        if self._model is None:
            return

        graph = build_graph(outcome.evidence)
        packet = (
            EvidenceContextCompiler()
            .compile(
                question=question,
                objective=outcome.state.objective.normalised_intent,
                evidence=outcome.evidence,
                graph=graph,
                interpretations=outcome.interpretations,
                artefacts=dict.fromkeys(outcome.state.artefact_ids, ""),
            )
            .packet
        )

        reasoning = ChiefSecurityReasoner(self._model).reason(
            packet, investigation_id=outcome.state.investigation_id
        )
        outcome.reasoning = reasoning

        if reasoning.failed:
            outcome.notes.append(f"reasoning did not complete: {reasoning.failure_reason}")
        if reasoning.rejected_for_no_citation:
            outcome.notes.append(
                f"{len(reasoning.rejected_for_no_citation)} claim(s) were discarded "
                f"for citing no evidence that exists"
            )

        # The verification pass explains what it dropped and why. Throwing
        # that away leaves a report saying nothing was found without saying
        # what was considered, which reads as a cleaner result than it is.
        for dropped in reasoning.dropped:
            outcome.notes.append(f"considered and not supported: {dropped}")

        if reasoning.hypotheses and not reasoning.candidates and not reasoning.failed:
            outcome.notes.append(
                f"{len(reasoning.hypotheses)} hypothes"
                f"{'is was' if len(reasoning.hypotheses) == 1 else 'es were'} "
                f"proposed and none survived verification against the available "
                f"evidence"
            )

        self._note_unreachable_requirements(outcome, reasoning)

        by_id = {e.evidence_id: e for e in outcome.evidence}
        validator = ValidationEngine()
        reviewer = AdversarialReviewer(self._model)

        for candidate in reasoning.candidates:
            hypothesis = next(
                (h for h in reasoning.hypotheses if h.hypothesis_id == candidate.hypothesis_id),
                None,
            )
            if hypothesis is None:
                continue

            class_key = str(hypothesis.hypothesis_class)
            if not self._requirements.covers(class_key):
                # No requirement set means nothing could establish it, so
                # it is reported as unexaminable rather than carried as an
                # untestable claim.
                outcome.notes.append(
                    f"no requirement set covers '{class_key}', so the hypothesis "
                    f"'{hypothesis.statement}' could not be examined"
                )
                continue

            validation = validator.validate(
                hypothesis,
                self._requirements.for_class(class_key),
                evidence=outcome.evidence,
                graph=graph,
            )

            review_packet = build_packet(
                candidate,
                validation,
                evidence=by_id,
                interpretations=outcome.interpretations,
            )
            review = reviewer.review(review_packet, known_evidence_ids=frozenset(by_id))

            outcome.findings.append(
                assemble(
                    candidate,
                    validation,
                    hypothesis.hypothesis_class,
                    evidence=by_id,
                    confidence_engine=self._confidence,
                    review=review,
                )
            )

        outcome.state = outcome.state.evolve(
            hypothesis_ids=tuple(h.hypothesis_id for h in reasoning.hypotheses),
            candidate_finding_ids=tuple(c.candidate_id for c in reasoning.candidates),
            finding_ids=tuple(f.finding_id for f in outcome.findings),
            model_history=outcome.state.model_history,
        )

    def _note_unreachable_requirements(
        self, outcome: InvestigationOutcome, reasoning: ReasoningResult
    ) -> None:
        """Say when a hypothesis could never be established by this build.

        A requirement set can demand evidence no registered capability
        produces - CWE-78 needs data-flow and reachability, and neither is
        implemented yet. Without this note the investigation looks like it
        found nothing, when in fact it could not have looked.
        """
        producible: set[EvidenceType] = set()
        for spec in available_specs():
            producible |= spec.produces

        # One note per class. Several hypotheses commonly share a class,
        # and repeating the same limitation makes a report look padded.
        seen: set[str] = set()
        for hypothesis in reasoning.hypotheses:
            class_key = str(hypothesis.hypothesis_class)
            if class_key in seen or not self._requirements.covers(class_key):
                continue
            seen.add(class_key)
            requirement_set = self._requirements.for_class(class_key)
            missing = [
                requirement.requirement_id
                for requirement in requirement_set.mandatory
                if not _can_produce(requirement.requirement_id, producible)
            ]
            if missing:
                outcome.notes.append(
                    f"'{class_key}' cannot be established by this build: no "
                    f"registered capability produces the evidence for "
                    f"{', '.join(missing)}"
                )

    def _finish(self, outcome: InvestigationOutcome) -> None:
        outcome.manifest = build_manifest(
            investigation_id=outcome.state.investigation_id,
            evidence=outcome.evidence,
            findings=outcome.findings,
            cyberre_version=CYBERRE_VERSION,
            confidence_formula_version=self._confidence.config.version,
        )

        for finding in outcome.findings:
            self._store.save_finding(finding)

        outcome.report = ReportGenerator().generate(
            outcome.state,
            findings=outcome.findings,
            evidence={e.evidence_id: e for e in outcome.evidence},
            manifest=outcome.manifest,
            failures=outcome.failures,
            observations=outcome.notes,
        )
        self._store.save_state(outcome.state)


#: Which evidence type each requirement suffix needs. Crude, and honest
#: about being so: the alternative is asking a predicate what it wants,
#: which it is not currently able to say.
REQUIREMENT_EVIDENCE: dict[str, EvidenceType] = {
    ".attacker_controlled_source": EvidenceType.DATA_FLOW,
    ".no_sanitisation": EvidenceType.DATA_FLOW,
    ".reachable": EvidenceType.REACHABILITY,
}


def _can_produce(requirement_id: str, producible: set[EvidenceType]) -> bool:
    for suffix, needed in REQUIREMENT_EVIDENCE.items():
        if requirement_id.endswith(suffix):
            return needed in producible
    return True


def _normalise(question: str) -> str:
    """A terse machine-readable intent.

    Deliberately crude. Intent classification is a FAST-tier model job that
    this build does not do, and a stub that pretended otherwise would be
    worse than an obvious placeholder.
    """
    words = [w.lower() for w in question.split() if w.isalpha()]
    return "_".join(words[:5]) or "investigate"
