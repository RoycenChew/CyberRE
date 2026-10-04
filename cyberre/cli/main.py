"""The CyberRE command line.

A thin shell over the runtime. Every command resolves to a service call and
holds no logic of its own, so the engine stays usable from Python, from the
API later, and from a test without going through argparse.

`argparse` rather than a CLI framework, consistent with the choices made for
the graph, storage and profile loaders: the standard library does this job,
and `core` depends on nothing but pydantic.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from cyberre.capabilities.registry import InMemoryCapabilityRegistry
from cyberre.core.findings.requirements import RequirementRegistry
from cyberre.core.models.enums import ArtefactType
from cyberre.core.profiles.loader import ProfileRegistry, select_profiles
from cyberre.knowledge.re.source import StructuredKnowledgeSource

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_READY = 3
"""Reserved for a command that cannot run because something is missing.

Distinct from a usage error: "you asked wrongly" and "this is not wired up
yet" should not look the same to a script.
"""


def _profiles(root: Path) -> ProfileRegistry:
    return ProfileRegistry.from_directory(root / "profiles")


def cmd_capabilities(args: argparse.Namespace) -> int:
    """List what this build can and cannot do.

    Including what it cannot. A tool that lists only its working features
    leaves the reader to discover the gaps by hitting them.
    """
    root = Path(args.root)
    registry = InMemoryCapabilityRegistry()
    profiles = _profiles(root)
    requirements = RequirementRegistry()
    knowledge = StructuredKnowledgeSource.from_directory()

    print("Capabilities")
    if len(registry) == 0:
        print("  none registered in this build")
    for spec in registry.all_specs():
        print(f"  {spec.capability_id:<32} risk={spec.risk_level.value}")

    print("\nProfiles")
    for profile in profiles.all_profiles():
        mark = "implemented" if profile.implemented else "NOT IMPLEMENTED"
        print(f"  {profile.profile_id.value:<24} {mark}")

    print(f"\nRequirement sets ({len(requirements)})")
    for requirement_set in requirements.all_sets():
        mandatory = len(requirement_set.mandatory)
        print(
            f"  {requirement_set.set_id:<36} "
            f"{requirement_set.hypothesis_class:<32} {mandatory} requirement(s)"
        )

    print(f"\nKnowledge records: {len(knowledge)} (version {knowledge.version})")
    return EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    """Show which profile would be chosen for an artefact type."""
    root = Path(args.root)
    profiles = _profiles(root)
    try:
        artefact_type = ArtefactType(args.artefact_type)
    except ValueError:
        print(
            f"unknown artefact type '{args.artefact_type}'. One of: "
            + ", ".join(t.value for t in ArtefactType),
            file=sys.stderr,
        )
        return EXIT_USAGE

    chosen = select_profiles(profiles, artefact_types=[artefact_type])
    if not chosen:
        print(f"no implemented profile applies to {artefact_type.value}")
        return EXIT_OK

    for profile in chosen:
        print(f"{profile.profile_id.value}: {profile.name}")
        print(f"  depth: {profile.default_depth.value}")
        print(f"  prefers: {', '.join(profile.preferred_capabilities) or 'nothing'}")
        if profile.forbidden_capabilities:
            print(f"  forbids: {', '.join(sorted(profile.forbidden_capabilities))}")
        print(f"  max risk requested: {profile.policy.max_risk_level.value}")
    return EXIT_OK


def cmd_knowledge(args: argparse.Namespace) -> int:
    """Look up a knowledge record."""
    knowledge = StructuredKnowledgeSource.from_directory()
    record = knowledge.lookup(args.term)
    if record is None:
        matches = knowledge.search(args.term, limit=5)
        if not matches:
            print(f"no record for '{args.term}'")
            return EXIT_OK
        print(f"no exact match for '{args.term}'. Closest:")
        for match in matches:
            print(f"  {match.record_id}: {match.statement}")
        return EXIT_OK

    entry = knowledge.entry(args.term)
    print(f"{record.record_id}@{record.record_version}")
    print(f"  {record.statement}")
    print(f"  source: {record.source_ref}")
    print(f"  confidence in the claim: {record.source_confidence}")
    if entry is not None:
        if entry.danger_class:
            print(f"  danger class: {entry.danger_class.value}")
        if entry.companions:
            print(f"  companions: {', '.join(entry.companions)}")
        if entry.benign_explanation:
            # Shown by default. Most uses of most dangerous APIs are
            # legitimate, and a lookup that omits that is misleading.
            print(f"  innocent reading: {entry.benign_explanation}")
    return EXIT_OK


def cmd_investigate(args: argparse.Namespace) -> int:
    """Run an investigation.

    Not yet wired to the CLI. The pipeline exists and is exercised
    end to end by the dual-slice acceptance tests, but artefact ingestion
    and capability registration are M12 work in progress, and a command
    that half-works is worse than one that says so.
    """
    print(
        "cyberre investigate is not available in this build.\n"
        "\n"
        "The investigation pipeline exists and runs end to end - evidence,\n"
        "interpretation, hypothesis, validation, adversarial review,\n"
        "confidence and report - and is exercised by:\n"
        "\n"
        "    pytest -m evaluation\n"
        "\n"
        "What is missing is artefact ingestion and capability registration,\n"
        "which connect a path on disk to that pipeline.",
        file=sys.stderr,
    )
    return EXIT_NOT_READY


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyberre",
        description=("Evidence-first cybersecurity and reverse-engineering investigation."),
    )
    parser.add_argument(
        "--root",
        default=".",
        help="repository root holding profiles/ and config/ (default: .)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    capabilities = subcommands.add_parser(
        "capabilities", help="list capabilities, profiles and requirement sets"
    )
    capabilities.set_defaults(handler=cmd_capabilities)

    profiles = subcommands.add_parser(
        "profiles", help="show which profile applies to an artefact type"
    )
    profiles.add_argument("artefact_type", help="e.g. pe, elf, source_tree")
    profiles.set_defaults(handler=cmd_profiles)

    knowledge = subcommands.add_parser(
        "knowledge", help="look up a reverse-engineering knowledge record"
    )
    knowledge.add_argument("term", help="an API name, record id or search term")
    knowledge.set_defaults(handler=cmd_knowledge)

    investigate = subcommands.add_parser("investigate", help="run an investigation")
    investigate.add_argument("question", nargs="?", help="what to investigate")
    investigate.add_argument("--source", help="path to a source tree")
    investigate.add_argument("--binary", help="path to a binary")
    investigate.set_defaults(handler=cmd_investigate)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


def app() -> None:
    """Console-script entry point."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
