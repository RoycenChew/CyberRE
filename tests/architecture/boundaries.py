"""Dependency-direction rules for CyberRE.

These rules encode the architecture invariants that concern imports. They are
data, not prose, so that `test_imports.py` can enforce them and a violation
fails CI instead of being caught (or missed) in review.

Related invariants (docs/ARCHITECTURE.md section "Architecture Invariants"):
  12-14  CyberRE core does not depend on Claude Code / Codex / Pi
  15     CyberRE core does not depend directly on LangGraph
  16     CyberRE core does not depend directly on Ghidra
  17-19  Storage, model provider and tool adapters are replaceable
"""

from __future__ import annotations

from dataclasses import dataclass

#: Third-party packages that bind CyberRE to a specific vendor, tool or
#: framework. Each may be imported only inside the packages listed against it.
#: Anything not listed here is unrestricted (stdlib, pydantic, networkx, ...).
VENDOR_PACKAGES: dict[str, tuple[str, ...]] = {
    # Reverse-engineering backends - adapters only (invariant 16).
    "pyghidra": ("cyberre.adapters.ghidra",),
    "ghidra": ("cyberre.adapters.ghidra",),
    "r2pipe": ("cyberre.adapters.radare2",),
    "binaryninja": ("cyberre.adapters.binary_ninja",),
    # Binary format parsing - adapters only.
    "lief": ("cyberre.adapters.binfmt",),
    "pefile": ("cyberre.adapters.binfmt",),
    # Model providers - adapters only (invariant 18).
    "anthropic": ("cyberre.adapters.models",),
    "openai": ("cyberre.adapters.models",),
    "httpx": ("cyberre.adapters.models", "cyberre.adapters.deps", "cyberre.knowledge"),
    # Workflow runtime - graph layer only (invariant 15).
    "langgraph": ("cyberre.agent.graph",),
    "langchain_core": ("cyberre.agent.graph",),
    # Storage engines - adapters only (invariant 17). sqlite3 is in the
    # standard library, which does not make it less of an engine choice: core
    # must not know which database is underneath it (ADR-020).
    "sqlite3": ("cyberre.adapters.storage",),
    "sqlalchemy": ("cyberre.adapters.storage",),
    "alembic": ("cyberre.adapters.storage",),
    "psycopg": ("cyberre.adapters.storage",),
    # Sandboxing.
    "docker": ("cyberre.adapters.sandbox",),
    # Pattern matching.
    "yara": ("cyberre.adapters.yara",),
    # Interface layers.
    "typer": ("cyberre.cli",),
    "fastapi": ("cyberre.api",),
    "uvicorn": ("cyberre.api",),
}


@dataclass(frozen=True)
class LayerRule:
    """`package` may not import anything under any prefix in `forbidden`."""

    package: str
    forbidden: tuple[str, ...]
    reason: str


#: Inward-only dependency flow: core <- {adapters, agent, capabilities} <- runtime <- cli/api.
LAYER_RULES: tuple[LayerRule, ...] = (
    LayerRule(
        package="cyberre.core",
        forbidden=(
            "cyberre.adapters",
            "cyberre.agent",
            "cyberre.capabilities",
            "cyberre.knowledge",
            "cyberre.runtime",
            "cyberre.cli",
            "cyberre.api",
            "devplane",
        ),
        reason=(
            "The core domain must not depend on any implementation, interface "
            "or engineering-plane package. Adapters depend on core, never the reverse."
        ),
    ),
    LayerRule(
        package="cyberre.adapters",
        forbidden=("cyberre.runtime", "cyberre.cli", "cyberre.api", "devplane"),
        reason="Adapters implement core contracts; they must not reach up into orchestration.",
    ),
    LayerRule(
        package="cyberre.agent",
        forbidden=("cyberre.cli", "cyberre.api", "devplane"),
        reason="The agent layer is driven by the runtime, not by an interface.",
    ),
    LayerRule(
        package="cyberre.capabilities",
        forbidden=("cyberre.cli", "cyberre.api", "devplane"),
        reason="Capabilities are invoked through the registry, not by an interface.",
    ),
    LayerRule(
        package="cyberre",
        forbidden=("devplane",),
        reason=(
            "Invariants 12-14: CyberRE must operate with no knowledge of the "
            "engineering plane (Claude Code, Codex, Pi). devplane may depend on "
            "cyberre.core for shared types; never the reverse."
        ),
    ),
    LayerRule(
        package="cyberre.agent.logic",
        forbidden=("cyberre.agent.graph", "langgraph", "langchain_core"),
        reason=(
            "Invariant 15: agent decision logic must be callable without a workflow "
            "engine, so the LangGraph runtime stays replaceable."
        ),
    ),
)
