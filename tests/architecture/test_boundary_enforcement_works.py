"""Verify the boundary checker actually detects violations.

A guard that silently stops guarding is worse than no guard, because the green
CI run is read as evidence. These tests plant real violations in the source
tree and assert that the checker reports them.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.architecture.boundaries import LAYER_RULES, VENDOR_PACKAGES
from tests.architecture.test_imports import (
    REPO_ROOT,
    _violations,
    all_import_sites,
)

pytestmark = pytest.mark.architecture


@contextmanager
def planted(relative_path: str, source: str) -> Iterator[Path]:
    """Write a throwaway module into the real tree, then remove it."""
    path = REPO_ROOT / relative_path
    assert not path.exists(), f"planted file would clobber {relative_path}"
    path.write_text(source, encoding="utf-8")
    try:
        yield path
    finally:
        path.unlink()


def test_detects_core_importing_an_adapter() -> None:
    core_rule = next(r for r in LAYER_RULES if r.package == "cyberre.core")
    with planted(
        "cyberre/core/_planted_layer_violation.py",
        "from cyberre.adapters.ghidra import GhidraRunner\n",
    ):
        found = _violations(core_rule, all_import_sites())
    assert any("_planted_layer_violation" in v for v in found), (
        "The layer checker did not detect cyberre.core importing cyberre.adapters."
    )


def test_detects_core_importing_the_engineering_plane() -> None:
    """Invariants 12-14: no path from CyberRE to Claude Code / Codex / Pi."""
    core_rule = next(r for r in LAYER_RULES if r.package == "cyberre.core")
    with planted(
        "cyberre/core/_planted_devplane_violation.py",
        "import devplane.contracts\n",
    ):
        found = _violations(core_rule, all_import_sites())
    assert any("_planted_devplane_violation" in v for v in found)


def test_detects_vendor_import_outside_its_adapter() -> None:
    """Invariant 16: Ghidra must not leak out of its adapter."""
    with planted(
        "cyberre/core/_planted_vendor_violation.py",
        "import pyghidra\n",
    ):
        sites = all_import_sites()
    allowed = VENDOR_PACKAGES["pyghidra"]
    offenders = [
        str(s)
        for s in sites
        if s.module.split(".")[0] == "pyghidra"
        and not any(s.owner == pkg or s.owner.startswith(pkg + ".") for pkg in allowed)
    ]
    assert any("_planted_vendor_violation" in o for o in offenders)


def test_clean_tree_has_no_violations() -> None:
    """With nothing planted, the real tree must be clean."""
    sites = all_import_sites()
    for rule in LAYER_RULES:
        assert not _violations(rule, sites), f"{rule.package}: {_violations(rule, sites)}"
