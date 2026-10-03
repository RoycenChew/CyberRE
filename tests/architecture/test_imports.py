"""Enforce the dependency direction by parsing every source file.

This is the structural half of the architecture quality gate. It reads the
source tree with `ast` rather than importing it, so a violation is caught even
in a module that cannot currently be imported.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.architecture.boundaries import LAYER_RULES, VENDOR_PACKAGES, LayerRule

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = ("cyberre", "devplane")

pytestmark = pytest.mark.architecture


@dataclass(frozen=True)
class ImportSite:
    """One imported module name, and where it was written."""

    module: str
    path: Path
    lineno: int

    @property
    def owner(self) -> str:
        """Dotted package of the importing file, e.g. ``cyberre.core.models``."""
        rel = self.path.relative_to(REPO_ROOT).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def __str__(self) -> str:
        rel = self.path.relative_to(REPO_ROOT).as_posix()
        return f"{rel}:{self.lineno} imports '{self.module}'"


def _python_files() -> list[Path]:
    files: list[Path] = []
    for root in SOURCE_ROOTS:
        files.extend(sorted((REPO_ROOT / root).rglob("*.py")))
    return files


def _imports_in(path: Path) -> list[ImportSite]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    sites: list[ImportSite] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                sites.append(ImportSite(alias.name, path, node.lineno))
        # level > 0 is a relative import; ruff's TID252 bans those outright.
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            sites.append(ImportSite(node.module, path, node.lineno))
    return sites


def all_import_sites() -> list[ImportSite]:
    return [site for path in _python_files() for site in _imports_in(path)]


def _is_under(module: str, prefix: str) -> bool:
    """True if `module` is `prefix` or a descendant of it."""
    return module == prefix or module.startswith(prefix + ".")


def _violations(rule: LayerRule, sites: list[ImportSite]) -> list[str]:
    found: list[str] = []
    for site in sites:
        if not _is_under(site.owner, rule.package):
            continue
        for forbidden in rule.forbidden:
            if _is_under(site.module, forbidden):
                found.append(str(site))
    return found


@pytest.mark.parametrize("rule", LAYER_RULES, ids=lambda r: r.package)
def test_layer_may_not_import_forbidden_packages(rule: LayerRule) -> None:
    violations = _violations(rule, all_import_sites())
    assert not violations, (
        f"\n{rule.package} must not import {rule.forbidden}.\n"
        f"Reason: {rule.reason}\n"
        f"Violations:\n  " + "\n  ".join(violations)
    )


@pytest.mark.parametrize("vendor", sorted(VENDOR_PACKAGES), ids=str)
def test_vendor_dependency_is_confined_to_its_adapter(vendor: str) -> None:
    allowed = VENDOR_PACKAGES[vendor]
    violations = [
        str(site)
        for site in all_import_sites()
        if _is_under(site.module.split(".")[0], vendor)
        and not any(_is_under(site.owner, pkg) for pkg in allowed)
    ]
    assert not violations, (
        f"\n'{vendor}' may only be imported inside {allowed}.\n"
        f"Keeping a vendor dependency behind one adapter is what makes it "
        f"replaceable (invariants 15-19).\n"
        f"Violations:\n  " + "\n  ".join(violations)
    )


def test_rules_reference_packages_that_exist() -> None:
    """A rule naming a package that was renamed away stops protecting anything."""
    missing = [
        rule.package
        for rule in LAYER_RULES
        if not (REPO_ROOT / Path(*rule.package.split("."))).is_dir()
    ]
    assert not missing, f"Boundary rules name packages that do not exist: {missing}"
