"""Running Semgrep as a subprocess.

Same shape as the Ghidra adapter: fixed argv, no shell, JSON out, nothing of
the tool's internals crossing into CyberRE. Semgrep is importable as a Python
package, but invoking it as a subprocess keeps its dependency tree out of
ours and means an upgrade cannot break CyberRE's own imports.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class SemgrepUnavailableError(RuntimeError):
    """Semgrep is not installed or cannot be executed.

    Distinct from a scan that ran and failed. The caller turns this into a
    ToolFailure; it must never read as "scanned and found nothing".
    """


class SemgrepScanError(RuntimeError):
    """Semgrep ran and did not produce usable output."""


@dataclass(frozen=True)
class SemgrepConfig:
    """How to invoke Semgrep.

    `ruleset` is recorded in provenance, so changing it changes the evidence
    digest - as it should, since a different ruleset is a different analysis.
    """

    ruleset: str = "p/security-audit"
    timeout_seconds: int = 900
    max_target_bytes: int = 5_000_000
    exclude: tuple[str, ...] = (
        # Excluded by default because findings here are overwhelmingly noise:
        # vendored code is not ours to fix, and test fixtures contain
        # deliberately insecure patterns. The reviewer would reject these
        # anyway; not scanning them saves the round trip.
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        "*_test.py",
        "*/tests/*",
        "*/testdata/*",
    )


def locate_semgrep() -> str:
    """Find the Semgrep executable.

    Looks on PATH first, then beside the running interpreter. A
    pip-installed console script lands in the environment's scripts
    directory, which is on PATH only when that environment is activated -
    and CyberRE is frequently invoked by its absolute path, from a service
    manager, or from a test runner, where it is not.

    Raises:
        SemgrepUnavailableError: if it cannot be found. Never returns None:
            an unscanned tree must not be reported as a clean one.
    """
    found = shutil.which("semgrep")
    if found is not None:
        return found

    scripts = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep"):
        candidate = scripts / name
        if candidate.is_file():
            return str(candidate)

    raise SemgrepUnavailableError(
        f"semgrep was not found on PATH or in {scripts}; install it "
        f"(pip install semgrep) or disable the source-security capability "
        f"rather than reporting an unscanned tree as clean"
    )


def semgrep_version(executable: str | None = None) -> str:
    """Read the installed version.

    Determined rather than guessed: it goes into provenance, and a wrong
    version there makes a finding unreproducible in a way nothing detects.
    """
    binary = executable if executable is not None else locate_semgrep()
    try:
        completed = subprocess.run(  # fixed argv list, shell=False
            [binary, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SemgrepUnavailableError(f"could not run '{binary} --version': {error}") from error

    version = completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else ""
    if not version:
        raise SemgrepUnavailableError(f"'{binary} --version' produced no output")
    return version


class SemgrepRunner:
    """Invokes Semgrep over a source tree."""

    def __init__(
        self, *, executable: str | None = None, config: SemgrepConfig | None = None
    ) -> None:
        self._executable = executable if executable is not None else locate_semgrep()
        self._config = config if config is not None else SemgrepConfig()
        self._version: str | None = None

    @property
    def version(self) -> str:
        if self._version is None:
            self._version = semgrep_version(self._executable)
        return self._version

    @property
    def config(self) -> SemgrepConfig:
        return self._config

    def scan(self, target: Path) -> dict[str, object]:
        """Scan `target` and return the parsed JSON output.

        Semgrep exits 1 when it finds something, which is a successful scan.
        Only an exit code above 1, or unusable output, is a failure - reading
        exit 1 as an error would turn every productive scan into a
        ToolFailure.
        """
        command = [
            self._executable,
            "--json",
            "--quiet",
            "--config",
            self._config.ruleset,
            "--max-target-bytes",
            str(self._config.max_target_bytes),
            "--timeout",
            str(self._config.timeout_seconds),
            # Semgrep must not reach the network during a scan: a security
            # tool that phones home while analysing a customer's code is a
            # data-residency problem (ADR-018).
            "--metrics",
            "off",
            "--disable-version-check",
        ]
        for pattern in self._config.exclude:
            command += ["--exclude", pattern]
        command.append(str(target))

        try:
            completed = subprocess.run(  # fixed argv list, shell=False
                command,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds + 60,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise SemgrepScanError(
                f"semgrep timed out after {self._config.timeout_seconds}s on {target}"
            ) from error
        except OSError as error:
            raise SemgrepUnavailableError(
                f"could not execute {self._executable}: {error}"
            ) from error

        if completed.returncode > 1:
            raise SemgrepScanError(
                f"semgrep exited {completed.returncode}: "
                f"{(completed.stderr or completed.stdout).strip()[:400]}"
            )

        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise SemgrepScanError(f"semgrep output is not valid JSON: {error}") from error

        if not isinstance(document, dict):
            raise SemgrepScanError("semgrep output is not a JSON object")
        return document
