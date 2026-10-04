"""Loading credentials from a .env file.

`.env.example` tells an operator to put their key in `.env`, so something
has to read it. Standard library rather than a dependency: the format is
`KEY=value` lines, and this is thirty lines of parsing.

Two rules:

* **The real environment wins.** A variable already set is never
  overwritten. CI and container deployments set credentials in the
  environment, and a stray `.env` left in a working copy must not silently
  replace the one the platform provided.
* **Values are never logged.** The loader reports which *names* it set,
  never what it set them to.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ENV_FILE = ".env"


@dataclass(frozen=True)
class EnvLoadResult:
    """What was loaded, by name only."""

    path: Path | None
    applied: tuple[str, ...] = ()
    already_set: tuple[str, ...] = ()
    malformed_lines: tuple[int, ...] = ()

    @property
    def loaded(self) -> bool:
        return self.path is not None


def parse_env(text: str) -> tuple[dict[str, str], tuple[int, ...]]:
    """Parse `KEY=value` lines, reporting the lines that are not.

    Malformed lines are reported rather than ignored. A typo in a
    credential file is the kind of thing that surfaces as a baffling
    authentication failure three steps later.
    """
    values: dict[str, str] = {}
    malformed: list[int] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            malformed.append(number)
            continue

        name, _, value = line.partition("=")
        name = name.strip()
        if not name or not name.replace("_", "").isalnum():
            malformed.append(number)
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[name] = value

    return values, tuple(malformed)


def load_env(
    path: Path | str = DEFAULT_ENV_FILE, *, environ: dict[str, str] | None = None
) -> EnvLoadResult:
    """Load `path` into the environment without overriding what is set.

    A missing file is not an error. Most deployments set credentials in the
    environment directly, and requiring a `.env` would make the normal
    production case fail.
    """
    target = os.environ if environ is None else environ
    file_path = Path(path)

    if not file_path.is_file():
        return EnvLoadResult(path=None)

    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError:
        return EnvLoadResult(path=None)

    values, malformed = parse_env(text)

    applied: list[str] = []
    already: list[str] = []
    for name, value in values.items():
        if target.get(name):
            # Explicit beats implicit. A stray .env in a working copy must
            # not replace the credential the platform provided.
            already.append(name)
            continue
        if not value:
            # An empty value is an unfilled placeholder, not a credential.
            # Setting it would turn "no key configured" into "a key that
            # does not work", which is a worse error to debug.
            continue
        target[name] = value
        applied.append(name)

    return EnvLoadResult(
        path=file_path,
        applied=tuple(sorted(applied)),
        already_set=tuple(sorted(already)),
        malformed_lines=malformed,
    )
