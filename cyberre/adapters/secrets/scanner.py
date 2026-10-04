"""Secret scanning.

Pure standard library: the patterns are regexes and the entropy test is a
histogram, so a dependency would buy nothing here.

The property that governs every design choice in this file is that **the
secret must never leave this module**. Evidence is durable, queryable, and
rendered into reports; a credential captured into it would be copied into
the database, the object store, the audit log and every export - turning a
tool that finds leaked secrets into one that spreads them.

So a match produces a redacted preview and a digest, never the value.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cyberre.core.models.base import stable_digest
from cyberre.core.models.enums import EvidenceType
from cyberre.core.models.evidence import Evidence, derive_independence_key
from cyberre.core.models.location import SourceLocation
from cyberre.core.models.observation import SecretMatch
from cyberre.core.models.provenance import Provenance, ToolProvenance

TOOL_NAME = "secrets"
DETECTOR_VERSION = "1.0.0"

#: Shannon entropy above which a long opaque string is worth reporting.
#: Tuned low enough to catch base64 keys and high enough to skip prose and
#: hex-encoded hashes, which are long and uniform but rarely secret.
ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_CANDIDATE_LENGTH = 24

#: Characters that make a string a plausible encoded secret.
_CANDIDATE = re.compile(rf"[A-Za-z0-9+/=_\-]{{{MIN_ENTROPY_CANDIDATE_LENGTH},}}")


@dataclass(frozen=True)
class Detector:
    """One named credential pattern.

    `confidence` reflects how specific the pattern is. A prefixed vendor
    token is near-certain; "a long assignment to a variable called secret"
    is not, and the difference must reach the confidence engine rather than
    being flattened here.
    """

    name: str
    pattern: re.Pattern[str]
    confidence: float
    description: str


#: Prefixed, structurally distinctive credentials first; generic shapes last.
#: Each pattern is deliberately narrow: a loose pattern produces findings a
#: reviewer must reject one by one, which costs more analyst time than the
#: occasional miss.
DETECTORS: tuple[Detector, ...] = (
    Detector(
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0.95,
        "AWS access key identifier",
    ),
    Detector(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        0.95,
        "GitHub personal access or app token",
    ),
    Detector(
        "slack_token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        0.9,
        "Slack API token",
    ),
    Detector(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        0.9,
        "Google API key",
    ),
    Detector(
        "stripe_key",
        re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        0.9,
        "Stripe secret key",
    ),
    Detector(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        0.95,
        "Embedded private key",
    ),
    Detector(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        0.75,
        "JSON Web Token",
    ),
    Detector(
        "generic_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|credential)\b"
            r"\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']"
        ),
        0.5,
        "A credential-shaped assignment",
    ),
)

#: Values that match a pattern but are obviously not live credentials.
#: Placeholder detection matters more than it sounds: example configuration
#: and documentation are where generic patterns fire most often, and each
#: false positive costs an analyst a context switch.
_PLACEHOLDER = re.compile(
    # Anchored at the start and tolerant of a suffix, because placeholders
    # are routinely decorated - "changeme1234", "your_api_key_here",
    # "example-token-2024". Requiring a full match let those through, and
    # each one costs an analyst a context switch to dismiss.
    r"(?i)^(?:x{3,}$|\*{3,}$|\.{3,}$|<[^>]+>$|\$\{[^}]+\}$"
    r"|change[_-]?me|placeholder|your[_-]?|example|dummy|sample|redacted"
    r"|insert[_-]?|replace[_-]?|todo|fixme|foo(?:bar)?$|test[_-]?(?:key|token|secret|value)?$)"
)


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def redact(value: str) -> str:
    """A preview that identifies a match without disclosing it.

    Shows at most the first four characters - enough for a human to locate
    the line and recognise the credential they are rotating - and never the
    tail, which is the part that makes a token usable.
    """
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 4)}"


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.match(value.strip()))


@dataclass(frozen=True)
class SecretCandidate:
    """A match, already stripped of the secret.

    The value is reduced to a preview and a digest at construction. There is
    deliberately no field holding the original, so no later code path can
    reach one.
    """

    detector: str
    line_number: int
    preview: str
    digest: str
    confidence: float
    entropy: float


def scan_text(text: str, *, entropy_threshold: float = ENTROPY_THRESHOLD) -> list[SecretCandidate]:
    """Find credential-shaped strings in `text`."""
    candidates: list[SecretCandidate] = []
    seen: set[tuple[str, int, str]] = set()

    for line_number, line in enumerate(text.splitlines(), start=1):
        for detector in DETECTORS:
            for match in detector.pattern.finditer(line):
                value = match.group(match.lastindex or 0)
                if not value or looks_like_placeholder(value):
                    continue
                digest = stable_digest(detector.name, value)[:16]
                key = (detector.name, line_number, digest)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    SecretCandidate(
                        detector=detector.name,
                        line_number=line_number,
                        preview=redact(value),
                        digest=digest,
                        confidence=detector.confidence,
                        entropy=shannon_entropy(value),
                    )
                )

        for match in _CANDIDATE.finditer(line):
            value = match.group(0)
            entropy = shannon_entropy(value)
            if entropy < entropy_threshold or looks_like_placeholder(value):
                continue
            digest = stable_digest("high_entropy", value)[:16]
            key = ("high_entropy", line_number, digest)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                SecretCandidate(
                    detector="high_entropy_string",
                    line_number=line_number,
                    preview=redact(value),
                    digest=digest,
                    # Entropy alone is weak. Plenty of high-entropy strings
                    # are hashes, UUIDs or minified code.
                    confidence=0.35,
                    entropy=entropy,
                )
            )

    return sorted(candidates, key=lambda c: (c.line_number, c.detector))


def build_provenance(*, artefact_sha256: str, raw_output_ref: str | None = None) -> Provenance:
    return Provenance(
        tool=ToolProvenance(
            tool=TOOL_NAME,
            tool_version=DETECTOR_VERSION,
            ruleset_version=f"detectors@{len(DETECTORS)}",
        ),
        artefact_sha256=artefact_sha256,
        # No raw output reference by default: the raw output of a secret
        # scanner is the secrets, and storing it would defeat the point.
        raw_output_ref=raw_output_ref,
    )


def to_evidence(
    candidates: Iterable[SecretCandidate],
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
    path: str,
    provenance: Provenance,
) -> list[Evidence]:
    """Convert candidates into evidence.

    The resulting `SecretMatch` carries only the redacted preview. There is
    no code path from evidence back to the credential.
    """
    evidence: list[Evidence] = []
    for candidate in candidates:
        location = SourceLocation(path=path, start_line=candidate.line_number)
        observation = SecretMatch(
            detector=candidate.detector,
            redacted_preview=candidate.preview,
            entropy=round(candidate.entropy, 3),
        )
        evidence.append(
            Evidence(
                investigation_id=investigation_id,
                artefact_id=artefact_id,
                artefact_sha256=artefact_sha256,
                evidence_type=EvidenceType.SECRET_MATCH,
                observation=observation,
                location=location,
                provenance=provenance,
                independence_key=derive_independence_key(
                    TOOL_NAME, artefact_sha256, str(location), observation.kind
                ),
                source_reliability=candidate.confidence,
            )
        )
    return evidence


#: Files that are not worth scanning, and whose contents are usually binary
#: or generated. Skipping them is a precision measure, not only a speed one.
SKIP_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".class",
        ".jar",
        ".pyc",
        ".wasm",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".mp3",
        ".min.js",
        ".map",
    }
)
MAX_FILE_BYTES = 2_000_000


def iter_source_files(root: Path) -> Iterator[Path]:
    """Files worth scanning under `root`, deterministically ordered."""
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if any(part in {".git", "node_modules", ".venv", "venv"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_tree(
    root: Path,
    *,
    investigation_id: str,
    artefact_id: str,
    artefact_sha256: str,
) -> tuple[list[Evidence], list[str]]:
    """Scan every source file under `root`.

    Returns the evidence and a list of files that could not be read, so an
    unreadable file is reported rather than counting as clean.
    """
    provenance = build_provenance(artefact_sha256=artefact_sha256)
    evidence: list[Evidence] = []
    unreadable: list[str] = []

    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            unreadable.append(str(PurePosixPath(path.relative_to(root).as_posix())))
            continue

        candidates = scan_text(text)
        if candidates:
            evidence.extend(
                to_evidence(
                    candidates,
                    investigation_id=investigation_id,
                    artefact_id=artefact_id,
                    artefact_sha256=artefact_sha256,
                    path=path.relative_to(root).as_posix(),
                    provenance=provenance,
                )
            )

    return evidence, unreadable
