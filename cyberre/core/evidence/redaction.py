"""The secret boundary.

Three chokepoints were promised in SECURITY.md: anything entering model
context, anything entering logs, and anything entering a report. This is the
implementation, and it redacts at the sink rather than relying on every
call site to remember.

The patterns deliberately overlap with the secret scanner's. That module
detects credentials as a finding; this one stops them travelling. A value
the scanner would report must not be the value a prompt leaks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Credential shapes. Narrow and prefixed where possible, because a loose
#: pattern that redacts ordinary text makes an evidence packet unreadable,
#: and an unreadable packet gets the redaction turned off.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    (
        "bearer",
        re.compile(r"(?i)\b(?:authorization|bearer)\b\s*[:=]?\s*[A-Za-z0-9._\-]{20,}"),
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|passwd|password|token|credential)\b"
            r"(\s*[:=]\s*)([\"']?)([^\s\"',;]{8,})\3"
        ),
    ),
)


@dataclass(frozen=True)
class RedactionReport:
    """What was removed, so the removal itself is visible.

    Silent redaction is its own problem: an analyst reading a packet with a
    value quietly missing cannot tell whether the tool found nothing or hid
    something.
    """

    text: str
    removed: tuple[str, ...]

    @property
    def redacted(self) -> bool:
        return bool(self.removed)


def redact(text: str) -> RedactionReport:
    """Remove credential-shaped values from `text`.

    The marker names the detector rather than the value, so a reader knows a
    credential was present and what kind without learning it.
    """
    removed: list[str] = []
    result = text

    for name, pattern in REDACTION_PATTERNS:
        if name == "assignment":

            def _replace(match: re.Match[str], _name: str = name) -> str:
                removed.append(_name)
                return f"{match.group(1)}{match.group(2)}[REDACTED:{_name}]"

            result, count = pattern.subn(_replace, result)
        else:
            result, count = pattern.subn(f"[REDACTED:{name}]", result)
            if count:
                removed.extend([name] * count)

    return RedactionReport(text=result, removed=tuple(dict.fromkeys(removed)))


def redact_text(text: str) -> str:
    """Convenience wrapper for callers that do not need the report."""
    return redact(text).text
