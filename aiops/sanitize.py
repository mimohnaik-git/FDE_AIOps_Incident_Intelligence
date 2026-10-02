"""All event-controlled strings cross this boundary before storage or analysis."""

import hashlib
import re
from datetime import UTC

from aiops.models import EventFingerprint, NormalizedEvent, RawLogEvent, RedactionResult

# Patterns are deliberately conservative for a demonstration, not a DLP guarantee.
PATTERNS = [
    ("bearer", r"(?i)\bbearer\s+[a-z0-9._~+/=-]+"),
    (
        "credential",
        r"(?i)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|token|password|passwd|secret|authorization)"
        r"\b[\"']?\s*[:=]\s*(?:[\"'][^\"']+[\"']|[^\s,;]+)",
    ),
    ("key", r"\b(?:sk-(?:or-v1-)?[a-zA-Z0-9_-]{8,}|gh[pousr]_[a-zA-Z0-9]{8,}|AKIA[A-Z0-9]{16})\b"),
    ("email", r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b"),
    ("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("ipv6", r"(?i)(?<!\w)(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{0,39}(?!\w)"),
    (
        "path",
        r"(?i)(?:[a-z]:\\(?:Users|Documents and Settings)\\[^\s,;]+|/(?:home|Users)/[^\s,;]+)",
    ),
    ("host", r"(?i)\b(?:host|hostname|server)\s*[:=]\s*[^\s,;]+"),
    ("url", r"(?i)https?://[^\s]+"),
    ("jwt", r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
]


def redact(text: str) -> RedactionResult:
    counts = {}
    for name, pattern in PATTERNS:
        text, count = re.subn(pattern, f"[REDACTED_{name.upper()}]", text)
        if count:
            counts[name] = counts.get(name, 0) + count
    return RedactionResult(text=text[:4096] or "[EMPTY]", replacements=counts)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize(raw: RawLogEvent) -> NormalizedEvent:
    result = redact(" ".join(raw.message.split()))
    # Metadata is untrusted too; never forward caller-supplied host/user identities.
    source = raw.source.lower() if raw.source.lower() in {"synthetic", "system", "api"} else "api"
    component = raw.component.lower()
    if component not in {
        "application",
        "network",
        "system",
        "storage",
        "scheduler",
        "identity",
        "database",
        "security",
    }:
        component = "application"
    signature = re.sub(r"\b\d+(?:\.\d+)?\b", "#", result.text.lower())
    fingerprint = EventFingerprint(
        value=digest(f"{source}|{component}|{signature}"), signature=signature
    )
    timestamp = raw.timestamp.astimezone(UTC)
    event_id = digest(f"{fingerprint.value}|{timestamp.isoformat()}|{result.text}")
    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        component=component,
        message=result.text,
        event_id=event_id,
        fingerprint=fingerprint,
        redaction=result,
    )
