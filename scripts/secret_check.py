"""Deterministic tracked/nonignored scanner; reports locations, never secret values."""

import re
import subprocess
from pathlib import Path

# Test fixtures use human-readable 'fixture...' sentinels, not realistic credential tokens.
PATTERNS = [
    re.compile(r"\bsk-(?:or-v1-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"""(?i)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*["']([^"'\n]{12,})["']"""),
    re.compile(
        r"(?i)\b(?:[a-z0-9]+[_-])*(?:api[_-]?key|password|secret|token)"
        r"\s*[:=]\s*([a-z0-9_./+-]{12,})"
    ),
]


def scan() -> list[str]:
    root = Path(__file__).resolve().parents[1]
    files = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    findings = []
    for entry in sorted(set(files)):
        if not entry:
            continue
        relative = entry.decode("utf-8")
        # Never inspect local .env content; detect tracking as a violation instead.
        if Path(relative).name == ".env":
            findings.append(f"{relative}: tracked environment file")
            continue
        path = root / relative
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), 1):
            for pattern in PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                if match.lastindex and match.group(1).startswith(
                    ("fixture", "environmentSentinel")
                ):
                    continue
                findings.append(f"{relative}:{number}: potential credential")
                break
    return findings


if __name__ == "__main__":
    findings = scan()
    for finding in findings:
        print(finding)
    print(f"Secret check: {len(findings)} findings (matched values withheld)")
    raise SystemExit(int(bool(findings)))
