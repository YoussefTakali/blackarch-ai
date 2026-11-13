"""Remove secrets from text before it is sent to a cloud model.

Redaction is local and deterministic; it does not depend on the LLM. The
original text stays in the local database — only the outbound copy changes.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

MASK = "[REDACTED]"

# (kind, pattern, replacement). Replacements may keep a non-secret prefix.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        f"[REDACTED PRIVATE KEY]",
    ),
    (
        "api_token",
        re.compile(
            r"\b(?:sk-ant-[A-Za-z0-9_\-]{20,}"
            r"|sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"
            r"|nvapi-[A-Za-z0-9_\-]{20,}"
            r"|AIza[0-9A-Za-z_\-]{35}"
            r"|gh[pousr]_[A-Za-z0-9]{36,}"
            r"|github_pat_[A-Za-z0-9_]{40,}"
            r"|xox[abprs]-[A-Za-z0-9\-]{10,})"
        ),
        MASK,
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        MASK,
    ),
    (
        "bearer",
        re.compile(r"(?i)\b(authorization:\s*(?:bearer|basic|token)\s+)[^\s\"']+"),
        r"\g<1>" + MASK,
    ),
    (
        "url_credentials",
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"),
        r"\g<1>" + MASK + "@",
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b((?:password|passwd|pwd|passphrase|secret|client[_\-]?secret"
            r"|api[_\-]?key|access[_\-]?key|secret[_\-]?key|auth[_\-]?token|token)"
            r"[\"']?\s*[:=]\s*)([\"']?)([^\s\"',;]{4,})\2"
        ),
        r"\g<1>\g<2>" + MASK + r"\g<2>",
    ),
]

_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD)", re.IGNORECASE)


@dataclass
class RedactionResult:
    text: str
    counts: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    def __init__(
        self,
        extra_patterns: Iterable[str] = (),
        secret_values: Iterable[str] | None = None,
    ) -> None:
        self._extra = [re.compile(p) for p in extra_patterns]
        if secret_values is None:
            secret_values = (
                v for k, v in os.environ.items() if _SECRET_ENV.search(k) and len(v) >= 8
            )
        # Longest first so a value that contains another is masked whole.
        self._literals = sorted({v for v in secret_values if len(v) >= 8}, key=len, reverse=True)

    def redact(self, text: str) -> RedactionResult:
        counts: Counter[str] = Counter()
        for value in self._literals:
            if value in text:
                counts["env_secret"] += text.count(value)
                text = text.replace(value, MASK)
        for kind, pattern, repl in _PATTERNS:
            text, n = pattern.subn(repl, text)
            if n:
                counts[kind] += n
        for pattern in self._extra:
            text, n = pattern.subn(MASK, text)
            if n:
                counts["custom"] += n
        # A literal already masked can be matched again by a pattern
        # (e.g. "token=[REDACTED]"); don't count masks of masks.
        return RedactionResult(text=text, counts=counts)

    def redact_messages(self, messages: list[dict]) -> tuple[list[dict], Counter[str]]:
        """Return redacted copies of chat messages (string or text-part content)."""
        total: Counter[str] = Counter()
        out: list[dict] = []
        for msg in messages:
            new = dict(msg)
            content = msg.get("content")
            if isinstance(content, str):
                r = self.redact(content)
                new["content"] = r.text
                total.update(r.counts)
            elif isinstance(content, list):
                parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        r = self.redact(part.get("text", ""))
                        total.update(r.counts)
                        part = {**part, "text": r.text}
                    parts.append(part)
                new["content"] = parts
            out.append(new)
        return out, total
