"""Redaction: scrub sensitive data from tool results before the agent sees them.

Three layers, all applied recursively:

1. Key names. Any dict key containing a sensitive term ("password", "token", ...) has its
   whole value replaced. Extra names you configure are matched exactly (case-insensitive).
2. Value patterns. AWS access key IDs, PEM private keys and JWTs are scrubbed from any
   string, plus any regexes you configure.
3. Text secrets. "password=hunter2" / '"api_key": "abc"' inside free text (for example an
   S3 file) has its value scrubbed.

Limits worth knowing: redaction hides values, it does not stop an agent from inferring them
through filter expressions, and it cannot recognise a secret that has no telltale name or
shape. Use the table/bucket allowlists for anything truly off limits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

REDACTED = "[REDACTED]"

# Matched as substrings of the normalised key name (lowercase, letters/digits only).
DEFAULT_SENSITIVE_TERMS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "privatekey",
    "authorization",
    "credential",
)

# Structural keys we generate ourselves; never redact these.
EXEMPT_KEYS = frozenset({"nexttoken"})

DEFAULT_VALUE_PATTERNS = (
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",  # AWS access key id
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",  # PEM
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",  # JWT
)


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


@dataclass(frozen=True)
class Redactor:
    names: frozenset[str] = field(default_factory=frozenset)  # normalised, exact match
    patterns: tuple[str, ...] = ()
    defaults: bool = True
    _value_res: tuple[re.Pattern, ...] = field(init=False, repr=False, default=())
    _text_re: re.Pattern | None = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        object.__setattr__(self, "names", frozenset(_norm(n) for n in self.names if n))
        pats = (DEFAULT_VALUE_PATTERNS if self.defaults else ()) + tuple(self.patterns)
        object.__setattr__(
            self, "_value_res", tuple(re.compile(p, re.DOTALL) for p in pats)
        )
        words = list(DEFAULT_SENSITIVE_TERMS if self.defaults else ()) + sorted(self.names)
        if words:
            alt = "|".join(r"[-_]?".join(re.escape(c) for c in w) for w in words)
            # key (optionally quoted) then : or =, then the value
            text = (
                rf"(?i)(\b(?:[\w-]*(?:{alt})[\w-]*)[\"']?\s*[:=]\s*)"
                rf"(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;&]+)"
            )
            object.__setattr__(self, "_text_re", re.compile(text))

    # ------------------------------------------------------------------ public

    def redact(self, value: Any) -> tuple[Any, int]:
        """Return (clean_copy, number_of_redactions)."""
        count = 0

        def walk(v: Any) -> Any:
            nonlocal count
            if isinstance(v, dict):
                out = {}
                for k, x in v.items():
                    if isinstance(k, str) and self._sensitive_key(k):
                        out[k] = REDACTED
                        count += 1
                    else:
                        out[k] = walk(x)
                return out
            if isinstance(v, (list, tuple)):
                return [walk(x) for x in v]
            if isinstance(v, str):
                s, n = self._scrub_text(v)
                count += n
                return s
            return v

        return walk(value), count

    # ----------------------------------------------------------------- helpers

    def _sensitive_key(self, key: str) -> bool:
        n = _norm(key)
        if n in EXEMPT_KEYS:
            return False
        if n in self.names:
            return True
        return self.defaults and any(t in n for t in DEFAULT_SENSITIVE_TERMS)

    def _scrub_text(self, text: str) -> tuple[str, int]:
        total = 0
        for rx in self._value_res:
            text, n = rx.subn(REDACTED, text)
            total += n
        if self._text_re is not None:
            hits = 0

            def sub(m: re.Match) -> str:
                nonlocal hits
                if m.group(2).strip("\"'") == REDACTED:  # already scrubbed above
                    return m.group(0)
                hits += 1
                return m.group(1) + REDACTED

            text = self._text_re.sub(sub, text)
            total += hits
        return text, total
