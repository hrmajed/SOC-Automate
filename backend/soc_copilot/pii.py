"""Reversible, identity-aware pseudonymisation applied before any text reaches an LLM.

All variants of one person (username, DOMAIN\\user, email, display name, IAM user) map to the same token so the
model can still correlate activity across EDR, IdP and CloudTrail without ever seeing the real identity.
IP addresses are intentionally left intact: they carry operational meaning and are not personal data in this context.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

TOKEN_RE = re.compile(r"\[(USER|EMAIL|PHONE|SSN|CARD|AWS_KEY|SECRET|TOKEN)_(\d+)\]")

_B = r"(?<![A-Za-z0-9])"
_E = r"(?![A-Za-z0-9])"

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SECRET", re.compile(r"(?i)((?:password|passwd|pwd|secret|aws_secret_access_key|api[_-]?key)\s*[=:]\s*)(\S{6,})")),
    ("TOKEN", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("AWS_KEY", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")),
    ("SSN", re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")),
    ("CARD", re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")),
    ("PHONE", re.compile(r"(?<![\w.])\+?\d{1,2}[ .-]?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PiiMasker:
    def __init__(self, identities: list[dict[str, Any]] | None = None):
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._counters: Counter[str] = Counter()
        self.stats: Counter[str] = Counter()
        self._identity_variants: list[tuple[re.Pattern[str], str]] = []
        for ident in identities or []:
            variants = {ident["username"], ident.get("email", ""), ident.get("display_name", ""),
                        ident.get("windows_account", ""), *ident.get("aliases", []), *ident.get("aws_iam_users", [])}
            name_parts = ident.get("display_name", "").split()
            if ident.get("title", "").lower() != "service account":
                variants.update(p for p in name_parts if len(p) >= 4)
            for v in sorted((v for v in variants if v), key=len, reverse=True):
                pat = re.compile(_B + re.escape(v) + _E, re.IGNORECASE)
                self._identity_variants.append((pat, ident["username"]))
        self._identity_variants.sort(key=lambda t: len(t[0].pattern), reverse=True)

    def _token(self, kind: str, value: str) -> str:
        key = (kind, value.lower() if kind in ("USER", "EMAIL") else value)
        if key not in self._forward:
            self._counters[kind] += 1
            tok = f"[{kind}_{self._counters[kind]}]"
            self._forward[key] = tok
            self._reverse[tok] = value
        self.stats[kind] += 1
        return self._forward[key]

    def mask_text(self, text: str) -> str:
        if not text:
            return text
        out = text
        m = PATTERNS[0][1]
        out = m.sub(lambda mm: mm.group(1) + self._token("SECRET", mm.group(2)), out)
        for kind in ("TOKEN", "AWS_KEY"):
            out = dict(PATTERNS)[kind].sub(lambda mm, k=kind: self._token(k, mm.group(0)), out)
        for pat, username in self._identity_variants:
            out = pat.sub(lambda mm, u=username: self._token("USER", u), out)
        out = dict(PATTERNS)["EMAIL"].sub(lambda mm: self._token("EMAIL", mm.group(0)), out)
        out = dict(PATTERNS)["SSN"].sub(lambda mm: self._token("SSN", mm.group(0)), out)
        out = dict(PATTERNS)["CARD"].sub(
            lambda mm: self._token("CARD", mm.group(0)) if _luhn_ok(mm.group(0)) else mm.group(0), out)
        out = dict(PATTERNS)["PHONE"].sub(lambda mm: self._token("PHONE", mm.group(0)), out)
        return out

    def unmask_text(self, text: str) -> str:
        if not text:
            return text
        return TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text)

    def mask(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.mask_text(obj)
        if isinstance(obj, list):
            return [self.mask(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.mask(v) for k, v in obj.items()}
        return obj

    def unmask(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.unmask_text(obj)
        if isinstance(obj, list):
            return [self.unmask(v) for v in obj]
        if isinstance(obj, dict):
            return {k: self.unmask(v) for k, v in obj.items()}
        return obj

    @property
    def vault_size(self) -> int:
        return len(self._reverse)

    def summary(self) -> dict[str, Any]:
        by_kind = Counter(tok.strip("[]").rsplit("_", 1)[0] for tok in self._reverse)
        return {"unique_values_masked": self.vault_size, "by_type": dict(by_kind),
                "replacements": sum(self.stats.values())}
