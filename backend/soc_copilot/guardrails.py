"""Defences for the AI pipeline itself: injection scanning, spotlighting, tool policy and output validation.

Every control assumes the model may be fooled; each layer must hold on its own.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import json
import re
import secrets
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any

# ---------------------------------------------------------------- findings


@dataclass
class Finding:
    id: str
    layer: str  # input | rag | tool | output
    kind: str
    severity: str  # info | low | medium | high
    location: str
    detail: str
    action: str
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingLog:
    def __init__(self) -> None:
        self.items: list[Finding] = []
        self._seq = itertools.count(1)

    def add(self, **kw: Any) -> Finding:
        f = Finding(id=f"GF-{next(self._seq)}", **kw)
        self.items.append(f)
        return f

    def to_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.items]


# ---------------------------------------------------------------- injection scanner

INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("instruction_override", "high", re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|all|any|your|system|the)\b"
        r"[^.\n]{0,25}?\b(instructions?|prompts?|rules|directives|guidelines|guardrails)\b", re.I)),
    ("addresses_ai", "high", re.compile(
        r"\b(note|message|instructions?|attention|memo)\s+(to|for)\s+(the\s+|any\s+)?(ai|assistant|llm|model|copilot|agent|chatbot|analyst\s+bot)\b"
        r"|\b(ai|llm)\s+(assistant|model|agent|copilot)\s*[:,]", re.I)),
    ("verdict_manipulation", "high", re.compile(
        r"\b(classify|mark|label|treat|report|close|resolve)\b[^.\n]{0,40}?\b(as\s+)?(a\s+)?(benign|false[\s-]positive|harmless|authori[sz]ed\s+activity)\b", re.I)),
    ("severity_manipulation", "high", re.compile(
        r"\bset\s+(the\s+)?(severity|priority)\s+to\b|\b(lower|downgrade|reduce)\s+(the\s+)?(severity|priority|risk)\b", re.I)),
    ("suppression", "medium", re.compile(r"\bdo\s+not\s+(mention|report|include|escalate|flag|alert|log)\b", re.I)),
    ("role_tokens", "high", re.compile(
        r"<\|im_start\|>|<\|system\|>|<\|assistant\|>|\[/?INST\]|<<SYS>>|(^|\n)\s*(system|assistant|developer)\s*:\s", re.I)),
    ("delimiter_escape", "high", re.compile(
        r"<<\s*/?\s*(END_)?UNTRUSTED|</?\s*untrusted[_\s-]?data|END\s+OF\s+(UNTRUSTED|DATA|LOG)|BEGIN\s+SYSTEM", re.I)),
    ("tool_directive", "high", re.compile(
        r"\b(call|invoke|run|execute|use)\s+(the\s+)?(tool|function)\b|\b(disable_user|isolate_host|delete_\w+|http_get|http_post|send_email|run_shell)\s*\(", re.I)),
    ("exfil_markup", "high", re.compile(r"!\[[^\]]*\]\(\s*https?://", re.I)),
    ("persona_hijack", "medium", re.compile(
        r"\byou\s+are\s+(now|no\s+longer)\b|\bnew\s+instructions\b|\bdeveloper\s+mode\b|\bjailbreak\b", re.I)),
]

HIDDEN_CHARS_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
TAG_CHARS_RE = re.compile("[\U000e0000-\U000e007f]+")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class ScanHit:
    pattern: str
    severity: str
    via: str  # plain | base64 | unicode_tags
    matched: str
    start: int
    end: int


def _decode_b64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    for enc in ("utf-8", "utf-16le"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in text)
        if text and printable / len(text) > 0.95:
            return text
    return None


def _match_patterns(text: str) -> list[tuple[str, str, re.Match[str]]]:
    return [(name, sev, m) for name, sev, pat in INJECTION_PATTERNS for m in pat.finditer(text)]


def scan_text(text: str) -> list[ScanHit]:
    """Find instruction-like content aimed at an AI inside a data field (plain, base64 or Unicode-tag encoded)."""
    if not text or not isinstance(text, str):
        return []
    hits: list[ScanHit] = []
    for tag_run in TAG_CHARS_RE.finditer(text):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tag_run.group(0))
        for name, sev, m in _match_patterns(decoded):
            hits.append(ScanHit(name, sev, "unicode_tags", m.group(0), tag_run.start(), tag_run.end()))
    visible = HIDDEN_CHARS_RE.sub("", text)
    normalized = unicodedata.normalize("NFKC", visible)
    offset_ok = len(normalized) == len(text)
    for name, sev, m in _match_patterns(normalized):
        start, end = (m.start(), m.end()) if offset_ok else _locate(text, m.group(0))
        hits.append(ScanHit(name, sev, "plain", m.group(0), start, end))
    for bm in B64_RE.finditer(text):
        decoded = _decode_b64(bm.group(0))
        if decoded:
            for name, sev, m in _match_patterns(unicodedata.normalize("NFKC", decoded)):
                hits.append(ScanHit(name, sev, "base64", m.group(0), bm.start(), bm.end()))
    return hits


def _locate(text: str, needle: str) -> tuple[int, int]:
    idx = text.lower().find(needle.lower())
    return (idx, idx + len(needle)) if idx >= 0 else (0, len(text))


def has_hidden_chars(text: str) -> bool:
    return bool(HIDDEN_CHARS_RE.search(text or ""))


_SENTENCE_RE = re.compile(r"[^.!?\n]*(?:[.!?]+|\n|$)")


def neutralize(text: str, hits: list[ScanHit], finding_id: str) -> str:
    """Redact every sentence (or encoded blob) that carries an injection hit; strip hidden characters."""
    spans = sorted((h.start, h.end) for h in hits)
    out: list[str] = []
    pos = 0
    marker = f"[REDACTED: suspected prompt injection, see {finding_id}]"
    for sm in _SENTENCE_RE.finditer(text):
        s, e = sm.start(), sm.end()
        if s == e:
            continue
        if any(a < e and b > s for a, b in spans):
            if not out or out[-1] != marker:
                out.append(text[pos:s])
                out.append(marker)
            pos = e
    out.append(text[pos:])
    cleaned = "".join(out)
    for a, b in spans:
        seg = text[a:b]
        if seg and seg in cleaned:
            cleaned = cleaned.replace(seg, marker)
    cleaned = HIDDEN_CHARS_RE.sub("", cleaned)
    return re.sub(r"(\s*" + re.escape(marker) + r")+", " " + marker, cleaned).strip()


class InputGuard:
    """Scans untrusted structures (alerts, tool results, retrieved chunks) and redacts injection attempts."""

    def __init__(self, findings: FindingLog, enabled: bool = True):
        self.findings = findings
        self.enabled = enabled
        self.nonce = secrets.token_hex(4)
        self.injection_evidence: list[dict[str, Any]] = []
        self._cache: dict[tuple[str, str], str] = {}

    def sanitize(self, obj: Any, location: str, layer: str = "input") -> Any:
        if not self.enabled:
            return obj
        return self._walk(obj, location, layer)

    def _walk(self, obj: Any, path: str, layer: str) -> Any:
        if isinstance(obj, dict):
            return {k: self._walk(v, f"{path}.{k}", layer) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(v, f"{path}[{i}]", layer) for i, v in enumerate(obj)]
        if isinstance(obj, str):
            cached = self._cache.get((path, obj))
            if cached is not None:
                return cached
            cleaned = self._clean_str(obj, path, layer)
            self._cache[(path, obj)] = cleaned
            return cleaned
        return obj

    def _clean_str(self, obj: str, path: str, layer: str) -> str:
        hits = scan_text(obj)
        if hits:
            strongest = max(hits, key=lambda h: h.severity == "high")
            f = self.findings.add(
                layer=layer, kind="prompt_injection", severity="high", location=path,
                detail=f"Instruction-like content aimed at the AI ({', '.join(sorted({h.pattern for h in hits}))}; "
                       f"via {', '.join(sorted({h.via for h in hits}))}).",
                action="redacted before reaching the model; kept as evidence",
                snippet=strongest.matched[:160])
            self.injection_evidence.append({"location": path, "finding_id": f.id, "text": obj})
            return neutralize(obj, hits, f.id)
        if has_hidden_chars(obj):
            self.findings.add(layer=layer, kind="hidden_unicode", severity="medium", location=path,
                              detail="Invisible Unicode characters present.", action="stripped")
            return HIDDEN_CHARS_RE.sub("", obj)
        return obj

    def wrap(self, label: str, content: str) -> str:
        if not self.enabled:
            return content
        return (f"<<UNTRUSTED_DATA {self.nonce} source={label}>>\n{content}\n"
                f"<<END_UNTRUSTED_DATA {self.nonce}>>")


# ---------------------------------------------------------------- tool policy


@dataclass
class ParamSpec:
    type: str
    max_len: int = 128
    maximum: int | None = None
    pattern: str | None = None


@dataclass
class ToolSpec:
    name: str
    description: str
    params: dict[str, ParamSpec]
    required: list[str] = field(default_factory=list)
    read_only: bool = True

    def to_llm(self) -> dict[str, Any]:
        props = {}
        for k, p in self.params.items():
            props[k] = {"type": p.type, "description": k.replace("_", " ")}
        return {"type": "function", "function": {
            "name": self.name, "description": self.description,
            "parameters": {"type": "object", "properties": props, "required": self.required}}}


class ToolPolicy:
    MAX_WINDOW = timedelta(days=3)

    def __init__(self, specs: dict[str, ToolSpec], findings: FindingLog, max_calls: int = 40, enabled: bool = True):
        self.specs = specs
        self.findings = findings
        self.max_calls = max_calls
        self.enabled = enabled
        self.calls = 0
        self.seen: set[str] = set()

    def check(self, name: str, args: dict[str, Any]) -> tuple[bool, str]:
        if not self.enabled:
            self.calls += 1
            return True, "policy disabled"
        reason = self._violation(name, args)
        if reason:
            self.findings.add(layer="tool", kind="tool_denied", severity="high" if "not allowed" in reason else "medium",
                              location=name, detail=reason, action="call blocked",
                              snippet=json.dumps(args)[:160])
            return False, reason
        self.calls += 1
        return True, "allowed"

    def _violation(self, name: str, args: dict[str, Any]) -> str | None:
        spec = self.specs.get(name)
        if spec is None:
            return f"Tool '{name}' is not allowed (not on the read-only allow-list)."
        if not spec.read_only:
            return f"Tool '{name}' is not allowed: state-changing actions require human approval."
        if self.calls >= self.max_calls:
            return f"Tool-call budget exhausted ({self.max_calls})."
        if not isinstance(args, dict):
            return "Arguments must be an object."
        for k in spec.required:
            if k not in args or args[k] in (None, ""):
                return f"Missing required argument '{k}'."
        for k, v in args.items():
            p = spec.params.get(k)
            if p is None:
                return f"Unexpected argument '{k}'."
            if v is None:
                continue
            if p.type == "string":
                if not isinstance(v, str):
                    return f"Argument '{k}' must be a string."
                if len(v) > p.max_len:
                    return f"Argument '{k}' exceeds {p.max_len} characters."
                if p.pattern and not re.fullmatch(p.pattern, v):
                    return f"Argument '{k}' has an invalid format."
            elif p.type == "integer":
                if not isinstance(v, int) or isinstance(v, bool):
                    return f"Argument '{k}' must be an integer."
                if p.maximum is not None and v > p.maximum:
                    return f"Argument '{k}'={v} exceeds the cap of {p.maximum}."
        if "start" in args or "end" in args:
            try:
                start = _ts(args.get("start")) if args.get("start") else None
                end = _ts(args.get("end")) if args.get("end") else None
            except ValueError:
                return "start/end must be ISO-8601 timestamps."
            if start and end and end - start > self.MAX_WINDOW:
                return f"Time window exceeds {self.MAX_WINDOW.days} days."
        key = f"{name}:{json.dumps(args, sort_keys=True)}"
        if key in self.seen:
            return "Duplicate call (loop protection)."
        self.seen.add(key)
        return None


def _ts(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


# ---------------------------------------------------------------- output guard

URL_RE = re.compile(r"\bhttps?://[^\s)\]>\"']+", re.I)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)]+)\)")
CITATION_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9]*-[A-Za-z0-9.-]+)\]")
PSEUDONYM_RE = re.compile(r"^(USER|EMAIL|PHONE|SSN|CARD|AWS_KEY|SECRET|TOKEN)_\d+$")
TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def defang(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]", 1) \
        if "://" in url else url


class OutputGuard:
    def __init__(self, findings: FindingLog, enabled: bool = True):
        self.findings = findings
        self.enabled = enabled

    def clean_text(self, text: str, known_ids: set[str], known_techniques: set[str], location: str) -> str:
        if not self.enabled or not text:
            return text
        for m in MD_IMAGE_RE.finditer(text):
            self.findings.add(layer="output", kind="exfil_markup", severity="high", location=location,
                              detail="Markdown image in model output (auto-loading URL can exfiltrate data).",
                              action="removed", snippet=m.group(0)[:160])
        text = MD_IMAGE_RE.sub("", text)
        text = MD_LINK_RE.sub(lambda m: f"{m.group(1)} ({defang(m.group(2))})", text)
        text = URL_RE.sub(lambda m: defang(m.group(0)), text)

        def _cite(m: re.Match[str]) -> str:
            ref = m.group(1)
            if PSEUDONYM_RE.match(ref) or ref in known_ids:
                return m.group(0)
            self.findings.add(layer="output", kind="unknown_citation", severity="medium", location=location,
                              detail=f"Model cited '{ref}', which is not in the collected evidence.",
                              action="citation removed", snippet=ref)
            return ""
        text = CITATION_RE.sub(_cite, text)
        for m in TECHNIQUE_RE.finditer(text):
            if m.group(1) not in known_techniques:
                self.findings.add(layer="output", kind="unsupported_technique", severity="low", location=location,
                                  detail=f"{m.group(1)} is not supported by any mapped evidence.",
                                  action="flagged", snippet=m.group(1))
        hits = scan_text(text)
        if hits:
            f = self.findings.add(layer="output", kind="injection_echo", severity="high", location=location,
                                  detail="Model output contains instruction-like text (possible injection echo).",
                                  action="redacted", snippet=hits[0].matched[:160])
            text = neutralize(text, hits, f.id)
        return re.sub(r"[ \t]{2,}", " ", text).strip()

    def enforce_verdict(self, proposed_verdict: str | None, proposed_severity: str | None,
                        floor_verdict: str, floor_severity: str, evidence_strength: str) -> tuple[str, str]:
        verdict = proposed_verdict or floor_verdict
        severity = proposed_severity if proposed_severity in SEVERITY_ORDER else floor_severity
        if not self.enabled:
            return verdict, severity
        if evidence_strength == "strong" and verdict != floor_verdict and floor_verdict == "true_positive":
            self.findings.add(layer="output", kind="verdict_conflict", severity="high", location="report.verdict",
                              detail=f"Model proposed '{verdict}' but grounded evidence is strongly malicious.",
                              action=f"overridden to '{floor_verdict}'", snippet=str(proposed_verdict))
            verdict = floor_verdict
        if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(floor_severity):
            self.findings.add(layer="output", kind="severity_floor", severity="high", location="report.severity",
                              detail=f"Model proposed severity '{severity}' below the evidence-based floor.",
                              action=f"raised to '{floor_severity}'", snippet=str(proposed_severity))
            severity = floor_severity
        return verdict, severity
