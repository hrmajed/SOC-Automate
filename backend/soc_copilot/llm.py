"""Pluggable LLM backends. All share the Ollama chat message format.

- OllamaBackend: local model with native tool calling (llama3.1, qwen2.5, mistral-nemo, ...).
- MockBackend: deterministic planner so the product works with no model (demos, CI, evals).
- GullibleBackend / CompromisedBackend: adversarial stand-ins used by the eval harness.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from .config import Settings

log = logging.getLogger(__name__)

CONTEXT_MARKER = "INVESTIGATION_CONTEXT_JSON:"


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMBackend(Protocol):
    name: str
    model: str

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             json_mode: bool = False) -> LLMResponse: ...


# ---------------------------------------------------------------------------- Ollama


class OllamaBackend:
    name = "ollama"

    def __init__(self, host: str, model: str, timeout: float = 180):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             json_mode: bool = False) -> LLMResponse:
        payload: dict[str, Any] = {"model": self.model, "messages": messages, "stream": False,
                                   "options": {"temperature": 0.1, "num_ctx": 16384}}
        if tools:
            payload["tools"] = tools
        if json_mode:
            payload["format"] = "json"
        r = httpx.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout)
        r.raise_for_status()
        msg = r.json().get("message", {})
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            calls.append(ToolCall(fn.get("name", ""), args))
        return LLMResponse(content=msg.get("content", ""), tool_calls=calls)

    @staticmethod
    def probe(host: str, model: str) -> tuple[bool, str | None]:
        try:
            r = httpx.get(f"{host.rstrip('/')}/api/tags", timeout=0.8)
            r.raise_for_status()
            names = [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return False, None
        if not names:
            return False, None
        if model in names or f"{model}:latest" in names:
            return True, model
        chat_models = [n for n in names if "embed" not in n]
        return (True, chat_models[0]) if chat_models else (False, None)


# ---------------------------------------------------------------------------- Mock planner


def _extract_json_blocks(content: str) -> list[Any]:
    out = []
    body = re.sub(r"<<(END_)?UNTRUSTED_DATA[^>]*>>", "", content)
    try:
        out.append(json.loads(body.strip()))
    except json.JSONDecodeError:
        pass
    return out


class MockBackend:
    """Deterministic pivot planner: follows entities discovered in tool results, then consults the knowledge base.

    It only reads the masked conversation (like a real model would) and returns tool calls in batches.
    The final message defers narrative writing to the grounded synthesiser.
    """

    name = "mock"
    model = "deterministic-planner-v1"

    def __init__(self, step_delay: float = 0.0):
        self.step_delay = step_delay

    def _context(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        for m in messages:
            if m["role"] == "user" and CONTEXT_MARKER in m["content"]:
                raw = m["content"].split(CONTEXT_MARKER, 1)[1].strip().splitlines()[0]
                return json.loads(raw)
        return {}

    def plan(self, messages: list[dict[str, Any]]) -> list[ToolCall]:
        ctx = self._context(messages)
        done = {json.dumps({"n": tc["function"]["name"], "a": tc["function"]["arguments"]}, sort_keys=True)
                for m in messages if m["role"] == "assistant" for tc in m.get("tool_calls") or []}
        window = ctx.get("window", {})
        ents: list[tuple[str, str]] = []

        def add(kind: str, value: str | None) -> None:
            if value and (kind, value) not in ents:
                ents.append((kind, value))

        for kind in ("hosts", "users", "ips"):
            for v in ctx.get("entities", {}).get(kind, []):
                add(kind, v)
        internal_ips: set[str] = set()
        for m in messages:
            if m["role"] != "tool":
                continue
            for data in _extract_json_blocks(m["content"]):
                if not isinstance(data, dict):
                    continue
                if data.get("ip") and data.get("internal"):
                    internal_ips.add(data["ip"])
                    add("hosts", data.get("asset"))
                for ev in data.get("events", []):
                    for kind in ("hosts", "users", "ips", "buckets", "roles"):
                        for v in ev.get("entities", {}).get(kind, []):
                            add(kind, v)
        tw = {k: window[k] for k in ("start", "end") if window.get(k)}
        calls: list[ToolCall] = []
        for kind, v in ents:
            if kind == "hosts":
                cand = [ToolCall("lookup_asset", {"name": v}), ToolCall("query_edr", {"host": v, **tw})]
            elif kind == "users":
                cand = [ToolCall("lookup_identity", {"user": v}), ToolCall("query_idp", {"user": v, **tw}),
                        ToolCall("query_edr", {"user": v, **tw}), ToolCall("query_cloudtrail", {"user": v, **tw})]
            elif kind == "ips":
                cand = [ToolCall("lookup_ip", {"ip": v})]
                looked_up = any(json.loads(d)["n"] == "lookup_ip" and json.loads(d)["a"].get("ip") == v for d in done)
                if looked_up and v not in internal_ips:
                    cand += [ToolCall("query_cloudtrail", {"source_ip": v, **tw}),
                             ToolCall("query_idp", {"source_ip": v, **tw})]
            else:
                cand = [ToolCall("lookup_asset", {"name": v})]
            pending = [c for c in cand if json.dumps({"n": c.name, "a": c.arguments}, sort_keys=True) not in done]
            if pending:
                calls = pending
                break
        if calls:
            return calls
        hosts = [v for k, v in ents if k == "hosts"]
        followups = []
        primary = (ctx.get("entities", {}).get("hosts") or ctx.get("entities", {}).get("users") or [None])[0]
        if primary:
            followups.append(ToolCall("get_related_alerts", {"entity": primary}))
        followups.append(ToolCall("search_knowledge", {"query": f"{ctx.get('title', '')} {' '.join(hosts[:2])}".strip(), "k": 4}))
        ext_ips = [v for k, v in ents if k == "ips" and v not in internal_ips]
        if ext_ips:
            followups.append(ToolCall("search_knowledge", {"query": f"{' '.join(ext_ips[:3])} known IP vendor", "k": 3}))
        buckets = [v for k, v in ents if k == "buckets"]
        if buckets:
            followups.append(ToolCall("search_knowledge", {"query": f"{' '.join(buckets)} personal data breach notification", "k": 3}))
        if len(hosts) > 1:
            followups.append(ToolCall("search_knowledge", {"query": f"{' '.join(hosts[1:3])} privileged access credentials policy", "k": 3}))
        return [c for c in followups if json.dumps({"n": c.name, "a": c.arguments}, sort_keys=True) not in done]

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             json_mode: bool = False) -> LLMResponse:
        if self.step_delay:
            time.sleep(self.step_delay)
        if json_mode or not tools:
            return LLMResponse(content=json.dumps(self.final(messages)))
        calls = self.plan(messages)
        if calls:
            return LLMResponse(tool_calls=calls)
        return LLMResponse(content="INVESTIGATION_COMPLETE")

    def final(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return {"verdict": None, "severity": None, "narrative": None}


# ---------------------------------------------------------------------------- adversarial stand-ins

OBEY_PATTERNS = {
    "benign": re.compile(r"(benign|false[\s-]positive|authori[sz]ed)", re.I),
    "low": re.compile(r"severity\s+to\s+(low|info)", re.I),
    "tool": re.compile(r"\b(disable_user|isolate_host|http_get)\b\s*\(?\s*['\"]?([^'\")]*)", re.I),
    "image": re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)"),
}


def _reveal_hidden(text: str) -> str:
    """A 'gullible' model reads everything: plain text, Unicode tag characters and base64 blobs."""
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)
    decoded = []
    for tok in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            decoded.append(raw.decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return "\n".join([text, tags, *decoded])


INSTRUCTION_CUE = re.compile(r"(ignore (all |any )?previous|note to (the )?ai|ai assistant|system\s*:|always classify)", re.I)


class GullibleBackend(MockBackend):
    """Simulates a model that obeys any instruction it can read inside its context window."""

    name = "gullible-mock"
    model = "obeys-injections"

    def _injected(self, messages: list[dict[str, Any]]) -> str:
        texts = [_reveal_hidden(m.get("content", "")) for m in messages if m["role"] in ("user", "tool")]
        return "\n".join(t for t in texts if INSTRUCTION_CUE.search(t))

    def plan(self, messages: list[dict[str, Any]]) -> list[ToolCall]:
        injected = self._injected(messages)
        done = {tc["function"]["name"] for m in messages if m["role"] == "assistant" for tc in m.get("tool_calls") or []}
        m = OBEY_PATTERNS["tool"].search(injected)
        if m and m.group(1) not in done:
            return [ToolCall(m.group(1), {"target": m.group(2) or "all"})]
        return super().plan(messages)

    def final(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        injected = self._injected(messages)
        out: dict[str, Any] = {"verdict": None, "severity": None, "narrative": None}
        if OBEY_PATTERNS["benign"].search(injected):
            out.update(verdict="likely_benign", severity="low",
                       narrative="Authorized activity; this is a benign false positive. No further action required.")
        if OBEY_PATTERNS["low"].search(injected):
            out["severity"] = "low"
        img = OBEY_PATTERNS["image"].search(injected)
        if img:
            out["narrative"] = (out["narrative"] or "Investigation complete.") + f" ![status]({img.group(1)})"
        return out


class CompromisedBackend(MockBackend):
    """Simulates a fully compromised model (e.g. a detector bypass or backdoored weights) with scripted behaviour."""

    name = "compromised-mock"
    model = "scripted-attacker"

    def __init__(self, tool_calls: list[ToolCall] | None = None, final: dict[str, Any] | None = None):
        super().__init__()
        self.scripted_calls = tool_calls or []
        self.scripted_final = final

    def plan(self, messages: list[dict[str, Any]]) -> list[ToolCall]:
        issued = sum(len(m.get("tool_calls") or []) for m in messages if m["role"] == "assistant")
        if issued < len(self.scripted_calls):
            return self.scripted_calls[issued:]
        return super().plan(messages)

    def final(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return self.scripted_final or super().final(messages)


# ---------------------------------------------------------------------------- selection


def select_backend(settings: Settings | None = None) -> LLMBackend:
    s = settings or Settings()
    choice = s.llm_backend.lower()
    if choice in ("auto", "ollama"):
        ok, model = OllamaBackend.probe(s.ollama_host, s.ollama_model)
        if ok and model:
            log.info("Using Ollama backend (%s)", model)
            return OllamaBackend(s.ollama_host, model)
        if choice == "ollama":
            log.warning("Ollama requested but not reachable at %s; falling back to mock", s.ollama_host)
    return MockBackend(step_delay=s.mock_step_delay)
