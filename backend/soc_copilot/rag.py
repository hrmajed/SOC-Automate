"""Local retrieval over the organisation's knowledge: network map, past incidents, compliance and policy docs.

Poisoning defences: provenance trust tiers, ingest-time injection scanning (quarantine) and a SHA-256
integrity manifest verified on every retrieval.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx
import numpy as np

from .config import DATA_DIR, Settings
from .guardrails import scan_text
from .store import DataStore

log = logging.getLogger(__name__)

SOURCE_TRUST = {"incident-reports": "trusted", "compliance": "trusted", "network-map": "trusted",
                "wiki-import": "untrusted"}

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]*[a-z0-9]|[a-z0-9]")


def tokenize(text: str) -> list[str]:
    toks = TOKEN_RE.findall(text.lower())
    out = list(toks)
    for t in toks:
        if any(c in t for c in ".-_") and not re.fullmatch(r"[\d.]+", t):
            out.extend(p for p in re.split(r"[.\-_]", t) if len(p) > 1)
    out.extend(f"{a} {b}" for a, b in zip(toks, toks[1:]))
    return out


class Embedder(Protocol):
    name: str

    def fit(self, texts: list[str]) -> None: ...
    def embed(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Deterministic, dependency-free TF-IDF embedding using feature hashing (fully offline)."""

    name = "hashing-tfidf-2048"

    def __init__(self, dim: int = 2048):
        self.dim = dim
        self.idf = np.ones(dim, dtype=np.float32)

    def _index(self, tok: str) -> tuple[int, float]:
        h = hashlib.blake2b(tok.encode(), digest_size=8).digest()
        n = int.from_bytes(h, "little")
        return n % self.dim, 1.0 if (n >> 63) & 1 else -1.0

    def _tf(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for tok, cnt in Counter(tokenize(text)).items():
            i, sign = self._index(tok)
            vec[i] += sign * (1.0 + math.log(cnt))
        return vec

    def fit(self, texts: list[str]) -> None:
        df = np.zeros(self.dim, dtype=np.float32)
        for t in texts:
            for tok in set(tokenize(t)):
                df[self._index(tok)[0]] += 1
        self.idf = np.log((1 + len(texts)) / (1 + df)).astype(np.float32) + 1.0

    def embed(self, texts: list[str]) -> np.ndarray:
        mat = np.stack([self._tf(t) * self.idf for t in texts]) if texts else np.zeros((0, self.dim))
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return mat / norms


class OllamaEmbedder:
    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"

    def fit(self, texts: list[str]) -> None:
        return None

    def embed(self, texts: list[str]) -> np.ndarray:
        r = httpx.post(f"{self.host}/api/embed", json={"model": self.model, "input": texts}, timeout=60)
        r.raise_for_status()
        mat = np.array(r.json()["embeddings"], dtype=np.float32)
        return mat / np.clip(np.linalg.norm(mat, axis=1, keepdims=True), 1e-9, None)


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    source: str
    trust: str
    doc_type: str
    text: str
    meta: dict[str, Any] = field(default_factory=dict)


def parse_frontmatter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---"):
        return {}, raw
    _, fm, body = raw.split("---", 2)
    meta = {}
    for line in fm.strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, body.strip()


def chunk_markdown(doc_id: str, title: str, body: str) -> list[str]:
    sections = re.split(r"\n(?=## )", body)
    chunks = []
    for sec in sections:
        sec = sec.strip()
        if sec:
            chunks.append(f"{title}\n{sec}")
    return chunks


class KnowledgeBase:
    def __init__(self, store: DataStore, settings: Settings | None = None, data_dir: Path = DATA_DIR):
        self.store = store
        self.settings = settings or Settings()
        self.data_dir = Path(data_dir)
        self.chunks: list[Chunk] = []
        self.docs: dict[str, dict[str, Any]] = {}
        self.manifest: dict[str, str] = {}
        self.quarantine: dict[str, dict[str, Any]] = {}
        self.embedder: Embedder = self._make_embedder()
        self.matrix = np.zeros((0, 1), dtype=np.float32)
        self.build()

    def _make_embedder(self) -> Embedder:
        if self.settings.embeddings == "ollama":
            emb = OllamaEmbedder(self.settings.ollama_host, self.settings.ollama_embed_model)
            try:
                emb.embed(["ping"])
                return emb
            except Exception as exc:  # pragma: no cover - depends on local Ollama
                log.warning("Ollama embeddings unavailable (%s); falling back to hashing embedder", exc)
        return HashingEmbedder()

    # ------------------------------------------------------------------ ingest
    def build(self) -> None:
        self.chunks = []
        kdir = self.data_dir / "knowledge"
        for path in sorted(kdir.rglob("*.md")):
            meta, body = parse_frontmatter(path.read_text())
            doc_id = meta.get("id", path.stem)
            source = meta.get("source", "unknown")
            self.docs[doc_id] = {**meta, "id": doc_id, "path": str(path.relative_to(self.data_dir)),
                                 "trust": SOURCE_TRUST.get(source, "untrusted")}
            for i, text in enumerate(chunk_markdown(doc_id, meta.get("title", doc_id), body)):
                self.chunks.append(Chunk(f"{doc_id}#{i}", doc_id, meta.get("title", doc_id), source,
                                         SOURCE_TRUST.get(source, "untrusted"), meta.get("type", "doc"), text, meta))
        self._ingest_network_map()
        for c in self.chunks:
            hits = scan_text(c.text)
            if hits and c.doc_id not in self.quarantine:
                self.quarantine[c.doc_id] = {
                    "doc_id": c.doc_id, "title": c.title, "source": c.source, "trust": c.trust,
                    "reason": f"Ingest scan found instruction-like content ({', '.join(sorted({h.pattern for h in hits}))})",
                    "snippet": hits[0].matched[:160]}
        self.manifest = {c.chunk_id: _sha(c.text) for c in self.chunks}
        texts = [c.text for c in self.chunks]
        self.embedder.fit(texts)
        self.matrix = self.embedder.embed(texts)

    def _ingest_network_map(self) -> None:
        nm = self.store.network_map
        for a in nm["assets"]:
            seg = next((s for s in nm["segments"] if s["name"] == a["segment"]), {})
            text = (f"Asset {a['hostname']} ({a['type']}, {a['os']}) IP {a['ip']} in segment {a['segment']} "
                    f"({seg.get('cidr', '')}, zone {seg.get('zone', '')}). Owner {a['owner']}. Criticality {a['criticality']}. "
                    f"Tags: {', '.join(a['tags'])}. {a['notes']} Segment rule: {seg.get('notes', '')}")
            doc_id = f"ASSET-{a['hostname']}"
            meta = {"id": doc_id, "title": f"Network map: {a['hostname']}", "type": "asset", "source": "network-map",
                    "hosts": a["hostname"], "summary": f"{a['hostname']} is a {a['criticality']}-criticality {a['type']} "
                                                       f"in {a['segment']}. {a['notes']}"}
            self.docs[doc_id] = {**meta, "trust": "trusted", "path": "network_map.json"}
            self.chunks.append(Chunk(f"{doc_id}#0", doc_id, meta["title"], "network-map", "trusted", "asset", text, meta))
        for acct in nm.get("cloud", []):
            for r in acct["resources"]:
                doc_id = f"CLOUD-{r['name']}"
                text = (f"AWS account {acct['account_id']} ({acct['alias']}) resource {r['type']} {r['name']}. "
                        f"Criticality {r['criticality']}. {('Data classification: ' + r['classification'] + '. ') if r.get('classification') else ''}"
                        f"{r['notes']}")
                meta = {"id": doc_id, "title": f"Cloud inventory: {r['name']}", "type": "cloud_asset",
                        "source": "network-map", "hosts": r["name"],
                        "summary": f"{r['name']} ({r['type']}, {r['criticality']} criticality). "
                                   f"{r.get('classification', '')} {r['notes']}".strip()}
                self.docs[doc_id] = {**meta, "trust": "trusted", "path": "network_map.json"}
                self.chunks.append(Chunk(f"{doc_id}#0", doc_id, meta["title"], "network-map", "trusted",
                                         "cloud_asset", text, meta))

    def remove_doc(self, doc_id: str) -> None:
        keep = [i for i, c in enumerate(self.chunks) if c.doc_id != doc_id]
        self.chunks = [self.chunks[i] for i in keep]
        self.matrix = self.matrix[keep]
        self.docs.pop(doc_id, None)
        self.quarantine.pop(doc_id, None)
        self.manifest = {k: v for k, v in self.manifest.items() if not k.startswith(f"{doc_id}#")}

    def tamper(self, doc_id: str, new_text: str) -> None:
        """Simulate an unauthorised post-review edit (used by the adversarial eval)."""
        for c in self.chunks:
            if c.doc_id == doc_id:
                c.text = new_text
                break

    # ------------------------------------------------------------------ retrieval
    def search(self, query: str, k: int = 4, guarded: bool = True) -> dict[str, Any]:
        qv = self.embedder.embed([query])[0]
        scores = self.matrix @ qv
        order = np.argsort(-scores)
        hits: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        seen_docs: set[str] = set()
        for idx in order:
            if len(hits) >= k:
                break
            c = self.chunks[int(idx)]
            score = float(scores[idx])
            if score <= 0.02:
                break
            if guarded:
                reason = None
                if c.doc_id in self.quarantine:
                    reason = "quarantined at ingest (injection content)"
                elif c.trust != "trusted":
                    reason = f"source '{c.source}' is not a trusted tier"
                elif _sha(c.text) != self.manifest.get(c.chunk_id):
                    reason = "integrity check failed (content changed after indexing)"
                if reason:
                    blocked.append({"doc_id": c.doc_id, "chunk_id": c.chunk_id, "title": c.title, "reason": reason,
                                    "score": round(score, 3)})
                    continue
            if c.doc_id in seen_docs:
                continue
            seen_docs.add(c.doc_id)
            hits.append({"doc_id": c.doc_id, "chunk_id": c.chunk_id, "title": c.title, "source": c.source,
                         "trust": c.trust, "type": c.doc_type, "score": round(score, 3),
                         "summary": c.meta.get("summary", ""), "disposition": c.meta.get("disposition"),
                         "hosts": [h.strip() for h in c.meta.get("hosts", "").split(",") if h.strip()],
                         "text": c.text[:1200]})
        return {"query": query, "hits": hits, "blocked": blocked}

    def info(self) -> dict[str, Any]:
        return {"embedder": self.embedder.name, "chunks": len(self.chunks), "documents": len(self.docs),
                "quarantined": list(self.quarantine.values()),
                "by_trust": dict(Counter(c.trust for c in self.chunks))}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
