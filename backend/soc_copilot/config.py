from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).parent / "data"))


@dataclass
class Settings:
    llm_backend: str = field(default_factory=lambda: os.environ.get("SOC_LLM_BACKEND", "auto"))
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    ollama_model: str = field(default_factory=lambda: os.environ.get("SOC_OLLAMA_MODEL", "llama3.1:8b"))
    embeddings: str = field(default_factory=lambda: os.environ.get("SOC_EMBEDDINGS", "hashing"))
    ollama_embed_model: str = field(default_factory=lambda: os.environ.get("SOC_OLLAMA_EMBED_MODEL", "nomic-embed-text"))
    mock_step_delay: float = field(default_factory=lambda: float(os.environ.get("SOC_MOCK_STEP_DELAY", "0")))
    max_tool_calls: int = field(default_factory=lambda: int(os.environ.get("SOC_MAX_TOOL_CALLS", "30")))
    cors_origins: list[str] = field(
        default_factory=lambda: os.environ.get("SOC_CORS_ORIGINS", "*").split(",")
    )


def get_settings() -> Settings:
    return Settings()
