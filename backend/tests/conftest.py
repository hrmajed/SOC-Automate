import os

import pytest

os.environ.setdefault("SOC_LLM_BACKEND", "mock")

from soc_copilot.config import Settings  # noqa: E402
from soc_copilot.rag import KnowledgeBase  # noqa: E402
from soc_copilot.store import DataStore  # noqa: E402


@pytest.fixture(scope="session")
def settings():
    return Settings(llm_backend="mock", mock_step_delay=0.0)


@pytest.fixture
def store():
    return DataStore()


@pytest.fixture
def kb(store, settings):
    return KnowledgeBase(store, settings)
