from __future__ import annotations

from types import SimpleNamespace

import pytest

from blackarch_ai.config import load_settings


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    """Never touch the real ~/.config or ~/.local/share during tests."""
    monkeypatch.setenv("BLACKARCH_AI_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("BLACKARCH_AI_DATA_DIR", str(tmp_path / "data"))
    for var in ("NVIDIA_NIM_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


@pytest.fixture
def settings():
    s = load_settings()
    # Pin retries so retry/fallback tests don't depend on the production default.
    s.llm.max_retries = 2
    return s


def response(content: str, *, prompt: int = 10, completion: int = 5, reasoning: str = ""):
    """A minimal object shaped like a LiteLLM ModelResponse."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content,
                                                         reasoning_content=reasoning))],
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion,
                              completion_tokens_details=None),
    )


def chunk(text: str = "", reasoning: str = "", usage=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=text or None,
                                                       reasoning_content=reasoning or None))],
        usage=usage,
    )


class FakeStream:
    def __init__(self, chunks, fail_after: int | None = None, exc: Exception | None = None):
        self.chunks = chunks
        self.fail_after = fail_after
        self.exc = exc

    def __aiter__(self):
        return self._gen()

    async def _gen(self):
        for i, c in enumerate(self.chunks):
            if self.fail_after is not None and i == self.fail_after:
                raise self.exc
            yield c
        if self.fail_after is not None and self.fail_after >= len(self.chunks):
            raise self.exc
