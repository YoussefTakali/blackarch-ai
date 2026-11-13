"""Known cloud providers and how to tell whether each one is configured.

Calls go through LiteLLM, so adding a provider is mostly a matter of listing
its LiteLLM prefix and the environment variable that holds its key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str            # LiteLLM provider prefix
    name: str
    key_env: tuple[str, ...]  # any one of these satisfies the provider
    docs: str


PROVIDERS: dict[str, Provider] = {
    p.id: p
    for p in [
        Provider("nvidia_nim", "NVIDIA API Catalog (NIM)", ("NVIDIA_NIM_API_KEY",), "https://build.nvidia.com"),
        Provider("anthropic", "Anthropic", ("ANTHROPIC_API_KEY",), "https://console.anthropic.com"),
        Provider("openai", "OpenAI", ("OPENAI_API_KEY",), "https://platform.openai.com"),
        Provider("gemini", "Google Gemini", ("GEMINI_API_KEY",), "https://aistudio.google.com"),
    ]
}

# Local providers need no API key and run on the machine; always "available".
LOCAL_PREFIXES = ("ollama", "ollama_chat")


def provider_of(model: str) -> str:
    """Provider id for a model string. Unprefixed names are resolved by LiteLLM."""
    if "/" in model:
        prefix = model.split("/", 1)[0]
        if prefix in PROVIDERS:
            return prefix
    try:
        import litellm

        return litellm.get_llm_provider(model)[1]
    except Exception:
        return model.split("/", 1)[0] if "/" in model else "unknown"


def has_key(provider_id: str) -> bool:
    prov = PROVIDERS.get(provider_id)
    if prov is None:
        return False
    return any(os.environ.get(var) for var in prov.key_env)


def model_available(model: str) -> bool:
    prov = provider_of(model)
    if prov in LOCAL_PREFIXES:  # local Ollama: no key needed, always usable
        return True
    return has_key(prov)
