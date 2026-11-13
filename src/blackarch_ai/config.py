"""Configuration: built-in defaults, overridden by ~/.config/blackarch-ai/config.toml.

Secrets never live in config.toml. They come from the process environment or
from ~/.config/blackarch-ai/.env (loaded without overriding real env vars).
"""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

ORCH_MODEL = "nvidia_nim/stepfun-ai/step-5-preview"
AGENT_MODEL = "nvidia_nim/nvidia/nemotron-3.5-lightning-30b-a3b"
MISTRAL = "nvidia_nim/mistralai/mistral-large-4-1t-a52b"
MINIMAX = "nvidia_nim/minimaxai/minimax-m3.1-flash"
# Kept for callers/tests that refer to the primary orchestrator model.
DEFAULT_PRIMARY = ORCH_MODEL


def config_dir() -> Path:
    return Path(os.environ.get("BLACKARCH_AI_CONFIG_DIR", "~/.config/blackarch-ai")).expanduser()


def data_dir() -> Path:
    return Path(os.environ.get("BLACKARCH_AI_DATA_DIR", "~/.local/share/blackarch-ai")).expanduser()


class ModelProfile(BaseModel):
    """Which model a role uses, and what to fall back to when it fails."""

    model: str
    fallbacks: list[str] = Field(default_factory=list)
    temperature: float | None = 0.4
    top_p: float | None = None
    max_tokens: int | None = None
    reasoning_effort: str | None = None
    # Prepended as a system message to every call (e.g. "/no_think" for qwen3 on
    # Ollama, which otherwise emits a huge reasoning block and times out).
    prompt_prefix: str | None = None
    # Provider-specific body, e.g. {"chat_template_kwargs": {"enable_thinking": true}}
    extra_body: dict[str, Any] | None = None
    # Discourage the model from looping the same text; dropped for models that
    # don't support them (drop_params=True in the gateway). These default on so
    # existing config.toml profiles (which replace ours wholesale) still get them.
    frequency_penalty: float | None = 0.5
    presence_penalty: float | None = 0.3
    timeout: float = 240.0

    @field_validator("reasoning_effort")
    @classmethod
    def _effort(cls, v: str | None) -> str | None:
        if v is not None and v not in {"minimal", "low", "medium", "high"}:
            raise ValueError("reasoning_effort must be minimal, low, medium or high")
        return v

    def chain(self) -> list[str]:
        seen: list[str] = []
        for m in [self.model, *self.fallbacks]:
            if m not in seen:
                seen.append(m)
        return seen


class Pricing(BaseModel):
    """USD per million tokens. Overrides LiteLLM's built-in price table."""

    input_per_mtok: float
    output_per_mtok: float


class LLMSettings(BaseModel):
    profiles: dict[str, ModelProfile]
    max_retries: int = 2
    retry_backoff: float = 2.0
    pricing: dict[str, Pricing] = Field(default_factory=dict)

    def profile_for(self, role: str) -> ModelProfile:
        """Exact role (e.g. an agent id) → 'agent' for agents → 'orchestrator'."""
        if role in self.profiles:
            return self.profiles[role]
        if role != "orchestrator" and "agent" in self.profiles:
            return self.profiles["agent"]
        return self.profiles["orchestrator"]


class RedactionSettings(BaseModel):
    enabled: bool = True
    extra_patterns: list[str] = Field(default_factory=list)


class ChatSettings(BaseModel):
    max_history_messages: int = 40


class AgentOverride(BaseModel):
    """Per-agent settings from [agents.<id>] in config.toml."""

    enabled: bool = True
    # Can only lower the ceiling from agents.toml, never raise it.
    max_permission: str | None = None
    # Appended to the agent's system prompt.
    extra_instructions: str = ""
    # Max installed-tool names listed in the agent's prompt.
    max_tool_names: int = 40


class Settings(BaseModel):
    llm: LLMSettings
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)
    chat: ChatSettings = Field(default_factory=ChatSettings)
    agents: dict[str, AgentOverride] = Field(default_factory=dict)

    def agent(self, agent_id: str) -> AgentOverride:
        return self.agents.get(agent_id, AgentOverride())

    @property
    def db_path(self) -> Path:
        return data_dir() / "blackarch-ai.db"


DEFAULTS: dict[str, Any] = {
    "llm": {
        "max_retries": 1,
        "retry_backoff": 2.0,
        "profiles": {
            "orchestrator": {
                # minimax leads: fast + valid JSON. stepfun valid but can hang
                # for minutes on big prompts. mistral excluded (~350s).
                "model": MINIMAX,
                "fallbacks": [ORCH_MODEL, AGENT_MODEL,
                              "anthropic/claude-sonnet-5-5", "openai/gpt-5.5", "gemini/gemini-3.8-flash"],
                "max_tokens": 8192,
                "temperature": 0.4,
                "frequency_penalty": 0.5,
                "presence_penalty": 0.3,
                "timeout": 60.0,
            },
            "agent": {
                "model": MINIMAX,
                "fallbacks": [ORCH_MODEL, AGENT_MODEL,
                              "anthropic/claude-haiku-5-5", "openai/gpt-5.4-mini", "gemini/gemini-3.8-flash"],
                "max_tokens": 8192,
                "temperature": 0.4,
                "frequency_penalty": 0.5,
                "presence_penalty": 0.3,
                "timeout": 60.0,
            },
        },
    },
}

DEFAULT_CONFIG_TOML = f"""\
# BlackArch AI configuration. API keys do NOT go here — use .env in this directory.
#
# Model names use LiteLLM's "provider/model" form. A role tries `model` first,
# then each fallback whose provider has an API key configured.
# Roles: "orchestrator", "agent" (default for all agents), or a specific agent
# id such as "web" or "network" to give that agent its own model.

[llm]
max_retries = 1        # retries per model on transient errors (rate limit, timeout, 5xx)
retry_backoff = 2.0    # seconds, doubled after each retry

[llm.profiles.orchestrator]
model = "{ORCH_MODEL}"
fallbacks = ["{AGENT_MODEL}", "{MISTRAL}", "{MINIMAX}",
             "anthropic/claude-sonnet-5-5", "openai/gpt-5.5", "gemini/gemini-3.8-flash"]
max_tokens = 8192
temperature = 0.4          # lower = steadier; the provider default can ramble
frequency_penalty = 0.5    # discourage looping the same text (dropped if unsupported)
presence_penalty = 0.3
# reasoning_effort = "medium"   # sent only to models that support it
# timeout = 240        # seconds per attempt

[llm.profiles.agent]
# stepfun reliably returns valid structured JSON; nemotron-3.5-lightning does
# not (it mangles field names / omits the JSON), so it is not used for agents.
model = "{ORCH_MODEL}"
fallbacks = ["{MISTRAL}", "{MINIMAX}",
             "anthropic/claude-haiku-5-5", "openai/gpt-5.4-mini", "gemini/gemini-3.8-flash"]
max_tokens = 8192
temperature = 0.4
frequency_penalty = 0.5
presence_penalty = 0.3

# Example per-agent override:
# [llm.profiles.web]
# model = "anthropic/claude-sonnet-5-5"

# Prices (USD per million tokens) for models LiteLLM doesn't know. Without an
# entry, cost is shown as "unknown" rather than guessed.
# [llm.pricing."{ORCH_MODEL}"]
# input_per_mtok = 0.0
# output_per_mtok = 0.0

[redaction]
enabled = true
# Extra regexes whose matches are replaced before text is sent to a cloud model.
extra_patterns = []

[chat]
max_history_messages = 40

# Per-agent settings. Agents are defined in the package's data/agents.toml;
# use these sections to switch one off, lower its permission ceiling, or add
# instructions. The model for an agent is set under [llm.profiles.<id>].
# [agents.exploitation]
# enabled = false
# [agents.web]
# max_permission = "low"
# extra_instructions = "The client forbids authenticated testing."
"""


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_env() -> Path:
    env_file = config_dir() / ".env"
    if env_file.is_file():
        load_dotenv(env_file, override=False)
    return env_file


def load_settings(path: Path | None = None) -> Settings:
    load_env()
    path = path or config_dir() / "config.toml"
    raw: dict[str, Any] = {}
    if path.is_file():
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    merged = _deep_merge(DEFAULTS, raw)
    # A profile defined in the file replaces the default one wholesale, so a
    # user's fallback list isn't silently merged with ours.
    for name, prof in raw.get("llm", {}).get("profiles", {}).items():
        merged["llm"]["profiles"][name] = prof
    return Settings.model_validate(merged)
