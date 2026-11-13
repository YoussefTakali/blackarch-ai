"""Provider-independent model gateway.

Everything that talks to a cloud model goes through `ModelGateway`. It:

* resolves a role ("orchestrator", "agent", or an agent id) to a model chain,
* skips models whose provider has no API key,
* retries transient errors with exponential backoff, then falls back to the
  next model in the chain,
* redacts secrets from every outbound message,
* streams text and reasoning deltas,
* validates structured (JSON) responses against a Pydantic model,
* reports token usage and estimated cost for every attempt to a recorder.

Agents and the CLI never import a provider SDK directly.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from blackarch_ai.config import ModelProfile, Settings
from blackarch_ai.llm.pricing import estimate_cost
from blackarch_ai.llm.providers import model_available, provider_of
from blackarch_ai.security.redaction import Redactor

T = TypeVar("T", bound=BaseModel)

CompletionFn = Callable[..., Awaitable[Any]]


# ---------------------------------------------------------------- data types


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    estimated: bool = False

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class CallRecord:
    """One attempt against one model. Sent to the recorder (DB/audit)."""

    role: str
    model: str
    provider: str
    success: bool
    usage: Usage
    cost_usd: float | None
    latency_ms: int
    error: str | None = None
    redactions: dict[str, int] = field(default_factory=dict)
    streamed: bool = False


@dataclass
class LLMResult:
    content: str
    reasoning: str
    model: str
    provider: str
    usage: Usage
    cost_usd: float | None
    latency_ms: int
    attempts: list[CallRecord]
    redactions: dict[str, int]
    parsed: Any = None

    @property
    def fell_back(self) -> bool:
        return len({a.model for a in self.attempts}) > 1


@dataclass
class StreamEvent:
    type: Literal["reasoning", "text", "attempt_failed", "done"]
    text: str = ""
    model: str = ""
    error: str = ""
    result: LLMResult | None = None


class Recorder(Protocol):
    def __call__(self, record: CallRecord) -> None: ...


class GatewayError(RuntimeError):
    """Every model in the chain failed (or none was configured)."""

    def __init__(self, message: str, attempts: list[CallRecord]):
        super().__init__(message)
        self.attempts = attempts


class StreamInterrupted(GatewayError):
    """The model failed after it had already streamed text; no fallback."""

    def __init__(self, message: str, attempts: list[CallRecord], partial: str):
        super().__init__(message, attempts)
        self.partial = partial


class StructuredOutputError(GatewayError):
    pass


# ---------------------------------------------------------------- errors


def _litellm_exc(*names: str) -> tuple[type[BaseException], ...]:
    try:
        import litellm.exceptions as ex
    except Exception:  # pragma: no cover - litellm is a hard dependency
        return ()
    return tuple(getattr(ex, n) for n in names if hasattr(ex, n))


TRANSIENT = _litellm_exc(
    "RateLimitError", "Timeout", "APIConnectionError", "ServiceUnavailableError",
    "InternalServerError",
) + (asyncio.TimeoutError, TimeoutError, ConnectionError)


def is_transient(exc: BaseException) -> bool:
    return isinstance(exc, TRANSIENT)


def _short(exc: BaseException) -> str:
    msg = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
    return f"{type(exc).__name__}: {msg[:300]}" if msg else type(exc).__name__


# ---------------------------------------------------------------- helpers


def _usage_from(obj: Any) -> Usage | None:
    u = getattr(obj, "usage", None)
    if u is None and isinstance(obj, dict):
        u = obj.get("usage")
    if not u:
        return None

    def g(o: Any, k: str) -> Any:
        return o.get(k) if isinstance(o, dict) else getattr(o, k, None)

    details = g(u, "completion_tokens_details")
    reasoning = (g(details, "reasoning_tokens") if details else None) or 0
    return Usage(
        prompt_tokens=int(g(u, "prompt_tokens") or 0),
        completion_tokens=int(g(u, "completion_tokens") or 0),
        reasoning_tokens=int(reasoning),
    )


def _estimate_usage(model: str, messages: list[dict], completion: str) -> Usage:
    try:
        import litellm

        p = litellm.token_counter(model=model, messages=messages)
        c = litellm.token_counter(model=model, text=completion)
    except Exception:
        p = sum(len(str(m.get("content", ""))) for m in messages) // 4
        c = len(completion) // 4
    return Usage(prompt_tokens=int(p), completion_tokens=int(c), estimated=True)


def _delta_fields(chunk: Any) -> tuple[str, str]:
    choices = getattr(chunk, "choices", None) or []
    if not choices:
        return "", ""
    delta = getattr(choices[0], "delta", None)
    if delta is None:
        return "", ""
    return (getattr(delta, "content", None) or "", getattr(delta, "reasoning_content", None) or "")


_JSON_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _clean_key(k: Any) -> Any:
    """Strip wrapper chars small models add to JSON keys (_summary_, /tool/, *x*)."""
    if not isinstance(k, str):
        return k
    return k.strip().strip("_/*`: \t").strip()


def normalize_keys(obj: Any) -> Any:
    """Recursively normalise dict keys (e.g. '_summary_ ' -> 'summary').

    Some models (notably small NIM models) wrap field names in underscores or
    trailing spaces. Schema field names here never legitimately start or end
    with an underscore, so this is safe and only touches mangled keys.
    """
    if isinstance(obj, dict):
        return {_clean_key(k): normalize_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_keys(v) for v in obj]
    return obj


def extract_json(text: str) -> Any:
    """Parse the first JSON object/array in `text` (tolerates code fences and prose)."""
    m = _JSON_FENCE.search(text)
    candidate = m.group(1) if m else text
    candidate = candidate.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for i, ch in enumerate(candidate):
        if ch in "{[":
            try:
                return decoder.raw_decode(candidate[i:])[0]
            except json.JSONDecodeError:
                continue
    raise ValueError("no JSON object found in model response")


# ---------------------------------------------------------------- gateway


class ModelGateway:
    def __init__(
        self,
        settings: Settings,
        *,
        recorder: Recorder | None = None,
        completion_fn: CompletionFn | None = None,
        redactor: Redactor | None = None,
        availability: Callable[[str], bool] = model_available,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.settings = settings
        self._recorder = recorder
        self._completion_fn = completion_fn
        self._redactor = redactor or (
            Redactor(settings.redaction.extra_patterns) if settings.redaction.enabled else None
        )
        self._available = availability
        self._sleep = sleep

    # -- model resolution

    def profile(self, role: str) -> ModelProfile:
        return self.settings.llm.profile_for(role)

    def candidates(self, role: str) -> list[str]:
        return [m for m in self.profile(role).chain() if self._available(m)]

    async def _call(self, **kwargs: Any) -> Any:
        fn = self._completion_fn
        if fn is None:
            import litellm

            fn = litellm.acompletion
        return await fn(**kwargs)

    def _request(self, model: str, prof: ModelProfile, messages: list[dict], **extra: Any) -> dict:
        req: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "timeout": prof.timeout,
            "drop_params": True,  # silently drop params a provider doesn't support
        }
        if prof.temperature is not None:
            req["temperature"] = prof.temperature
        if prof.top_p is not None:
            req["top_p"] = prof.top_p
        if prof.max_tokens is not None:
            req["max_tokens"] = prof.max_tokens
        if prof.reasoning_effort is not None:
            req["reasoning_effort"] = prof.reasoning_effort
        if prof.frequency_penalty is not None:
            req["frequency_penalty"] = prof.frequency_penalty
        if prof.presence_penalty is not None:
            req["presence_penalty"] = prof.presence_penalty
        if prof.extra_body is not None:
            req["extra_body"] = prof.extra_body
        req.update({k: v for k, v in extra.items() if v is not None})
        return req

    def _with_prefix(self, messages: list[dict], prof: ModelProfile) -> list[dict]:
        """Prepend the profile's prompt_prefix as a system message, if set."""
        if not prof.prompt_prefix:
            return messages
        return [{"role": "system", "content": prof.prompt_prefix}, *messages]

    def _prepare(self, messages: list[dict]) -> tuple[list[dict], dict[str, int]]:
        if self._redactor is None:
            return [dict(m) for m in messages], {}
        out, counts = self._redactor.redact_messages(messages)
        return out, dict(counts)

    def _record(self, rec: CallRecord) -> None:
        if self._recorder is not None:
            try:
                self._recorder(rec)
            except Exception:
                # Recording failures must never break a conversation.
                pass

    def _no_models(self, role: str) -> GatewayError:
        chain = ", ".join(self.profile(role).chain())
        return GatewayError(
            f"no usable model for role {role!r}: none of [{chain}] has an API key configured. "
            "Run `blackarch-ai setup`.",
            [],
        )

    def _cost(self, model: str, usage: Usage) -> float | None:
        return estimate_cost(
            model, usage.prompt_tokens, usage.completion_tokens, self.settings.llm.pricing
        )

    # -- non-streaming

    async def complete(
        self,
        messages: list[dict],
        *,
        role: str = "orchestrator",
        response_model: type[T] | None = None,
        **extra: Any,
    ) -> LLMResult:
        """Single response. With `response_model`, the result's `.parsed` is validated."""
        if response_model is not None:
            return await self._complete_structured(messages, role, response_model, **extra)
        return await self._complete_raw(messages, role, **extra)

    async def _complete_raw(self, messages: list[dict], role: str,
                            models: list[str] | None = None, **extra: Any) -> LLMResult:
        models = models if models is not None else self.candidates(role)
        if not models:
            raise self._no_models(role)
        prof = self.profile(role)
        outbound, redactions = self._prepare(self._with_prefix(messages, prof))
        attempts: list[CallRecord] = []
        retries = self.settings.llm.max_retries

        for model in models:
            provider = provider_of(model)
            for attempt in range(retries + 1):
                started = time.monotonic()
                try:
                    # Enforce the timeout ourselves: LiteLLM's own `timeout` does
                    # not reliably abort a hung NIM connection (seen running 901s
                    # against a 300s setting), so wrap the call in wait_for.
                    resp = await asyncio.wait_for(
                        self._call(**self._request(model, prof, outbound, **extra)),
                        timeout=prof.timeout,
                    )
                except Exception as exc:
                    rec = CallRecord(role, model, provider, False, Usage(), None,
                                     int((time.monotonic() - started) * 1000), _short(exc), redactions)
                    attempts.append(rec)
                    self._record(rec)
                    if is_transient(exc) and attempt < retries:
                        await self._sleep(self.settings.llm.retry_backoff * (2**attempt))
                        continue
                    break  # permanent error or retries exhausted → next model
                latency = int((time.monotonic() - started) * 1000)
                message = resp.choices[0].message
                content = getattr(message, "content", None) or ""
                reasoning = getattr(message, "reasoning_content", None) or ""
                usage = _usage_from(resp) or _estimate_usage(model, outbound, content)
                cost = self._cost(model, usage)
                rec = CallRecord(role, model, provider, True, usage, cost, latency, None, redactions)
                attempts.append(rec)
                self._record(rec)
                return LLMResult(content, reasoning, model, provider, usage, cost, latency,
                                 attempts, redactions)
        raise GatewayError(
            "all models failed: " + "; ".join(f"{a.model}: {a.error}" for a in attempts),
            attempts,
        )

    async def _complete_structured(
        self, messages: list[dict], role: str, response_model: type[T], **extra: Any
    ) -> LLMResult:
        schema = json.dumps(response_model.model_json_schema(), indent=None)
        instruction = {
            "role": "system",
            "content": (
                "Respond with a single JSON object and nothing else. It must validate "
                f"against this JSON Schema:\n{schema}"
            ),
        }
        models = self.candidates(role)
        if not models:
            raise self._no_models(role)
        all_attempts: list[CallRecord] = []
        last_error = ""
        # Try each model in the chain; a model that can't produce valid JSON
        # (even after a repair round) falls back to the next, stronger one.
        for model in models:
            convo = [*messages, instruction]
            for _ in range(2):  # one repair round per model
                try:
                    result = await self._complete_raw(
                        convo, role, models=[model],
                        response_format={"type": "json_object"}, **extra,
                    )
                except GatewayError as exc:
                    last_error = str(exc)[:1000]
                    all_attempts.extend(exc.attempts)
                    break  # HTTP-level failure on this model → next model
                all_attempts.extend(result.attempts)
                try:
                    data = normalize_keys(extract_json(result.content))
                    result.parsed = response_model.model_validate(data)
                    result.attempts = all_attempts
                    return result
                except (ValueError, ValidationError) as exc:
                    last_error = str(exc)[:1000]
                    convo = [
                        *convo,
                        {"role": "assistant", "content": result.content},
                        {
                            "role": "user",
                            "content": "That response was not valid. Error:\n"
                            f"{last_error}\nReturn only the corrected JSON object.",
                        },
                    ]
        raise StructuredOutputError(
            f"model did not return valid {response_model.__name__}: {last_error}", all_attempts
        )

    # -- streaming

    async def stream(
        self, messages: list[dict], *, role: str = "orchestrator", **extra: Any
    ) -> AsyncIterator[StreamEvent]:
        """Yield reasoning/text deltas, then a final `done` event carrying the result.

        Falls back to the next model only if the failing one has not emitted any
        answer text yet; otherwise raises `StreamInterrupted` with the partial text.
        """
        models = self.candidates(role)
        if not models:
            raise self._no_models(role)
        prof = self.profile(role)
        outbound, redactions = self._prepare(self._with_prefix(messages, prof))
        attempts: list[CallRecord] = []
        retries = self.settings.llm.max_retries

        for model in models:
            provider = provider_of(model)
            for attempt in range(retries + 1):
                started = time.monotonic()
                text_parts: list[str] = []
                reasoning_parts: list[str] = []
                usage: Usage | None = None
                try:
                    resp = await self._call(
                        **self._request(model, prof, outbound, stream=True,
                                        stream_options={"include_usage": True}, **extra)
                    )
                    async for chunk in resp:
                        text, reasoning = _delta_fields(chunk)
                        if reasoning:
                            reasoning_parts.append(reasoning)
                            yield StreamEvent("reasoning", reasoning, model=model)
                        if text:
                            text_parts.append(text)
                            yield StreamEvent("text", text, model=model)
                        usage = _usage_from(chunk) or usage
                except (asyncio.CancelledError, GeneratorExit):
                    content = "".join(text_parts)
                    u = usage or _estimate_usage(model, outbound, content)
                    rec = CallRecord(role, model, provider, False, u, self._cost(model, u),
                                     int((time.monotonic() - started) * 1000),
                                     "cancelled by user", redactions, streamed=True)
                    self._record(rec)
                    raise
                except Exception as exc:
                    content = "".join(text_parts)
                    u = usage or (_estimate_usage(model, outbound, content) if content else Usage())
                    rec = CallRecord(role, model, provider, False, u,
                                     self._cost(model, u) if content else None,
                                     int((time.monotonic() - started) * 1000), _short(exc),
                                     redactions, streamed=True)
                    attempts.append(rec)
                    self._record(rec)
                    if content:
                        raise StreamInterrupted(
                            f"{model} failed mid-response: {_short(exc)}", attempts, content
                        ) from exc
                    yield StreamEvent("attempt_failed", model=model, error=_short(exc))
                    if is_transient(exc) and attempt < retries:
                        await self._sleep(self.settings.llm.retry_backoff * (2**attempt))
                        continue
                    break

                content = "".join(text_parts)
                latency = int((time.monotonic() - started) * 1000)
                u = usage or _estimate_usage(model, outbound, content)
                cost = self._cost(model, u)
                rec = CallRecord(role, model, provider, True, u, cost, latency, None,
                                 redactions, streamed=True)
                attempts.append(rec)
                self._record(rec)
                result = LLMResult(content, "".join(reasoning_parts), model, provider, u, cost,
                                   latency, attempts, redactions)
                yield StreamEvent("done", model=model, result=result)
                return

        raise GatewayError(
            "all models failed: " + "; ".join(f"{a.model}: {a.error}" for a in attempts),
            attempts,
        )


def total_redactions(counts: dict[str, int] | Counter[str]) -> int:
    return sum(counts.values())
