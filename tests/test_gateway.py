import asyncio

import litellm
import pytest
from pydantic import BaseModel
from conftest import FakeStream, chunk, response

from blackarch_ai.config import Pricing
from blackarch_ai.llm.gateway import (
    GatewayError,
    ModelGateway,
    StreamInterrupted,
    StructuredOutputError,
    extract_json,
)

PRIMARY = "nvidia_nim/minimaxai/minimax-m3.1-flash"
FALLBACK = "anthropic/claude-sonnet-5-5"


def transient():
    return litellm.exceptions.RateLimitError("slow down", llm_provider="x", model="m")


def auth_error():
    return litellm.exceptions.AuthenticationError("bad key", llm_provider="x", model="m")


class Script:
    """Completion fn that plays back per-model outcomes and records requests."""

    def __init__(self, plan):
        self.plan = {k: list(v) for k, v in plan.items()}
        self.calls = []

    async def __call__(self, **req):
        self.calls.append(req)
        outcome = self.plan[req["model"]].pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


async def no_sleep(_):
    return None


def gw(settings, script, *, available=(PRIMARY, FALLBACK), records=None):
    return ModelGateway(
        settings,
        completion_fn=script,
        availability=lambda m: m in available,
        sleep=no_sleep,
        recorder=(records.append if records is not None else None),
    )


def run(coro):
    return asyncio.run(coro)


def test_success_records_usage_and_cost(settings):
    settings.llm.pricing[PRIMARY] = Pricing(input_per_mtok=1.0, output_per_mtok=2.0)
    records = []
    script = Script({PRIMARY: [response("hi", prompt=1000, completion=500)]})
    r = run(gw(settings, script, records=records).complete([{"role": "user", "content": "x"}]))
    assert r.content == "hi" and r.model == PRIMARY and not r.fell_back
    assert r.usage.prompt_tokens == 1000 and r.cost_usd == pytest.approx(0.002)
    assert len(records) == 1 and records[0].success
    assert script.calls[0]["drop_params"] is True
    assert script.calls[0]["timeout"] == settings.llm.profiles["orchestrator"].timeout


def test_unknown_price_is_none_not_zero(settings):
    script = Script({PRIMARY: [response("hi")]})
    r = run(gw(settings, script).complete([{"role": "user", "content": "x"}]))
    assert r.cost_usd is None


def test_transient_errors_retry_then_succeed(settings):
    script = Script({PRIMARY: [transient(), transient(), response("ok")]})
    r = run(gw(settings, script).complete([{"role": "user", "content": "x"}]))
    assert r.content == "ok" and len(r.attempts) == 3 and r.model == PRIMARY


def test_falls_back_after_retries_exhausted(settings):
    script = Script({PRIMARY: [transient()] * 3, FALLBACK: [response("from fallback")]})
    r = run(gw(settings, script).complete([{"role": "user", "content": "x"}]))
    assert r.model == FALLBACK and r.fell_back
    assert [c["model"] for c in script.calls] == [PRIMARY] * 3 + [FALLBACK]


def test_permanent_error_skips_retries(settings):
    script = Script({PRIMARY: [auth_error()], FALLBACK: [response("ok")]})
    r = run(gw(settings, script).complete([{"role": "user", "content": "x"}]))
    assert r.model == FALLBACK and len(script.calls) == 2


def test_all_fail(settings):
    script = Script({PRIMARY: [auth_error()], FALLBACK: [auth_error()]})
    with pytest.raises(GatewayError) as ei:
        run(gw(settings, script).complete([{"role": "user", "content": "x"}]))
    assert len(ei.value.attempts) == 2


def test_models_without_keys_are_skipped(settings):
    script = Script({FALLBACK: [response("ok")]})
    r = run(gw(settings, script, available=(FALLBACK,)).complete(
        [{"role": "user", "content": "x"}]))
    assert r.model == FALLBACK
    with pytest.raises(GatewayError, match="no usable model"):
        run(gw(settings, script, available=()).complete([{"role": "user", "content": "x"}]))


def test_outbound_messages_are_redacted(settings):
    script = Script({PRIMARY: [response("ok")]})
    msgs = [{"role": "user", "content": "use password=hunter22 please"}]
    r = run(gw(settings, script).complete(msgs))
    sent = script.calls[0]["messages"][0]["content"]
    assert "hunter22" not in sent and r.redactions == {"assignment": 1}
    assert msgs[0]["content"] == "use password=hunter22 please"  # caller's copy untouched


class Plan(BaseModel):
    steps: list[str]
    risk: str


def test_structured_output_with_repair(settings):
    script = Script({PRIMARY: [response("sure! {\"steps\": [\"a\"]}"),
                               response("```json\n{\"steps\": [\"a\"], \"risk\": \"low\"}\n```")]})
    r = run(gw(settings, script).complete([{"role": "user", "content": "plan"}],
                                          response_model=Plan))
    assert r.parsed == Plan(steps=["a"], risk="low")
    assert len(r.attempts) == 2
    assert script.calls[0]["response_format"] == {"type": "json_object"}
    assert "JSON Schema" in script.calls[0]["messages"][-1]["content"]


def test_structured_output_gives_up(settings):
    script = Script({PRIMARY: [response("nope"), response("still nope")]})
    with pytest.raises(StructuredOutputError):
        run(gw(settings, script).complete([{"role": "user", "content": "x"}],
                                          response_model=Plan))


def test_extract_json_variants():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('Here you go:\n{"a": [1, 2]} hope that helps') == {"a": [1, 2]}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_normalize_keys_fixes_mangled_fields():
    from blackarch_ai.llm.gateway import normalize_keys

    # Small NIM models emit keys like '_summary_ ' with underscores/spaces.
    mangled = {"_summary_ ": "x", " _analysis_": "y",
               "steps": [{"_tool_ ": "nmap", "requires_approval": True}]}
    assert normalize_keys(mangled) == {
        "summary": "x", "analysis": "y",
        "steps": [{"tool": "nmap", "requires_approval": True}],
    }
    # Internal underscores and clean keys are untouched.
    assert normalize_keys({"max_tokens": 1, "a": [1, 2]}) == {"max_tokens": 1, "a": [1, 2]}


async def collect(agen):
    return [ev async for ev in agen]


def usage(p, c):
    from types import SimpleNamespace

    return SimpleNamespace(prompt_tokens=p, completion_tokens=c, completion_tokens_details=None)


def test_stream_events_and_usage(settings):
    stream = FakeStream([chunk(reasoning="hmm"), chunk("Hel"), chunk("lo"),
                         chunk(usage=usage(7, 3))])
    script = Script({PRIMARY: [stream]})
    events = run(collect(gw(settings, script).stream([{"role": "user", "content": "x"}])))
    assert [e.type for e in events] == ["reasoning", "text", "text", "done"]
    result = events[-1].result
    assert result.content == "Hello" and result.reasoning == "hmm"
    assert (result.usage.prompt_tokens, result.usage.completion_tokens) == (7, 3)
    assert not result.usage.estimated
    assert script.calls[0]["stream"] is True


def test_stream_falls_back_before_any_text(settings):
    bad = FakeStream([chunk(reasoning="thinking")], fail_after=1, exc=auth_error())
    script = Script({PRIMARY: [bad], FALLBACK: [FakeStream([chunk("ok")])]})
    events = run(collect(gw(settings, script).stream([{"role": "user", "content": "x"}])))
    types = [e.type for e in events]
    assert "attempt_failed" in types and types[-1] == "done"
    assert events[-1].result.model == FALLBACK and events[-1].result.usage.estimated


def test_stream_interrupted_after_text_does_not_fall_back(settings):
    bad = FakeStream([chunk("partial ")], fail_after=1, exc=transient())
    script = Script({PRIMARY: [bad], FALLBACK: [FakeStream([chunk("never")])]})
    with pytest.raises(StreamInterrupted) as ei:
        run(collect(gw(settings, script).stream([{"role": "user", "content": "x"}])))
    assert ei.value.partial == "partial "
    assert [c["model"] for c in script.calls] == [PRIMARY]


def test_stream_cancellation_is_recorded(settings):
    class Slow:
        def __aiter__(self):
            return self._g()

        async def _g(self):
            yield chunk("a")
            await asyncio.sleep(10)
            yield chunk("b")

    records = []
    script = Script({PRIMARY: [Slow()]})

    async def main():
        task = asyncio.ensure_future(collect(gw(settings, script, records=records).stream(
            [{"role": "user", "content": "x"}])))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(main())
    assert records and records[-1].error == "cancelled by user"
