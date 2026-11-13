import asyncio

import pytest
from conftest import FakeStream, chunk

from blackarch_ai.core.conversation import Conversation
from blackarch_ai.core.domains import load_domains
from blackarch_ai.llm.gateway import CallRecord, GatewayError, ModelGateway, Usage
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.store import Store, StoreError

MODEL = "nvidia_nim/minimaxai/minimax-m3.1-flash"


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "t.db")


def test_engagement_lifecycle(store):
    eng = store.create_engagement("lab", Scope.build(["10.0.0.0/24"]), objective="test",
                                  authorized_by="me")
    assert store.get_engagement("lab").id == eng.id
    assert store.get_engagement(str(eng.id)).name == "lab"
    assert store.scope_of(eng).contains("10.0.0.3")
    with pytest.raises(StoreError, match="already exists"):
        store.create_engagement("lab", Scope.build(["10.0.0.0/24"]))
    with pytest.raises(StoreError):
        store.get_engagement("nope")
    actions = [e.action for e in store.audit_events(eng.id)]
    assert actions == ["engagement.create"]


def test_recorder_and_totals(store):
    cs = store.create_chat_session(None)
    rec = store.recorder(session_id=cs.id)
    rec(CallRecord("orchestrator", MODEL, "nvidia_nim", True, Usage(100, 20), None, 50))
    rec(CallRecord("orchestrator", "x/y", "x", True, Usage(10, 5), 0.01, 50))
    rec(CallRecord("orchestrator", MODEL, "nvidia_nim", False, Usage(), None, 5, "boom"))
    t = store.usage_totals(session_id=cs.id)
    assert (t.calls, t.failed, t.prompt_tokens, t.unpriced_calls) == (3, 1, 110, 1)
    assert t.cost_usd == pytest.approx(0.01)
    assert {e.action for e in store.audit_events()} >= {"llm.call", "llm.call_failed"}


def make_convo(store, plan, engagement=None):
    async def fn(**req):
        outcome = plan.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    from blackarch_ai.config import load_settings

    cs = store.create_chat_session(engagement.id if engagement else None)
    gw = ModelGateway(load_settings(), completion_fn=fn, availability=lambda m: m == MODEL,
                      recorder=store.recorder(session_id=cs.id))
    return Conversation(store, gw, load_domains(), session_id=cs.id, engagement=engagement)


async def drain(agen):
    return [e async for e in agen]


def test_conversation_persists_turns_and_includes_scope(store):
    eng = store.create_engagement("lab", Scope.build(["10.0.0.0/24"]))
    convo = make_convo(store, [FakeStream([chunk("Hello there")])], eng)
    events = asyncio.run(drain(convo.send("hi")))
    assert events[-1].type == "done"
    msgs = store.messages(convo.session_id)
    assert [(m.role, m.content) for m in msgs] == [("user", "hi"), ("assistant", "Hello there")]
    prompt = convo.system_prompt()
    assert "10.0.0.0/24" in prompt and "cannot run anything yourself" in prompt
    assert "Tool discovery IS active" in prompt
    assert store.get_chat_session(convo.session_id).title == "hi"


def test_failed_turn_keeps_user_message_and_merges_next(store):
    import litellm

    err = litellm.exceptions.AuthenticationError("bad", llm_provider="x", model="m")
    convo = make_convo(store, [err, FakeStream([chunk("ok")])])
    with pytest.raises(GatewayError):
        asyncio.run(drain(convo.send("first")))
    msgs = convo.build_messages("second")
    # system + one merged user turn (no two consecutive user messages)
    assert [m["role"] for m in msgs] == ["system", "user"]
    assert "first" in msgs[1]["content"] and "second" in msgs[1]["content"]


def test_interrupted_stream_saves_partial(store):
    import litellm

    bad = FakeStream([chunk("half an ans")], fail_after=1,
                     exc=litellm.exceptions.APIConnectionError("reset", llm_provider="x",
                                                               model="m"))
    convo = make_convo(store, [bad])
    with pytest.raises(GatewayError):
        asyncio.run(drain(convo.send("q")))
    last = store.messages(convo.session_id)[-1]
    assert last.role == "assistant" and last.interrupted and last.content == "half an ans"
    assert len(store.messages(convo.session_id)) == 2
