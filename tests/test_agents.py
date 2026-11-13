import asyncio
import importlib
import json
import re

import pytest
from conftest import response
from test_discovery import fake_root, make_discovery  # noqa: F401  (fixture re-export)
from typer.testing import CliRunner

from blackarch_ai.agents.base import Agent, AgentContext
from blackarch_ai.agents.bus import MessageBus
from blackarch_ai.agents.consult import consult
from blackarch_ai.agents.directory import AgentDirectory, UnknownAgent, register_agent, _CUSTOM
from blackarch_ai.agents.schema import AgentReport
from blackarch_ai.config import AgentOverride, load_settings
from blackarch_ai.core.domains import DomainConfigError, load_domains
from blackarch_ai.llm.gateway import ModelGateway
from blackarch_ai.security.permissions import Permission, highest
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.registry import Registry


# ---------------------------------------------------------------- fixtures

def report_json(**kw):
    base = {"summary": "s", "analysis": "a", "steps": [], "hypotheses": [],
            "help_requests": [], "out_of_scope_notes": []}
    base.update(kw)
    return json.dumps(base)


class FakeLLM:
    """Answers per agent id (read from the system prompt) with canned JSON."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    async def __call__(self, **req):
        system = req["messages"][0]["content"]
        agent = re.search(r"agent \((\w+)\)", system).group(1)
        self.calls.append((agent, req))
        answer = self.answers[agent]
        if isinstance(answer, Exception):
            raise answer
        return response(answer)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "a.db")


@pytest.fixture
def registry(store, fake_root):  # noqa: F811
    reg = Registry(store)
    reg.save(make_discovery(fake_root).scan())
    return reg


def make_directory(registry, llm, settings=None):
    settings = settings or load_settings()
    gw = ModelGateway(settings, completion_fn=llm, availability=lambda m: True,
                      sleep=lambda _: asyncio.sleep(0))
    return AgentDirectory(load_domains(), settings, gw, registry)


SCOPE = Scope.build(["10.0.0.0/24"], exclude=["10.0.0.1"])


def ctx(peers=("network", "web", "vulnintel"), scope=SCOPE, engagement=None):
    from types import SimpleNamespace

    eng = engagement or (SimpleNamespace(name="lab", objective="test") if scope else None)
    return AgentContext(engagement=eng, scope=scope, peers=list(peers))


# ---------------------------------------------------------------- permissions & domains

def test_permission_ordering():
    assert Permission.HIGH_IMPACT.exceeds(Permission.INTRUSIVE)
    assert not Permission.LOW.exceeds(Permission.LOW)
    assert Permission.INTRUSIVE.needs_approval and not Permission.LOW.needs_approval
    assert highest(Permission.LOW, Permission.PASSIVE) is Permission.LOW


def test_domains_have_ceilings():
    d = load_domains()
    assert d.agent("forensics").max_permission is Permission.PASSIVE
    assert d.agent("exploitation").max_permission is Permission.HIGH_IMPACT


def test_bad_ceiling_rejected(tmp_path):
    p = tmp_path / "a.toml"
    p.write_text('[[agent]]\nid="a"\nname="A"\nmax_permission="total"\n')
    with pytest.raises(DomainConfigError, match="max_permission"):
        load_domains(p)


# ---------------------------------------------------------------- directory & overrides

def test_directory_overrides(registry):
    settings = load_settings()
    settings.agents = {"exploitation": AgentOverride(enabled=False),
                       "web": AgentOverride(max_permission="passive", extra_instructions="No auth."),
                       "recon": AgentOverride(max_permission="high_impact")}
    d = make_directory(registry, FakeLLM({}), settings)
    assert "exploitation" not in d.ids() and len(d.ids()) == 11
    with pytest.raises(UnknownAgent, match="disabled"):
        d.get("exploitation")
    with pytest.raises(UnknownAgent, match="no agent"):
        d.get("nope")
    assert d.get("web").max_permission is Permission.PASSIVE        # lowered
    assert d.get("recon").max_permission is Permission.LOW          # never raised
    assert "No auth." in d.get("web").system_prompt(ctx())


def test_unknown_agent_in_config_rejected(registry):
    settings = load_settings()
    settings.agents = {"webb": AgentOverride()}
    with pytest.raises(UnknownAgent, match="webb"):
        make_directory(registry, FakeLLM({}), settings)


def test_custom_agent_class(registry):
    @register_agent("reporting")
    class CustomReporter(Agent):
        pass

    try:
        assert isinstance(make_directory(registry, FakeLLM({})).get("reporting"), CustomReporter)
    finally:
        _CUSTOM.pop("reporting")


def test_system_prompt_contents(registry):
    agent = make_directory(registry, FakeLLM({})).get("network")
    prompt = agent.system_prompt(ctx(), "probe ports on the lab hosts")
    assert "Network agent (network)" in prompt
    assert "10.0.0.0/24" in prompt and "exclude: 10.0.0.1" in prompt
    assert "Your ceiling is intrusive" in prompt
    assert "web, vulnintel" in prompt and "(network)" in prompt  # peers exclude itself
    assert "portprobe" in prompt and "nmap" in prompt and "wordbag" in prompt  # own + shared
    assert "webpoke" not in prompt.split("Installed tools in your domain")[1].split("\n")[0]
    no_eng = agent.system_prompt(ctx(scope=None))
    assert "No engagement is selected" in no_eng


# ---------------------------------------------------------------- local checks

def check(agent, **report):
    return agent.check(AgentReport.model_validate_json(report_json(**report)), ctx())


def step(**kw):
    return {"title": "t", "purpose": "p", "permission": "low", **kw}


def test_check_tools_scope_and_permissions(registry):
    d = make_directory(registry, FakeLLM({}))
    net = d.get("network")
    r = check(net, steps=[
        step(tool="nmap", target="10.0.0.5"),                     # 1 ok
        step(tool="ncat", target="10.0.0.1"),                     # 2 excluded target
        step(tool="webpoke", target="10.0.0.6", permission="intrusive"),  # 3 other agent
        step(tool="ghosttool", target="8.8.8.8"),                 # 4 not installed, out of scope
        step(tool="nmap", target="10.0.0.7", permission="high_impact"),  # 5 above ceiling
        step(title="no target", permission="low"),                # 6
    ])
    s = r.steps
    assert (s[0].tool_status, s[0].tool_package, s[0].scope_status, s[0].blocked,
            s[0].requires_approval) == ("installed", "nmap", "in_scope", False, False)
    assert s[1].tool_package == "nmap" and s[1].blocked and "excluded" in s[1].scope_reason
    assert s[2].tool_status == "other_agent" and s[2].requires_approval and not s[2].blocked
    assert s[3].tool_status == "not_installed" and s[3].scope_status == "out_of_scope"
    assert s[4].exceeds_ceiling and s[4].blocked
    assert "no target given" in s[5].notes[0]
    # excluded target, out-of-scope target, missing tool, ceiling (other-agent is only a note)
    assert len(r.issues) == 4


def test_high_impact_tool_raises_level(registry):
    agent = make_directory(registry, FakeLLM({})).get("exploitation")
    r = check(agent, steps=[step(tool="shadyshell", target="10.0.0.5", permission="low")])
    assert r.steps[0].permission is Permission.HIGH_IMPACT
    assert r.steps[0].requires_approval and not r.steps[0].blocked  # ceiling is high_impact


def test_steps_blocked_without_engagement(registry):
    agent = make_directory(registry, FakeLLM({})).get("network")
    rep = AgentReport.model_validate_json(report_json(steps=[step(tool="nmap", target="10.0.0.5")]))
    r = agent.check(rep, ctx(scope=None))
    assert r.steps[0].scope_status == "no_engagement" and r.steps[0].blocked


def test_help_request_validation_and_unverified_hypotheses(registry):
    agent = make_directory(registry, FakeLLM({})).get("network")
    r = check(agent,
              hypotheses=[{"statement": "x is vulnerable", "confidence": "high", "basis": "banner"}],
              help_requests=[{"to_agent": "network", "question": "self"},
                             {"to_agent": "martian", "question": "?"},
                             {"to_agent": "web", "question": "1"},
                             {"to_agent": "web", "question": "2"},
                             {"to_agent": "vulnintel", "question": "3"},
                             {"to_agent": "web", "question": "4"}])
    assert [h.question for h in r.help_requests] == ["1", "2", "3"]
    assert sum("dropped" in i for i in r.issues) == 3
    assert r.hypotheses[0].verified is False


# ---------------------------------------------------------------- consultation over the bus

def test_consult_with_help_round_trip(store, registry):
    llm = FakeLLM({
        "network": report_json(summary="nginx 1.18 on 10.0.0.5:443",
                               help_requests=[{"to_agent": "vulnintel",
                                               "question": "Known issues for nginx 1.18?"}]),
        "vulnintel": report_json(summary="Check vendor advisories for 1.18",
                                 hypotheses=[{"statement": "may be outdated", "confidence": "medium",
                                              "basis": "version string"}]),
    })
    eng = store.create_engagement("lab", SCOPE)
    d = make_directory(registry, llm)
    bus = MessageBus(store, eng.id)
    c = asyncio.run(consult(d, bus, "network", "What runs on 10.0.0.5?", engagement=eng,
                            scope=SCOPE))
    assert c.ok and c.report.summary.startswith("nginx")
    assert len(c.replies) == 1 and c.replies[0].agent_id == "vulnintel" and c.replies[0].ok

    # vulnintel got the question plus the original task as context
    vi_msgs = [req for a, req in llm.calls if a == "vulnintel"][0]["messages"]
    vi_task = vi_msgs[-2]["content"]  # last one is the gateway's JSON-schema instruction
    assert "network agent asks" in vi_task and "What runs on 10.0.0.5?" in vi_task

    kinds = [(m.sender, m.recipient, m.kind) for m in bus.recent()]
    assert kinds == [("user", "network", "task"), ("network", "user", "result"),
                     ("network", "vulnintel", "help_request"),
                     ("vulnintel", "network", "help_reply")]
    tasks = bus.tasks()
    assert {t.agent_id: t.status for t in tasks} == {"network": "done", "vulnintel": "done"}
    child = bus.children(c.task_id)
    assert [t.agent_id for t in child] == ["vulnintel"] and child[0].requested_by == "network"

    # A later task for network sees the help reply in its inbox.
    asyncio.run(consult(d, bus, "network", "follow-up", engagement=eng, scope=SCOPE,
                        follow_help=False))
    last = [req for a, req in llm.calls if a == "network"][-1]["messages"]
    assert any("Check vendor advisories" in m["content"] for m in last)


def test_consult_failure_is_recorded(store, registry):
    import litellm

    err = litellm.exceptions.AuthenticationError("bad key", llm_provider="x", model="m")
    d = make_directory(registry, FakeLLM({"web": err}))
    bus = MessageBus(store, None)
    c = asyncio.run(consult(d, bus, "web", "anything", engagement=None, scope=None))
    assert not c.ok and "bad key" in c.error
    assert bus.tasks()[0].status == "failed"
    assert bus.recent()[-1].kind == "error"


# ---------------------------------------------------------------- CLI

def test_cli_agents_show_ask_tasks(monkeypatch, store, registry):
    import litellm

    llm = FakeLLM({"web": report_json(
        summary="Start with fingerprinting",
        steps=[step(tool="webpoke", target="10.0.0.9", permission="intrusive"),
               step(tool="webpoke", target="example.com")])})
    monkeypatch.setattr(litellm, "acompletion", llm)
    monkeypatch.setenv("NVIDIA_NIM_API_KEY", "nvapi-test-" + "x" * 30)
    import blackarch_ai.cli.app as mod

    mod = importlib.reload(mod)
    monkeypatch.setattr(mod.ctx, "ensure_registry", lambda: True)
    monkeypatch.setattr(type(mod.ctx), "registry", property(lambda self: registry))
    monkeypatch.setattr(type(mod.ctx), "store", property(lambda self: store))
    runner = CliRunner()

    r = runner.invoke(mod.app, ["engagement", "create", "lab", "-t", "10.0.0.0/24", "-y"])
    assert r.exit_code == 0, r.output

    r = runner.invoke(mod.app, ["agents", "show", "web", "--prompt", "-e", "lab"])
    assert r.exit_code == 0 and "Permission ceiling: intrusive" in r.output
    assert "Authorized scope" in r.output

    r = runner.invoke(mod.app, ["agents", "ask", "web", "assess", "the", "site", "-e", "lab"])
    assert r.exit_code == 0, r.output
    assert "Start with fingerprinting" in r.output and "Recommended steps" in r.output

    r = runner.invoke(mod.app, ["agents", "ask", "web", "again", "-e", "lab", "--json"])
    assert r.exit_code == 0, r.output
    steps = json.loads(r.output)["report"]["steps"]
    assert (steps[0]["requires_approval"], steps[0]["blocked"]) == (True, False)
    assert (steps[1]["scope_status"], steps[1]["blocked"]) == ("out_of_scope", True)

    r = runner.invoke(mod.app, ["agents", "tasks", "-e", "lab"])
    assert "web" in r.output and "done" in r.output
    r = runner.invoke(mod.app, ["agents", "tasks", "--show", "1"])
    assert r.exit_code == 0 and "user → web (task)" in r.output

    assert runner.invoke(mod.app, ["agents", "ask", "nope", "x"]).exit_code == 1


def test_passive_floor_and_cve_flag(registry):
    agent = make_directory(registry, FakeLLM({})).get("web")
    r = check(agent, summary="nginx 1.18 has CVE-2019-20372",
              hypotheses=[{"statement": "see cve-2021-23017", "confidence": "high", "basis": "x"}],
              steps=[step(tool="webpoke", target="10.0.0.20", permission="passive"),
                     step(title="read notes", permission="passive")])
    assert r.steps[0].permission is Permission.LOW and "at least low" in r.steps[0].notes[0]
    assert r.steps[1].permission is Permission.PASSIVE
    assert any("CVE-2019-20372, CVE-2021-23017" in i and "unverified" in i for i in r.issues)
    assert "send a help_request to vulnintel" in agent.system_prompt(ctx())
    vi = make_directory(registry, FakeLLM({})).get("vulnintel")
    assert "never above medium" in vi.system_prompt(ctx())
