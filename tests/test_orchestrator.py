import asyncio
import json
import re

import pytest
from conftest import response
from test_agents import SCOPE, report_json  # reuse helpers
from test_execution import load_settings_for

from blackarch_ai.agents.bus import MessageBus
from blackarch_ai.agents.directory import AgentDirectory
from blackarch_ai.core.domains import load_domains
from blackarch_ai.execution.engine import ExecutionEngine, ExecutionError
from blackarch_ai.execution.operations import Operation, OperationCatalogue
from blackarch_ai.llm.gateway import ModelGateway
from blackarch_ai.orchestrator.orchestrator import Orchestrator
from blackarch_ai.orchestrator.plan import PlanError, PlanOutput, validate_plan
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Tool
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.registry import Registry

FAKE = "fake-scan"


def op(**kw):
    base = {"id": "x", "tool": FAKE, "command": "faketool", "permission": "low"}
    base.update(kw)
    return Operation.model_validate(base)


class ScriptLLM:
    """Routes by role: orchestrator → a plan; each agent id → its report."""

    def __init__(self, plan, reports):
        self.plan = plan
        self.reports = reports
        self.calls = []

    async def __call__(self, **req):
        system = req["messages"][0]["content"]
        if "planning an AUTHORIZED" in system:
            self.calls.append(("orchestrator", req))
            return response(self.plan)
        agent = re.search(r"agent \((\w+)\)", system).group(1)
        self.calls.append((agent, req))
        return response(self.reports[agent])


@pytest.fixture
def world(tmp_path):
    store = Store(tmp_path / "o.db")
    reg = Registry(store)
    script = tmp_path / "faketool"
    script.write_text("#!/usr/bin/env python3\nprint('ran', __import__('sys').argv[1:])\n")
    script.chmod(0o755)
    with store.session() as s, s.begin():
        s.add(Tool(name=FAKE, version="1.0", description="fake scanner", source="arch",
                   categories=["scanner"], agents=["network"], executables=[str(script)],
                   man_pages=[], permission="unclassified"))
    cat = OperationCatalogue([
        op(id="safe-scan", permission="low", target={"kind": "network"}),
        op(id="loud-scan", permission="intrusive", target={"kind": "host"}),
    ])
    settings = load_settings_for(tmp_path)
    return store, reg, cat, settings, tmp_path


def build(world, plan, reports, engagement=True):
    store, reg, cat, settings, _ = world
    llm = ScriptLLM(plan, reports)
    gw = ModelGateway(settings, completion_fn=llm, availability=lambda m: True,
                      sleep=lambda _: asyncio.sleep(0),
                      recorder=store.recorder())
    directory = AgentDirectory(load_domains(), settings, gw, reg)
    engine = ExecutionEngine(settings, store, reg, cat, evidence_root=_tmp(world) / "ev")
    eng = store.create_engagement("lab", SCOPE) if engagement else None
    bus = MessageBus(store, eng.id if eng else None)
    orch = Orchestrator(directory=directory, engine=engine, bus=bus, gateway=gw, registry=reg,
                        engagement=eng, scope=SCOPE if engagement else None)
    return orch, llm, store


def _tmp(world):
    return world[4]


def plan_json(*steps):
    return json.dumps({"summary": "do it", "steps": list(steps)})


def st(agent, objective="look", depends_on=None):
    return {"agent_id": agent, "objective": objective, "depends_on": depends_on or []}


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- plan validation

def test_validate_plan_drops_bad_steps_and_remaps_deps():
    p = PlanOutput(summary="x", steps=[
        {"agent_id": "network", "objective": "a", "depends_on": []},
        {"agent_id": "bogus", "objective": "b", "depends_on": [1]},
        {"agent_id": "web", "objective": "c", "depends_on": [1, 2]},  # dep 2 was dropped
    ])
    warnings = validate_plan(p, {"network", "web"})
    assert [s.agent_id for s in p.steps] == ["network", "web"]
    assert p.steps[1].depends_on == [1]  # remapped; dep on dropped step 2 removed
    assert any("bogus" in w for w in warnings)


def test_validate_plan_empty_raises():
    p = PlanOutput(summary="x", steps=[{"agent_id": "ghost", "objective": "a"}])
    with pytest.raises(PlanError):
        validate_plan(p, {"network"})


# ---------------------------------------------------------------- planning

def test_make_plan_persists_and_validates(world):
    orch, llm, store = build(world, plan_json(st("network"), st("web", depends_on=[1]),
                                              st("ghost")), {})
    row, out, warnings = run(orch.make_plan("inventory the lab"))
    assert [s.agent_id for s in out.steps] == ["network", "web"]
    assert any("ghost" in w for w in warnings)
    assert store.get_engagement("lab")  # engagement intact
    from blackarch_ai.storage.models import Plan

    with store.session() as s:
        assert s.get(Plan, row.id).objective == "inventory the lab"


# ---------------------------------------------------------------- running

def test_run_auto_runs_safe_and_queues_intrusive(world):
    reports = {
        "network": report_json(
            summary="two services",
            steps=[{"title": "scan", "purpose": "map", "tool": FAKE,
                    "target": "10.0.0.0/24", "permission": "low"},
                   {"title": "deep", "purpose": "enumerate", "tool": FAKE,
                    "target": "10.0.0.5", "permission": "intrusive"}],
            hypotheses=[{"statement": "host 10.0.0.5 is up", "confidence": "medium",
                         "basis": "ping"}]),
    }
    orch, llm, store = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("scan lab"))
    result = run(orch.run(row, out, mode="auto_safe"))

    statuses = {p.operation: p.status for p in result.proposed}
    assert statuses["safe-scan"] == "executed"     # passive/low auto-ran
    assert statuses["loud-scan"] == "pending"       # intrusive queued
    executed = result.by_status("executed")[0]
    assert executed.execution_id is not None

    # a finding from the hypothesis + a verified finding from the execution
    titles = [f.title for f in orch.context.findings()]
    assert any("10.0.0.5 is up" in t for t in titles)
    assert any("safe-scan on 10.0.0.0/24" in t for t in titles)
    assert any(f.verified for f in orch.context.findings())
    # the executed op actually spawned the fake tool
    ex = store.list_executions()[0]
    assert ex.status == "success" and ex.operation == "safe-scan"


def test_manual_mode_queues_everything(world):
    reports = {"network": report_json(steps=[
        {"title": "s", "purpose": "p", "tool": FAKE, "target": "10.0.0.0/24",
         "permission": "low"}])}
    orch, _, store = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("x"))
    result = run(orch.run(row, out, mode="manual"))
    assert result.proposed[0].status == "pending"
    assert store.list_executions() == []


def test_plan_only_runs_nothing(world):
    reports = {"network": report_json(steps=[
        {"title": "s", "purpose": "p", "tool": FAKE, "target": "10.0.0.0/24",
         "permission": "low"}])}
    orch, _, store = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("x"))
    result = run(orch.run(row, out, mode="plan_only"))
    assert result.proposed[0].status == "pending" and store.list_executions() == []


def test_out_of_scope_step_not_proposed_and_blocked_op(world):
    reports = {"network": report_json(steps=[
        # out of scope → agent marks it blocked → orchestrator skips proposing
        {"title": "x", "purpose": "p", "tool": FAKE, "target": "8.8.8.8", "permission": "low"},
        # unknown tool → needs_params advisory
        {"title": "y", "purpose": "p", "tool": "ghosttool", "target": "10.0.0.5",
         "permission": "low"}])}
    orch, _, _ = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("x"))
    result = run(orch.run(row, out))
    ops = {p.operation: p.status for p in result.proposed}
    assert "safe-scan" not in [p.operation for p in result.proposed if p.target == "8.8.8.8"]
    assert ops.get("ghosttool") == "needs_params"


def test_shared_context_flows_to_later_agents(world):
    reports = {
        "network": report_json(summary="found nginx on 10.0.0.5",
                               hypotheses=[{"statement": "nginx 1.18 on 10.0.0.5",
                                            "confidence": "high", "basis": "banner"}]),
        "web": report_json(summary="will test it"),
    }
    orch, llm, _ = build(world, plan_json(st("network"), st("web", depends_on=[1])), reports)
    row, out, _ = run(orch.make_plan("assess web"))
    run(orch.run(row, out))
    web_task = [req for a, req in llm.calls if a == "web"][-1]["messages"][-2]["content"]
    assert "nginx 1.18 on 10.0.0.5" in web_task  # the finding reached the web agent


# ---------------------------------------------------------------- approval queue

def test_approve_runs_queued_and_reject(world):
    reports = {"network": report_json(steps=[
        {"title": "deep", "purpose": "p", "tool": FAKE, "target": "10.0.0.5",
         "permission": "intrusive"},
        {"title": "deep2", "purpose": "p", "tool": FAKE, "target": "10.0.0.6",
         "permission": "intrusive"}])}
    orch, _, store = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("x"))
    run(orch.run(row, out))
    pending = orch.pending()
    assert len(pending) == 2 and all(p.permission == "intrusive" for p in pending)

    res = run(orch.approve(pending[0].id))
    assert res.ok
    assert orch.get_proposal(pending[0].id).status == "executed"
    # an approval record was written
    from blackarch_ai.storage.models import Approval

    with store.session() as s:
        from sqlalchemy import select
        assert s.scalars(select(Approval)).first().decision == "approved"

    orch.reject(pending[1].id)
    assert orch.get_proposal(pending[1].id).status == "rejected"
    assert orch.pending() == []

    with pytest.raises(ExecutionError, match="not pending"):
        run(orch.approve(pending[0].id))  # already executed


def test_approve_rechecks_scope(world, monkeypatch):
    reports = {"network": report_json(steps=[
        {"title": "deep", "purpose": "p", "tool": FAKE, "target": "10.0.0.5",
         "permission": "intrusive"}])}
    orch, _, _ = build(world, plan_json(st("network")), reports)
    row, out, _ = run(orch.make_plan("x"))
    run(orch.run(row, out))
    pid = orch.pending()[0].id
    # Tighten scope so the previously-queued target is now excluded.
    orch.scope = Scope.build(["10.0.0.0/24"], exclude=["10.0.0.5"])
    with pytest.raises(ExecutionError, match="out of scope"):
        run(orch.approve(pid))
    assert orch.get_proposal(pid).status == "blocked"
