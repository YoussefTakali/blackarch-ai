import asyncio
import importlib
import sys

import pytest
from typer.testing import CliRunner

from blackarch_ai.execution.engine import ExecutionEngine, ExecutionError, NotApproved
from blackarch_ai.execution.operations import (
    Operation,
    OperationCatalogue,
    OperationError,
    ValidationError,
    load_operations,
)
from blackarch_ai.security.permissions import Permission
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Tool
from blackarch_ai.storage.store import Store
from blackarch_ai.tools.registry import Registry


# ---------------------------------------------------------------- operation rendering

def op(**kw):
    base = {"id": "x", "tool": "nmap", "permission": "low"}
    base.update(kw)
    return Operation.model_validate(base)


def test_shipped_catalogue_loads():
    cat = load_operations()
    assert "nmap-service-scan" in cat.ids()
    assert cat.get("nmap-ping-sweep").permission is Permission.LOW
    assert cat.get("nmap-service-scan").permission is Permission.INTRUSIVE


def test_render_builds_argv():
    o = op(args=["-sV"], target={"kind": "network"},
           params=[{"name": "ports", "flag": "-p", "type": "string",
                    "pattern": r"^[0-9,\-]+$", "default": "80"},
                   {"name": "fast", "flag": "-F", "type": "bool"}])
    assert o.render_argv("/usr/bin/nmap", {"ports": "22,443", "fast": True}, "10.0.0.0/24") == \
        ["/usr/bin/nmap", "-sV", "-p", "22,443", "-F", "10.0.0.0/24"]
    # defaults applied, bool off omitted
    assert o.render_argv("/usr/bin/nmap", {}, "10.0.0.5") == \
        ["/usr/bin/nmap", "-sV", "-p", "80", "10.0.0.5"]


def test_host_op_prefixes_flatpak_spawn():
    o = op(host=True, args=["-l"], target={"kind": "host"})
    assert o.render_argv("tcpdump", {}, "10.0.0.5") == \
        ["flatpak-spawn", "--host", "tcpdump", "-l", "10.0.0.5"]
    # non-host op has no prefix
    assert op(args=["-l"]).render_argv("tcpdump", {}, None) == ["tcpdump", "-l"]


def test_template_wraps_target_and_param():
    o = op(args=["-M", "arp:remote"],
           params=[{"name": "gateway", "type": "string",
                    "pattern": r"^\d{1,3}(?:\.\d{1,3}){3}$", "template": "/{}//",
                    "required": True}],
           target={"kind": "host", "template": "/{}//"})
    # both the param and the target are validated as bare IPs, then slash-wrapped
    assert o.render_argv("ettercap", {"gateway": "172.26.0.2"}, "172.26.0.18") == \
        ["ettercap", "-M", "arp:remote", "/172.26.0.2//", "/172.26.0.18//"]
    # injection in a templated value is still rejected before wrapping
    with pytest.raises(ValidationError):
        o.render_argv("ettercap", {"gateway": "1.2.3.4; rm"}, "172.26.0.18")


def test_template_must_contain_placeholder():
    from pydantic import ValidationError as PydErr
    with pytest.raises(PydErr, match="must contain"):
        op(target={"kind": "host", "template": "/no-placeholder/"})
    with pytest.raises(PydErr, match="must contain"):
        op(params=[{"name": "g", "template": "nope"}])


def test_shipped_sniff_ops():
    cat = load_operations()
    passive = cat.get("wifi-sniff-passive")
    assert passive.host is True and passive.permission is Permission.LOW
    mitm = cat.get("mitm-sniff")
    assert mitm.host is True and mitm.permission is Permission.HIGH_IMPACT
    argv = mitm.render_argv("ettercap", {"iface": "wlan0", "gateway": "10.0.0.1"}, "10.0.0.5")
    assert argv[:2] == ["flatpak-spawn", "--host"]
    # ettercap 0.8.x target is MAC/IPv4/IPv6/PORT — three slashes (verified empirically)
    assert "/10.0.0.1//" in argv and "/10.0.0.5//" in argv
    # segment-wide variant: gateway endpoint + "///" (every host), no target
    all_op = cat.get("mitm-sniff-all")
    assert all_op.host is True and all_op.permission is Permission.HIGH_IMPACT
    all_argv = all_op.render_argv("ettercap", {"iface": "wlan0", "gateway": "10.0.0.1"}, None)
    assert all_argv[-2:] == ["/10.0.0.1//", "///"]


@pytest.mark.parametrize("params,target,msg", [
    ({"ports": "80; rm -rf /"}, "10.0.0.5", "format"),
    ({"ports": "-oG/x"}, "10.0.0.5", "start with"),
    ({}, "--script=x", "illegal target"),
    ({}, "10.0.0.5\nx", "illegal target"),
    ({"nope": "1"}, "10.0.0.5", "unknown parameter"),
])
def test_render_rejects_injection(params, target, msg):
    o = op(target={"kind": "any"},
           params=[{"name": "ports", "flag": "-p", "pattern": r"^[0-9,\-]+$"}])
    with pytest.raises(ValidationError, match=msg):
        o.render_argv("/usr/bin/nmap", params, target)


def test_int_and_enum_validation():
    o = op(params=[{"name": "n", "flag": "-n", "type": "int", "min": 1, "max": 10},
                   {"name": "mode", "flag": "-m", "type": "enum", "choices": ["a", "b"]}])
    with pytest.raises(ValidationError, match=">= 1"):
        o.render_argv("x", {"n": 0}, None)
    with pytest.raises(ValidationError, match="one of a, b"):
        o.render_argv("x", {"mode": "c"}, None)
    assert o.render_argv("x", {"n": 5, "mode": "b"}, None) == ["x", "-n", "5", "-m", "b"]


def test_required_target_and_param():
    o = op(target={"kind": "host", "required": True})
    with pytest.raises(ValidationError, match="needs a --target"):
        o.render_argv("x", {}, None)
    o2 = op(params=[{"name": "u", "flag": "-u", "required": True}])
    with pytest.raises(ValidationError, match="required parameter"):
        o2.render_argv("x", {}, None)


def test_bad_operation_definitions():
    # model-validator errors surface as pydantic ValidationError
    from pydantic import ValidationError as PydErr

    with pytest.raises(PydErr, match="bad operation id"):
        op(id="Bad Id")
    with pytest.raises(PydErr, match="duplicate parameter"):
        Operation.model_validate({"id": "x", "tool": "t", "permission": "low",
                                  "params": [{"name": "a"}, {"name": "a"}]})
    with pytest.raises(PydErr, match="illegal literal arg"):
        op(args=["ok", "bad\x00arg"])


def test_duplicate_operation_id():
    with pytest.raises(OperationError, match="duplicate"):
        OperationCatalogue([op(id="dup"), op(id="dup")])


# ---------------------------------------------------------------- engine

FAKE = "fake-scan"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    """A registry with a fake tool pointing at a python 'scanner', and an engine."""
    store = Store(tmp_path / "e.db")
    reg = Registry(store)
    # Insert a Tool row directly so no real package is needed.
    script = tmp_path / "faketool"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        "args = sys.argv[1:]\n"
        "if '--sleep' in args: time.sleep(float(args[args.index('--sleep')+1]))\n"
        "if '--fail' in args: sys.stderr.write('boom\\n'); sys.exit(3)\n"
        "if '--big' in args:\n"
        "    sys.stdout.write('A'*20); sys.exit(0)\n"
        "print('scanned', ' '.join(args))\n"
    )
    script.chmod(0o755)
    with store.session() as s, s.begin():
        s.add(Tool(name=FAKE, version="1.0", description="fake", source="arch",
                   categories=["scanner"], agents=["network"], executables=[str(script)],
                   man_pages=[], permission="unclassified"))

    cat = OperationCatalogue([
        op(id="scan", tool=FAKE, command="faketool", permission="low",
           target={"kind": "network", "required": True},
           params=[{"name": "ports", "flag": "-p", "default": "80"}]),
        op(id="loud", tool=FAKE, command="faketool", permission="intrusive",
           target={"kind": "host"}),
        op(id="slow", tool=FAKE, command="faketool", permission="low",
           args=["--sleep", "10"], target={"kind": "host"}, timeout=0.5),
        op(id="broken", tool=FAKE, command="faketool", permission="low",
           args=["--fail"], target={"kind": "host"}),
        op(id="flood", tool=FAKE, command="faketool", permission="low",
           args=["--big"], target={"kind": "host"}),
    ])
    engine = ExecutionEngine(load_settings_for(tmp_path), store, reg, cat,
                             evidence_root=tmp_path / "ev")
    return store, reg, cat, engine


def load_settings_for(tmp_path):
    from blackarch_ai.config import load_settings

    return load_settings()


SCOPE = Scope.build(["10.0.0.0/24"], exclude=["10.0.0.1"])


def run(coro):
    return asyncio.run(coro)


def test_plan_scope_and_permission(setup):
    _, _, _, engine = setup
    plan = engine.plan("scan", {"ports": "22"}, "10.0.0.5", engagement_id=1, scope=SCOPE)
    assert plan.argv[-3:] == ["-p", "22", "10.0.0.5"] and plan.scope_status == "in_scope"
    assert not plan.blocked and not plan.needs_approval

    blocked = engine.plan("scan", {}, "10.0.0.1", engagement_id=1, scope=SCOPE)
    assert blocked.blocked and blocked.scope_status == "out_of_scope"

    noeng = engine.plan("scan", {}, "10.0.0.5", engagement_id=None, scope=None)
    assert noeng.blocked and noeng.scope_status == "no_engagement"

    loud = engine.plan("loud", {}, "10.0.0.5", engagement_id=1, scope=SCOPE)
    assert loud.needs_approval and loud.permission is Permission.INTRUSIVE


def test_run_success_stores_evidence_and_audit(setup):
    store, _, _, engine = setup
    plan = engine.plan("scan", {"ports": "22"}, "10.0.0.9", engagement_id=None, scope=SCOPE)
    r = run(engine.run(plan))
    assert r.ok and r.exit_code == 0 and "scanned" in r.stdout
    assert len(r.evidence) == 2
    ex = store.get_execution(r.execution_id)
    assert ex.status == "success" and ex.stdout_bytes > 0
    assert {e.kind for e in ex.evidence} == {"stdout", "stderr"}
    assert all(e.sha256 for e in ex.evidence)
    actions = [e.action for e in store.audit_events()]
    assert "exec.start" in actions and "exec.success" in actions


def test_run_refuses_without_approval(setup):
    _, _, _, engine = setup
    plan = engine.plan("loud", {}, "10.0.0.5", engagement_id=None, scope=SCOPE)
    with pytest.raises(NotApproved):
        run(engine.run(plan))
    appr = engine.record_approval(plan, "approved")
    r = run(engine.run(plan, approval=appr))
    assert r.ok


def test_run_blocked_plan_raises(setup):
    _, _, _, engine = setup
    plan = engine.plan("scan", {}, "10.0.0.1", engagement_id=1, scope=SCOPE)
    with pytest.raises(ExecutionError, match="out of scope"):
        run(engine.run(plan))


def test_failed_exit_code(setup):
    store, _, _, engine = setup
    plan = engine.plan("broken", {}, "10.0.0.5", engagement_id=None, scope=SCOPE)
    r = run(engine.run(plan))
    assert r.status == "failed" and r.exit_code == 3 and "boom" in r.stderr


def test_timeout_is_killed(setup):
    store, _, _, engine = setup
    plan = engine.plan("slow", {}, "10.0.0.5", engagement_id=None, scope=SCOPE)
    r = run(engine.run(plan))
    assert r.status == "timeout" and r.exit_code is None
    assert store.get_execution(r.execution_id).status == "timeout"


def test_output_cap(setup, monkeypatch):
    import blackarch_ai.execution.engine as eng

    monkeypatch.setattr(eng, "MAX_OUTPUT_BYTES", 5)
    _, _, _, engine = setup
    plan = engine.plan("flood", {}, "10.0.0.5", engagement_id=None, scope=SCOPE)
    r = run(engine.run(plan))
    assert r.truncated and len(r.stdout) == 5


def test_unknown_tool_not_installed(tmp_path):
    store = Store(tmp_path / "u.db")
    reg = Registry(store)  # empty
    cat = OperationCatalogue([op(id="scan", tool="ghost", permission="low",
                                 target={"kind": "host"})])
    engine = ExecutionEngine(load_settings_for(tmp_path), store, reg, cat,
                             evidence_root=tmp_path / "ev")
    with pytest.raises(ExecutionError, match="not installed"):
        engine.plan("scan", {}, "10.0.0.5", engagement_id=None, scope=SCOPE)


def test_clean_env_drops_secrets(monkeypatch):
    import blackarch_ai.execution.engine as eng

    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret")
    monkeypatch.setenv("MY_TOKEN", "t")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = eng._clean_env()
    assert "ANTHROPIC_API_KEY" not in env and "MY_TOKEN" not in env and env["PATH"] == "/usr/bin"


# ---------------------------------------------------------------- CLI

def test_cli_run_and_history(tmp_path, monkeypatch, setup):
    store, reg, cat, _engine = setup
    import blackarch_ai.cli.app as mod

    mod = importlib.reload(mod)
    monkeypatch.setattr(mod.ctx, "ensure_registry", lambda: True)
    monkeypatch.setattr(type(mod.ctx), "registry", property(lambda self: reg))
    monkeypatch.setattr(type(mod.ctx), "store", property(lambda self: store))
    monkeypatch.setattr(type(mod.ctx), "catalogue", property(lambda self: cat))
    runner = CliRunner()

    store.create_engagement("lab", SCOPE)
    r = runner.invoke(mod.app, ["ops", "list"])
    assert r.exit_code == 0 and "scan" in r.output and "loud" in r.output

    # low op runs without approval
    r = runner.invoke(mod.app, ["run", "scan", "-t", "10.0.0.9", "-p", "ports=443", "-e", "lab"])
    assert r.exit_code == 0, r.output
    assert "success" in r.output and "scanned" in r.output

    # out of scope is blocked
    r = runner.invoke(mod.app, ["run", "scan", "-t", "8.8.8.8", "-e", "lab"])
    assert r.exit_code == 1 and "blocked" in r.output

    # intrusive op: declined at the prompt
    r = runner.invoke(mod.app, ["run", "loud", "-t", "10.0.0.5", "-e", "lab"], input="n\n")
    assert r.exit_code == 1 and "Rejected" in r.output
    # approved with --yes
    r = runner.invoke(mod.app, ["run", "loud", "-t", "10.0.0.5", "-e", "lab", "-y"])
    assert r.exit_code == 0 and "success" in r.output

    r = runner.invoke(mod.app, ["run", "scan", "-t", "10.0.0.9", "--dry-run", "-e", "lab"])
    assert r.exit_code == 0 and "dry run" in r.output

    r = runner.invoke(mod.app, ["exec", "list", "-e", "lab"])
    assert "scan" in r.output and "loud" in r.output
    r = runner.invoke(mod.app, ["exec", "show", "1"])
    assert r.exit_code == 0 and "stdout:" in r.output and "faketool" in r.output
