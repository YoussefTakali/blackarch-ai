import importlib
import json

import pytest
from typer.testing import CliRunner

from blackarch_ai.core.context import ContextStore
from blackarch_ai.reports.render import render_html, render_json, render_markdown
from blackarch_ai.reports.report import ExecSummary, build_report
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Evidence, ToolExecution, utcnow
from blackarch_ai.storage.store import Store

SCOPE = Scope.build(["10.0.0.0/24"])


@pytest.fixture
def populated(tmp_path):
    store = Store(tmp_path / "r.db")
    eng = store.create_engagement("lab", SCOPE, objective="review", authorized_by="me")
    cx = ContextStore(store, eng.id)
    cx.add_asset("host", "10.0.0.5", source="network")
    cx.add_asset("url", "http://10.0.0.5", source="web")
    cx.add_finding("nginx 1.18 on 10.0.0.5", description="banner", confidence="high",
                   severity="medium", agent="web")            # hypothesis
    cx.add_finding("weak guess", confidence="low", severity="low", agent="vulnintel")
    cx.add_finding("nmap on 10.0.0.5: success (exit 0)", description="631 open",
                   severity="info", confidence="high", verified=True, agent="orchestrator")
    # an execution with evidence
    with store.session() as s, s.begin():
        ex = ToolExecution(engagement_id=eng.id, requested_by="user", operation="nmap-tcp-connect",
                           tool="nmap", argv=["/usr/bin/nmap", "-sT", "10.0.0.5"],
                           target="10.0.0.5", permission="low", status="success", exit_code=0,
                           duration_s=0.4, finished_at=utcnow())
        s.add(ex)
    with store.session() as s, s.begin():
        s.add(Evidence(execution_id=ex.id, engagement_id=eng.id, kind="stdout",
                       path="/ev/exec-1/stdout.txt", size_bytes=120, sha256="abc123"))
    return store, eng


def test_build_report_separates_verified_and_hypotheses(populated):
    store, eng = populated
    r = build_report(store, eng)
    assert r.counts == {"assets": 2, "verified": 1, "hypotheses": 2,
                        "executions": 1, "executions_ok": 1}
    assert [f.verified for f in r.verified] == [True]
    assert all(not f.verified for f in r.hypotheses)
    # hypotheses sorted by severity: medium before low
    assert [f.severity for f in r.hypotheses] == ["medium", "low"]
    assert r.executions[0].evidence[0].sha256 == "abc123"


def test_markdown_render(populated):
    store, eng = populated
    md = render_markdown(build_report(store, eng))
    assert "# Security assessment — lab" in md
    assert "## Verified results" in md and "## Hypotheses to verify" in md
    assert "nginx 1.18 on 10.0.0.5" in md and "nmap-tcp-connect" in md
    assert "/ev/exec-1/stdout.txt" in md
    assert "unverified AI-generated reasoning" in md.lower() or "hypotheses are" in md.lower()


def test_json_render_is_valid_and_structured(populated):
    store, eng = populated
    data = json.loads(render_json(build_report(store, eng)))
    assert data["engagement"]["name"] == "lab"
    assert len(data["verified_results"]) == 1 and data["verified_results"][0]["verified"]
    assert len(data["hypotheses"]) == 2
    assert data["operations"][0]["evidence"][0]["sha256"] == "abc123"
    assert data["executive_summary"] is None
    assert "disclaimer" in data


def test_html_render_escapes_and_contains_sections(tmp_path):
    store = Store(tmp_path / "h.db")
    eng = store.create_engagement("x", SCOPE)
    ContextStore(store, eng.id).add_finding("<script>alert(1)</script>", agent="web")
    html = render_html(build_report(store, eng))
    assert "<!doctype html>" in html and "Hypotheses to verify" in html
    assert "<script>alert(1)</script>" not in html  # escaped
    assert "&lt;script&gt;" in html
    assert "prefers-color-scheme" in html  # dark mode


def test_summary_included_when_provided(populated):
    store, eng = populated
    s = ExecSummary(overview="Short recon only.", recommendations=["Patch nginx"],
                    model="test-model")
    r = build_report(store, eng, summary=s)
    md = render_markdown(r)
    assert "Executive summary" in md and "Patch nginx" in md and "AI-generated" in md
    data = json.loads(render_json(r))
    assert data["executive_summary"]["ai_generated"] is True


def test_cli_report_writes_files(tmp_path, monkeypatch, populated):
    store, eng = populated
    monkeypatch.setenv("BLACKARCH_AI_DATA_DIR", str(tmp_path / "data"))
    import blackarch_ai.cli.app as mod

    mod = importlib.reload(mod)
    monkeypatch.setattr(type(mod.ctx), "store", property(lambda self: store))
    runner = CliRunner()

    out_dir = tmp_path / "reports"
    r = runner.invoke(mod.app, ["report", "lab", "--format", "all", "--out", str(out_dir)])
    assert r.exit_code == 0, r.output
    files = sorted(p.suffix for p in out_dir.iterdir())
    assert files == [".html", ".json", ".md"]
    assert "1 verified" in r.output

    r = runner.invoke(mod.app, ["report", "lab", "-f", "json", "--stdout"])
    assert r.exit_code == 0 and json.loads(r.output)["engagement"]["name"] == "lab"
