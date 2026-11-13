import importlib
import os
import stat

import pytest
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def app():
    # Fresh module so the lazily-built Context picks up this test's dirs.
    import blackarch_ai.cli.app as mod

    return importlib.reload(mod).app


def test_engagement_create_list_check(app):
    r = runner.invoke(app, ["engagement", "create", "lab", "-t", "10.0.0.0/24",
                            "-x", "10.0.0.1", "-o", "home lab", "-y"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["engagement", "list"])
    assert "lab" in r.output and "10.0.0.0/24" in r.output
    r = runner.invoke(app, ["engagement", "check", "lab", "10.0.0.5"])
    assert r.exit_code == 0 and "in scope" in r.output
    r = runner.invoke(app, ["engagement", "check", "lab", "10.0.0.1", "8.8.8.8"])
    assert r.exit_code == 1 and "excluded" in r.output
    r = runner.invoke(app, ["engagement", "show", "lab"])
    assert r.exit_code == 0 and "engagement.create" in r.output


def test_engagement_requires_confirmation(app):
    r = runner.invoke(app, ["engagement", "create", "lab", "-t", "10.0.0.0/24", "-o", "x",
                            "--authorized-by", "me"], input="n\n")
    assert r.exit_code == 1
    assert "No engagements" in runner.invoke(app, ["engagement", "list"]).output


def test_broad_scope_rejected(app):
    r = runner.invoke(app, ["engagement", "create", "big", "-t", "0.0.0.0/0", "-y"])
    assert r.exit_code == 2 and "broader" in r.output


def test_report_requires_engagement(app):
    # report now exists; it fails cleanly for an unknown engagement, not with a stub.
    r = runner.invoke(app, ["report", "nope"])
    assert r.exit_code == 1 and "no engagement" in r.output.lower()


def test_agents_and_models_list(app):
    r = runner.invoke(app, ["agents", "list", "--no-pacman"])
    assert r.exit_code == 0 and "Web Application" in r.output and "webapp" in r.output
    r = runner.invoke(app, ["models", "list"])
    assert r.exit_code == 0 and "orchestrator" in r.output


def test_setup_creates_private_env_and_stores_key(app, isolated_dirs):
    r = runner.invoke(app, ["setup", "--keys"], input="nvapi-testkey-123456789\n\n\n\n")
    assert r.exit_code == 0, r.output
    env = isolated_dirs / "config" / ".env"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert "NVIDIA_NIM_API_KEY=nvapi-testkey-123456789" in env.read_text()
    assert (isolated_dirs / "config" / "config.toml").exists()
    os.environ.pop("NVIDIA_NIM_API_KEY", None)


def test_setup_without_keys_reports_failure(app):
    r = runner.invoke(app, ["setup"])
    assert r.exit_code == 1 and "No provider key" in r.output


def test_chat_without_keys_exits_cleanly(app):
    r = runner.invoke(app, ["--plain"], input="")
    assert r.exit_code == 1 and "No model is usable" in r.output
