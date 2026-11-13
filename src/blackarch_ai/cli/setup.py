"""`blackarch-ai setup`: config files, API keys, connectivity check."""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path

import typer

from blackarch_ai.cli.common import Context, console, fmt_cost
from blackarch_ai.cli.views import models_table, providers_table
from blackarch_ai.config import DEFAULT_CONFIG_TOML, config_dir, load_env
from blackarch_ai.llm.gateway import GatewayError, ModelGateway
from blackarch_ai.llm.providers import PROVIDERS, has_key

ENV_TEMPLATE = """\
# BlackArch AI secrets. Keep this file private (chmod 600). Never commit it.
""" + "".join(f"# {p.key_env[0]}=\n" for p in PROVIDERS.values())


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def set_env_var(path: Path, name: str, value: str) -> None:
    """Set NAME=value in a dotenv file, replacing an existing or commented line."""
    if "\n" in value or "\r" in value:
        raise ValueError("value must be a single line")
    lines = path.read_text().splitlines() if path.exists() else ENV_TEMPLATE.splitlines()
    pat = re.compile(rf"^\s*#?\s*{re.escape(name)}\s*=")
    for i, line in enumerate(lines):
        if pat.match(line):
            lines[i] = f"{name}={value}"
            break
    else:
        lines.append(f"{name}={value}")
    _write_private(path, "\n".join(lines) + "\n")


def run_setup(ctx: Context, *, add_keys: bool, test: bool, force_config: bool) -> int:
    cdir = config_dir()
    cdir.mkdir(parents=True, exist_ok=True)
    cfg = cdir / "config.toml"
    env = cdir / ".env"

    if cfg.exists() and not force_config:
        console.print(f"[green]✓[/] config: {cfg} (kept)")
    else:
        cfg.write_text(DEFAULT_CONFIG_TOML)
        console.print(f"[green]✓[/] config: {cfg} (written)")

    if env.exists():
        mode = env.stat().st_mode & 0o777
        if mode & 0o077:
            os.chmod(env, 0o600)
            console.print(f"[yellow]![/] {env} was mode {oct(mode)}; tightened to 0600")
        console.print(f"[green]✓[/] secrets: {env}")
    else:
        _write_private(env, ENV_TEMPLATE)
        console.print(f"[green]✓[/] secrets: {env} (created, mode 0600)")
    load_env()

    if add_keys:
        for p in PROVIDERS.values():
            if has_key(p.id):
                continue
            value = typer.prompt(
                f"{p.name} API key ({p.key_env[0]}; Enter to skip)",
                default="", show_default=False, hide_input=True,
            ).strip()
            if value:
                set_env_var(env, p.key_env[0], value)
                os.environ[p.key_env[0]] = value
                console.print(f"  [green]saved[/] {p.key_env[0]}")

    db = ctx.store  # creates the database
    console.print(f"[green]✓[/] database: {ctx.settings.db_path}")
    db.audit("user", "setup", {"config": str(cfg)})

    console.print()
    console.print(providers_table())
    console.print(models_table(ctx))

    if not any(has_key(p) for p in PROVIDERS):
        console.print("[red]No provider key configured.[/] Add one to "
                      f"{env} or rerun with --keys.")
        return 1
    if test:
        return asyncio.run(_test_models(ctx))
    console.print("[dim]Run `blackarch-ai setup --test` to check connectivity.[/]")
    return 0


async def _test_models(ctx: Context) -> int:
    """Send one tiny request per configured role through the real gateway."""
    gw = ModelGateway(ctx.settings, recorder=ctx.store.recorder())
    ok = True
    for role in ctx.settings.llm.profiles:
        console.print(f"Testing [bold]{role}[/] → {', '.join(gw.candidates(role)) or 'none'} …")
        started = time.monotonic()
        try:
            with console.status("waiting for model (this endpoint can take a minute or two)"):
                r = await gw.complete(
                    [{"role": "user", "content": "Reply with the single word: ready"}],
                    role=role,
                )
        except GatewayError as exc:
            ok = False
            console.print(f"  [red]✗ {exc}[/]")
            continue
        note = " [yellow](fallback)[/]" if r.fell_back else ""
        console.print(
            f"  [green]✓[/] {r.model}{note} replied {r.content.strip()[:40]!r} in "
            f"{time.monotonic() - started:.1f}s · {r.usage.total} tokens · {fmt_cost(r.cost_usd)}"
        )
    return 0 if ok else 1
