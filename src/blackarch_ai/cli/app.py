"""Typer command tree."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.markup import escape
from rich.table import Table

from blackarch_ai import __version__
from blackarch_ai.cli.common import Context, console, err_console, fmt_totals, not_yet
from blackarch_ai.cli.views import agents_table, engagements_table, models_table, providers_table
from blackarch_ai.security.scope import Scope, ScopeError
from blackarch_ai.storage.store import StoreError

app = typer.Typer(
    help="BlackArch AI — multi-agent assistant for authorized security assessments.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)
tools_app = typer.Typer(help="BlackArch tool registry.")
agents_app = typer.Typer(help="Specialist agents.")
models_app = typer.Typer(help="Cloud models and routing.")
engagement_app = typer.Typer(help="Engagements and their authorized scope.")
ops_app = typer.Typer(help="Registered operations the engine can run.")
exec_app = typer.Typer(help="Execution history and evidence.")
app.add_typer(tools_app, name="tools")
app.add_typer(agents_app, name="agents")
app.add_typer(models_app, name="models")
app.add_typer(engagement_app, name="engagement")
app.add_typer(ops_app, name="ops")
app.add_typer(exec_app, name="exec")

ctx = Context()


def _exit(code: int) -> None:
    if code:
        raise typer.Exit(code)


EngagementOpt = Annotated[
    str | None, typer.Option("--engagement", "-e", help="Engagement name or ID to work in.")
]


@app.callback(invoke_without_command=True)
def main(
    typer_ctx: typer.Context,
    engagement: EngagementOpt = None,
    resume: Annotated[
        str | None,
        typer.Option("--resume", "-r", help="Resume a chat session: an ID, or 'last'."),
    ] = None,
    plain: Annotated[
        bool, typer.Option("--plain", help="Plain text output for basic terminals.")
    ] = False,
    version: Annotated[bool, typer.Option("--version", help="Show version.")] = False,
) -> None:
    """Start the interactive chat (default when no command is given)."""
    if version:
        console.print(f"blackarch-ai {__version__}")
        raise typer.Exit()
    if typer_ctx.invoked_subcommand is None:
        from blackarch_ai.cli.chat import start_chat

        try:
            _exit(start_chat(ctx, engagement, resume, plain))
        except KeyboardInterrupt:
            console.print("\n[dim]bye[/]")
            raise typer.Exit(130) from None


@app.command()
def setup(
    keys: Annotated[bool, typer.Option("--keys", help="Prompt for missing API keys.")] = False,
    test: Annotated[bool, typer.Option("--test", help="Send a test request per role.")] = False,
    force_config: Annotated[
        bool, typer.Option("--force-config", help="Overwrite config.toml with defaults.")
    ] = False,
) -> None:
    """Create config files, store API keys and check model connectivity."""
    from blackarch_ai.cli.setup import run_setup

    _exit(run_setup(ctx, add_keys=keys, test=test, force_config=force_config))


@app.command()
def report(
    engagement: Annotated[str, typer.Argument(help="Engagement name or ID.")],
    fmt: Annotated[str, typer.Option("--format", "-f",
                                     help="md | html | json | all.")] = "md",
    out: Annotated[str | None, typer.Option("--out", "-o",
                   help="Output path (file for one format, directory for 'all').")] = None,
    summary: Annotated[bool, typer.Option("--summary/--no-summary",
                       help="Add an AI executive summary (needs an API key).")] = False,
    stdout: Annotated[bool, typer.Option("--stdout",
                      help="Print to the terminal instead of writing a file.")] = False,
) -> None:
    """Generate an engagement report (Markdown / HTML / JSON) from findings and evidence."""
    import asyncio
    from datetime import UTC, datetime
    from pathlib import Path

    from blackarch_ai.config import data_dir
    from blackarch_ai.llm.gateway import GatewayError, ModelGateway
    from blackarch_ai.reports.render import render_html, render_json, render_markdown
    from blackarch_ai.reports.report import build_report
    from blackarch_ai.reports.summary import generate_summary

    fmt = fmt.lower()
    if fmt not in ("md", "html", "json", "all"):
        err_console.print("[red]--format must be md, html, json or all[/]")
        raise typer.Exit(2)
    eng, _ = _engagement_or_exit(engagement)

    exec_summary = None
    if summary:
        gw = ModelGateway(ctx.settings, recorder=ctx.store.recorder(engagement_id=eng.id))
        if not gw.candidates("reporting"):
            err_console.print("[yellow]No API key — skipping the AI summary.[/]")
        else:
            try:
                with console.status("writing the executive summary…"):
                    exec_summary = asyncio.run(
                        generate_summary(gw, build_report(ctx.store, eng)))
            except GatewayError as exc:
                err_console.print(f"[yellow]summary failed ({exc}); continuing without it[/]")

    data = build_report(ctx.store, eng, summary=exec_summary)
    renderers = {"md": render_markdown, "html": render_html, "json": render_json}
    exts = {"md": "md", "html": "html", "json": "json"}
    formats = ["md", "html", "json"] if fmt == "all" else [fmt]

    if stdout:
        import sys

        # Write raw so JSON/Markdown aren't reflowed by the renderer.
        sys.stdout.write("\n\n".join(renderers[f](data) for f in formats) + "\n")
        return

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    base = f"{eng.name}-{stamp}"
    written = []
    if fmt == "all":
        out_dir = Path(out).expanduser() if out else data_dir() / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in formats:
            path = out_dir / f"{base}.{exts[f]}"
            path.write_text(renderers[f](data))
            written.append(path)
    else:
        path = (Path(out).expanduser() if out
                else data_dir() / "reports" / f"{base}.{exts[fmt]}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(renderers[fmt](data))
        written.append(path)

    c = data.counts
    console.print(f"[green]✓[/] report for [bold]{eng.name}[/]: {c['verified']} verified, "
                  f"{c['hypotheses']} to verify, {c['executions']} operations")
    for p in written:
        console.print(f"  {p}")


# ---------------------------------------------------------------- tools


def _need_registry() -> None:
    if not ctx.ensure_registry():
        raise typer.Exit(1)


def _exe_names(tool, limit: int = 4) -> str:
    names = [p.rsplit("/", 1)[-1] for p in tool.executables]
    more = f" +{len(names) - limit}" if len(names) > limit else ""
    return ", ".join(names[:limit]) + more if names else "[dim]—[/]"


@tools_app.command("scan")
def tools_scan() -> None:
    """Discover installed tools (pacman metadata + man pages; runs no tool binaries)."""
    from blackarch_ai.tools.pacman import PacmanUnavailable

    try:
        scan = ctx.scan_tools()
    except PacmanUnavailable as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    console.print(f"[green]✓[/] {scan.tools} tools · {scan.executables} executables · "
                  f"{scan.man_pages} man pages indexed in {scan.duration_s:.1f}s")
    counts = ctx.registry.agent_counts()
    console.print("Per agent: " + ", ".join(
        f"{a.id} {counts.get(a.id, 0)}" for a in ctx.domains.agents if a.categories or a.keywords)
        + f", shared {counts.get('shared', 0)}")
    for w in scan.warnings:
        console.print(f"[yellow]⚠ {w}[/]")


@tools_app.command("list")
def tools_list(
    agent: Annotated[str | None, typer.Option("--agent", "-a", help="Only this agent's tools.")] = None,
    category: Annotated[str | None, typer.Option("--category", "-c", help="Only this category.")] = None,
    commands: Annotated[bool, typer.Option("--commands", help="Hide data/library packages.")] = False,
) -> None:
    """List installed tools from the registry."""
    _need_registry()
    if agent and agent not in {a.id for a in ctx.domains.agents} | {"shared"}:
        err_console.print(f"[red]Unknown agent {agent!r}[/] — see blackarch-ai agents list")
        raise typer.Exit(2)
    tools = ctx.registry.list(agent=agent, category=category, commands_only=commands)
    t = Table(title=f"Installed tools ({len(tools)})", title_justify="left")
    t.add_column("Tool", no_wrap=True)
    t.add_column("Version", overflow="fold")
    t.add_column("Categories")
    t.add_column("Commands")
    t.add_column("Docs", justify="center")
    for tool in tools:
        name = f"[red]{tool.name}[/]" if tool.permission == "high_impact" else tool.name
        t.add_row(name, tool.version, ", ".join(tool.categories), _exe_names(tool),
                  "man" if tool.man_pages else "[dim]—[/]")
    console.print(t)
    console.print("[dim]Red = high-impact tool. `tools show NAME` for details, "
                  "`tools search TEXT` to find tools by purpose.[/]")


@tools_app.command("show")
def tools_show(
    name: Annotated[str, typer.Argument(help="Package or command name.")],
    man: Annotated[bool, typer.Option("--man", help="Print the full man page.")] = False,
) -> None:
    """Show a tool's metadata, documentation summary and owning agents."""
    _need_registry()
    tool = ctx.registry.get(name)
    if tool is None:
        err_console.print(f"[red]{name!r} is not in the registry[/] (not installed, or not a "
                          "known security tool). Try [bold]blackarch-ai tools search[/].")
        raise typer.Exit(1)
    agent_names = {a.id: a.name for a in ctx.domains.agents} | {"shared": "Shared"}
    console.print(f"[bold]{tool.name}[/] {tool.version}  [dim]({tool.source})[/]")
    console.print(escape(tool.description))
    if tool.url:
        console.print(f"[dim]{tool.url}[/]")
    console.print(f"Categories: {', '.join(tool.categories)}")
    console.print("Agents: " + ", ".join(agent_names.get(a, a) for a in tool.agents))
    console.print("Permission: " + ("[red]high-impact — always needs explicit approval[/]"
                                    if tool.permission == "high_impact"
                                    else "unclassified (set per operation in Phase 5)"))
    console.print(f"Commands: {', '.join(tool.executables) or '— (data/library package)'}")
    console.print(f"Man pages: {', '.join(tool.man_pages) or '—'}")
    if tool.summary:
        console.print("\n" + escape(tool.summary))
    if man:
        if not tool.man_pages:
            err_console.print("No man page installed for this tool.")
            raise typer.Exit(1)
        from blackarch_ai.tools.documentation import render_man

        text_ = render_man(tool.man_pages[0])
        if text_ is None:
            err_console.print("Could not render the man page.")
            raise typer.Exit(1)
        with console.pager():
            console.print(text_, markup=False, highlight=False)


@tools_app.command("search")
def tools_search(
    query: Annotated[list[str], typer.Argument(help="What you want to do, in plain words.")],
    agent: Annotated[str | None, typer.Option("--agent", "-a", help="Only this agent's tools.")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 10,
) -> None:
    """Find installed tools by purpose (searches names, descriptions and man pages)."""
    _need_registry()
    hits = ctx.registry.search(" ".join(query), limit, agent=agent)
    if not hits:
        console.print("No matching installed tools.")
        raise typer.Exit(1)
    t = Table(title=f"Tools matching {' '.join(query)!r}", title_justify="left")
    t.add_column("Tool", no_wrap=True)
    t.add_column("Description")
    t.add_column("Commands")
    for h in hits:
        desc = escape(h.tool.description) + (f"\n[dim]{escape(h.snippet)}[/]" if h.snippet else "")
        t.add_row(h.tool.name, desc, _exe_names(h.tool, 3))
    console.print(t)


# ---------------------------------------------------------------- agents


@agents_app.command("list")
def agents_list(
    no_pacman: Annotated[
        bool, typer.Option("--no-pacman", help="Don't query pacman for installed counts.")
    ] = False,
) -> None:
    """Show agents and the BlackArch categories each one owns."""
    table, warnings = agents_table(ctx, check_pacman=not no_pacman)
    console.print(table)
    console.print("[dim]Red = high-impact category (always needs explicit approval). "
                  "(0) = nothing installed from that category. "
                  "Ask one with: blackarch-ai agents ask ID \"question\"[/]")
    for w in warnings:
        console.print(f"[yellow]⚠ {w}[/]")


def _engagement_or_exit(name: str | None):
    if name is None:
        return None, None
    try:
        eng = ctx.store.get_engagement(name)
    except StoreError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    return eng, ctx.store.scope_of(eng)


@agents_app.command("show")
def agents_show(
    agent_id: Annotated[str, typer.Argument(help="Agent id, e.g. web.")],
    prompt: Annotated[bool, typer.Option("--prompt", help="Print the full system prompt.")] = False,
    engagement: EngagementOpt = None,
) -> None:
    """Show an agent's configuration, model chain, tools and prompt."""
    from blackarch_ai.agents.base import AgentContext
    from blackarch_ai.agents.directory import UnknownAgent

    eng, scope = _engagement_or_exit(engagement)
    directory, _ = ctx.agents_for(eng)
    try:
        agent = directory.get(agent_id)
    except UnknownAgent as exc:
        err_console.print(f"[red]{exc.args[0]}[/]")
        raise typer.Exit(1) from None
    gw = agent.gateway
    console.print(f"[bold]{agent.name}[/] ({agent.id})")
    console.print(agent.description)
    console.print(f"Categories: {', '.join(agent.domain.categories) or '—'}"
                  + (f"  ·  keywords: {', '.join(agent.domain.keywords)}"
                     if agent.domain.keywords else ""))
    console.print(f"Permission ceiling: {agent.max_permission.value}")
    console.print(f"Models (usable, in order): {' → '.join(gw.candidates(agent.id)) or '[red]none[/]'}")
    console.print(f"Installed tools: {len(agent.tool_names())}")
    if agent.override.extra_instructions:
        console.print(f"Extra instructions: {agent.override.extra_instructions}")
    if prompt:
        ctx_ = AgentContext(engagement=eng, scope=scope, peers=directory.ids())
        console.print()
        console.print(agent.system_prompt(ctx_), markup=False, highlight=False)


@agents_app.command("ask")
def agents_ask(
    agent_id: Annotated[str, typer.Argument(help="Agent id, e.g. web.")],
    question: Annotated[list[str], typer.Argument(help="The task or question.")],
    engagement: EngagementOpt = None,
    no_follow: Annotated[
        bool, typer.Option("--no-follow", help="Don't deliver the agent's help requests.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the checked report as JSON.")] = False,
) -> None:
    """Give one agent a task and show its checked report (nothing is executed)."""
    import asyncio
    import json

    from blackarch_ai.agents.consult import consult
    from blackarch_ai.agents.directory import UnknownAgent
    from blackarch_ai.cli.agent_views import print_consultation

    eng, scope = _engagement_or_exit(engagement)
    directory, bus = ctx.agents_for(eng)
    try:
        agent = directory.get(agent_id)
    except UnknownAgent as exc:
        err_console.print(f"[red]{exc.args[0]}[/]")
        raise typer.Exit(1) from None
    if not agent.gateway.candidates(agent.id):
        err_console.print("[red]No usable model for this agent (no API key).[/]")
        raise typer.Exit(1)
    text_ = " ".join(question)
    with console.status(f"{agent.name} agent working…"):
        result = asyncio.run(consult(directory, bus, agent.id, text_, engagement=eng,
                                     scope=scope, follow_help=not no_follow))
    if as_json:
        def dump(c):
            return {"agent": c.agent_id, "task_id": c.task_id, "error": c.error,
                    "report": c.report.model_dump(mode="json") if c.report else None,
                    "replies": [dump(r) for r in c.replies]}
        console.print_json(json.dumps(dump(result)))
    else:
        names = {a.id: a.name for a in ctx.domains.agents}
        print_consultation(console, result, names)
    _exit(0 if result.ok else 1)


@agents_app.command("tasks")
def agents_tasks(
    engagement: EngagementOpt = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
    show: Annotated[int | None, typer.Option("--show", help="Show one task's full report.")] = None,
) -> None:
    """List recent agent tasks (or show one) for an engagement."""
    from blackarch_ai.agents.bus import MessageBus
    from blackarch_ai.agents.schema import CheckedReport
    from blackarch_ai.cli.agent_views import report_renderable

    eng, _ = _engagement_or_exit(engagement)
    bus = MessageBus(ctx.store, eng.id if eng else None)
    if show is not None:
        task = bus.get_task(show)
        if task is None:
            err_console.print(f"[red]No task #{show}[/]")
            raise typer.Exit(1)
        console.print(f"Task #{task.id} · {task.agent_id} · asked by {task.requested_by} · "
                      f"{task.status}")
        console.print(f"[dim]{escape(task.input)}[/]")
        if task.report:
            console.print(report_renderable(CheckedReport.model_validate(task.report),
                                            task.agent_id, task.model or ""))
        elif task.error:
            console.print(f"[red]{escape(task.error)}[/]")
        for m in bus.thread([task.id] + [c.id for c in bus.children(task.id)]):
            console.print(f"[dim]{m.created_at:%H:%M:%S} {m.sender} → {m.recipient} "
                          f"({m.kind}): {escape(m.content[:200])}[/]")
        return
    tasks = bus.tasks(limit)
    if not tasks:
        console.print("No agent tasks yet.")
        return
    t = Table(title="Agent tasks", title_justify="left")
    for col in ("ID", "Agent", "Asked by", "Status", "Steps", "Issues", "Task"):
        t.add_column(col)
    for task in tasks:
        steps = len(task.report.get("steps", [])) if task.report else 0
        t.add_row(str(task.id), task.agent_id, task.requested_by, task.status, str(steps),
                  str(len(task.issues or [])), escape(task.input[:60]))
    console.print(t)


# ---------------------------------------------------------------- models


@models_app.command("list")
def models_list() -> None:
    """Show model routing per role and which providers have keys."""
    console.print(models_table(ctx))
    console.print(providers_table())
    totals = ctx.store.usage_totals()
    if totals.calls:
        console.print(f"All-time usage: {fmt_totals(totals)}")


@models_app.command("test")
def models_test() -> None:
    """Send one small request per role to check connectivity."""
    import asyncio

    from blackarch_ai.cli.setup import _test_models

    _exit(asyncio.run(_test_models(ctx)))


# ---------------------------------------------------------------- engagements


@engagement_app.command("create")
def engagement_create(
    name: Annotated[str, typer.Argument(help="Short unique name, e.g. 'homelab-2026'.")],
    target: Annotated[
        list[str] | None,
        typer.Option("--target", "-t", help="In-scope IP, CIDR, hostname, *.domain or URL. Repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", "-x", help="Out-of-scope entry. Repeatable."),
    ] = None,
    objective: Annotated[str, typer.Option("--objective", "-o", help="What the assessment is for.")] = "",
    authorized_by: Annotated[
        str, typer.Option("--authorized-by", help="Who authorized this testing.")
    ] = "",
    allow_broad: Annotated[
        bool, typer.Option("--allow-broad", help="Permit networks broader than /16 (IPv4).")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the authorization prompt.")] = False,
) -> None:
    """Create an engagement with an explicitly authorized scope."""
    targets = list(target or [])
    if not targets:
        raw = typer.prompt("In-scope targets (comma-separated IPs, CIDRs, hosts, URLs)")
        targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not objective and not yes:
        objective = typer.prompt("Objective", default="", show_default=False)
    try:
        scope = Scope.build(targets, exclude or [], allow_broad=allow_broad)
    except ScopeError as exc:
        err_console.print(f"[red]Invalid scope:[/] {exc}")
        raise typer.Exit(2) from None

    console.print(f"Scope: {scope.summary()}")
    if not yes:
        if not authorized_by:
            authorized_by = typer.prompt("Authorized by (person/org/ticket)", default="",
                                         show_default=False)
        if not typer.confirm("I confirm I am authorized to assess every in-scope target"):
            err_console.print("Cancelled; nothing created.")
            raise typer.Exit(1)
    try:
        eng = ctx.store.create_engagement(name, scope, objective=objective,
                                          authorized_by=authorized_by)
    except StoreError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    console.print(f"[green]✓[/] engagement [bold]{eng.name}[/] (#{eng.id}) created. "
                  f"Start with: [bold]blackarch-ai -e {eng.name}[/]")


@engagement_app.command("list")
def engagement_list() -> None:
    """List engagements."""
    engs = ctx.store.list_engagements()
    if not engs:
        console.print("No engagements yet. Create one with "
                      "[bold]blackarch-ai engagement create NAME -t TARGET[/]")
        return
    console.print(engagements_table(ctx, engs))


@engagement_app.command("show")
def engagement_show(name: Annotated[str, typer.Argument(help="Name or ID.")]) -> None:
    """Show an engagement's scope, usage and recent audit events."""
    try:
        eng = ctx.store.get_engagement(name)
    except StoreError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    scope = ctx.store.scope_of(eng)
    console.print(f"[bold]{eng.name}[/] (#{eng.id}) · {eng.status} · created "
                  f"{eng.created_at:%Y-%m-%d %H:%M}")
    console.print(f"Objective: {eng.objective or '—'}")
    console.print(f"Authorized by: {eng.authorized_by or '—'}")
    console.print(f"Scope: {scope.summary()}")
    console.print(f"Model usage: {fmt_totals(ctx.store.usage_totals(engagement_id=eng.id))}")
    t = Table(title="Recent audit events", title_justify="left")
    for col in ("Time", "Actor", "Action", "Details"):
        t.add_column(col)
    for ev in ctx.store.audit_events(eng.id, limit=15):
        details = ", ".join(f"{k}={v}" for k, v in ev.details.items() if v not in (None, {}, ""))
        t.add_row(f"{ev.created_at:%m-%d %H:%M:%S}", ev.actor, ev.action, details[:80])
    console.print(t)


@engagement_app.command("check")
def engagement_check(
    name: Annotated[str, typer.Argument(help="Engagement name or ID.")],
    targets: Annotated[list[str], typer.Argument(help="Targets to test against the scope.")],
) -> None:
    """Check whether targets are inside an engagement's authorized scope."""
    try:
        eng = ctx.store.get_engagement(name)
    except StoreError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    scope = ctx.store.scope_of(eng)
    all_ok = True
    for t in targets:
        ok, reason = scope.check(t)
        all_ok &= ok
        console.print(f"{'[green]✓ in scope' if ok else '[red]✗ out of scope'}[/]  {t}  [dim]{reason}[/]")
    _exit(0 if all_ok else 1)


# ---------------------------------------------------------------- operations


def _perm_style(p: str) -> str:
    return {"passive": "green", "low": "cyan", "intrusive": "yellow",
            "high_impact": "bold red"}.get(p, "white")


@ops_app.command("list")
def ops_list(
    tool: Annotated[str | None, typer.Option("--tool", "-t", help="Only this tool's operations.")] = None,
) -> None:
    """List registered operations the engine can run."""
    ops = ctx.catalogue.for_tool(tool) if tool else ctx.catalogue.all()
    t = Table(title=f"Registered operations ({len(ops)})", title_justify="left")
    t.add_column("Operation", no_wrap=True)
    t.add_column("Tool")
    t.add_column("Level")
    t.add_column("Summary")
    for op in ops:
        t.add_row(op.id, op.tool, f"[{_perm_style(op.permission.value)}]{op.permission.value}[/]",
                  op.summary)
    console.print(t)
    console.print("[dim]intrusive and high_impact operations require approval at run time. "
                  "Run one with: blackarch-ai run OP --target T [--param name=value][/]")


@ops_app.command("show")
def ops_show(op_id: Annotated[str, typer.Argument(help="Operation id.")]) -> None:
    """Show an operation's parameters, target and permission."""
    from blackarch_ai.execution.operations import OperationError

    try:
        op = ctx.catalogue.get(op_id)
    except OperationError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    console.print(f"[bold]{op.id}[/] — {op.summary}")
    console.print(f"Tool: {op.tool} (command: {op.exe_name})")
    console.print(f"Permission: [{_perm_style(op.permission.value)}]{op.permission.value}[/]"
                  + ("  [yellow](needs approval)[/]" if op.permission.needs_approval else ""))
    console.print(f"Fixed args: {' '.join(op.args) or '—'}  ·  timeout {op.timeout:.0f}s")
    if op.target:
        console.print(f"Target: kind={op.target.kind}, "
                      f"{'required' if op.target.required else 'optional'}"
                      + (f", flag {op.target.flag}" if op.target.flag else ""))
    if op.params:
        t = Table(title="Parameters", title_justify="left")
        for c in ("Name", "Type", "Flag", "Required", "Default", "Choices/format"):
            t.add_column(c)
        for p in op.params:
            extra = ", ".join(p.choices) if p.choices else (p.pattern or "")
            t.add_row(p.name, p.type, p.flag or "—", "yes" if p.required else "no",
                      str(p.default) if p.default is not None else "—", extra)
        console.print(t)


def _parse_params(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            err_console.print(f"[red]--param must be name=value, got {pair!r}[/]")
            raise typer.Exit(2)
        k, _, v = pair.partition("=")
        out[k.strip()] = v
    return out


@app.command()
def run(
    operation: Annotated[str, typer.Argument(help="Operation id (see `ops list`).")],
    target: Annotated[str | None, typer.Option("--target", "-t", help="Target host/URL/network.")] = None,
    param: Annotated[list[str] | None, typer.Option("--param", "-p", help="name=value. Repeatable.")] = None,
    engagement: EngagementOpt = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Approve without the interactive prompt.")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show the plan and exit; run nothing.")] = False,
) -> None:
    """Run one registered operation against an authorized target."""
    import asyncio

    from blackarch_ai.execution.engine import ExecutionError, NotApproved
    from blackarch_ai.execution.operations import OperationError, ValidationError

    if not ctx.ensure_registry():
        raise typer.Exit(1)
    eng, scope = _engagement_or_exit(engagement)
    engine = ctx.engine()
    try:
        plan = engine.plan(operation, _parse_params(param or []), target,
                           engagement_id=eng.id if eng else None, scope=scope)
    except (OperationError, ValidationError, ExecutionError) as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from None

    lvl = plan.permission.value
    console.print(f"[bold]{plan.operation.id}[/]  [{_perm_style(lvl)}]{lvl}[/]")
    console.print(f"Command: [dim]{escape(plan.command_line)}[/]")
    if plan.target:
        style = "green" if plan.scope_status == "in_scope" else "red"
        console.print(f"Target: {escape(plan.target)}  [{style}]{plan.scope_status}[/] "
                      f"[dim]{plan.scope_reason}[/]")
    if plan.blocked:
        err_console.print(f"[bold red]✗ blocked:[/] {plan.block_reason}")
        raise typer.Exit(1)
    if dry_run:
        console.print("[dim]dry run — nothing executed[/]")
        return

    approval = None
    if plan.needs_approval:
        if not yes and not typer.confirm(
                f"This is a {lvl} operation. Approve and run it?", default=False):
            engine.record_approval(plan, "rejected")
            console.print("Rejected; nothing ran.")
            raise typer.Exit(1)
        approval = engine.record_approval(plan, "approved",
                                          reason="--yes" if yes else "interactive")

    try:
        with console.status(f"running {plan.operation.id} (Ctrl+C to cancel)…"):
            result = asyncio.run(engine.run(plan, approval=approval))
    except NotApproved as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    except KeyboardInterrupt:
        console.print("[yellow]⏹ cancelled[/]")
        raise typer.Exit(130) from None

    colour = {"success": "green", "failed": "yellow", "timeout": "red",
              "error": "red"}.get(result.status, "white")
    console.print(f"[{colour}]{result.status}[/] · exit {result.exit_code} · "
                  f"{result.duration_s:.1f}s · execution #{result.execution_id}"
                  + (" · [red]output truncated[/]" if result.truncated else ""))
    if result.error:
        err_console.print(f"[red]{escape(result.error)}[/]")
    if result.stdout.strip():
        console.print(result.stdout.rstrip(), markup=False, highlight=False)
    if result.stderr.strip():
        console.print("[dim]--- stderr ---[/]")
        console.print(result.stderr.rstrip()[:4000], markup=False, highlight=False)
    console.print(f"[dim]evidence: {', '.join(result.evidence)}[/]")
    _exit(0 if result.ok else 1)


@exec_app.command("list")
def exec_list(
    engagement: EngagementOpt = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 20,
) -> None:
    """List recent tool executions."""
    eng, _ = _engagement_or_exit(engagement)
    rows = ctx.store.list_executions(engagement_id=eng.id if eng else None, limit=limit)
    if not rows:
        console.print("No executions yet. Run one with [bold]blackarch-ai run OP -t TARGET[/]")
        return
    t = Table(title="Executions", title_justify="left")
    for c in ("ID", "Operation", "Target", "Level", "Status", "Exit", "When"):
        t.add_column(c)
    for e in rows:
        t.add_row(str(e.id), e.operation, escape(e.target or "—"), e.permission,
                  f"[{_perm_style(e.permission)}]{e.status}[/]" if e.status != 'success'
                  else "[green]success[/]",
                  str(e.exit_code) if e.exit_code is not None else "—",
                  e.created_at.strftime("%m-%d %H:%M"))
    console.print(t)


@exec_app.command("show")
def exec_show(exec_id: Annotated[int, typer.Argument(help="Execution id.")]) -> None:
    """Show one execution's command, result and evidence files."""
    e = ctx.store.get_execution(exec_id)
    if e is None:
        err_console.print(f"[red]No execution #{exec_id}[/]")
        raise typer.Exit(1)
    console.print(f"[bold]#{e.id}[/] {e.operation} ({e.tool}) · {e.permission} · {e.status}"
                  f" · exit {e.exit_code} · {e.duration_s:.1f}s")
    console.print(f"Command: [dim]{escape(' '.join(e.argv))}[/]")
    console.print(f"Target: {escape(e.target or '—')}  ·  requested by {e.requested_by}")
    if e.error:
        console.print(f"[red]{escape(e.error)}[/]")
    for ev in e.evidence:
        console.print(f"[dim]{ev.kind}: {ev.path} ({ev.size_bytes} B, sha256 {ev.sha256[:12]}…)[/]")


# ---------------------------------------------------------------- orchestration

plan_app = typer.Typer(help="Orchestration plans and the approval queue.")
app.add_typer(plan_app, name="plan")


@app.command()
def orchestrate(
    objective: Annotated[list[str], typer.Argument(help="What to assess, in plain words.")],
    engagement: EngagementOpt = None,
    plan_only: Annotated[bool, typer.Option("--plan-only", help="Plan and run agents; execute nothing.")] = False,
    manual: Annotated[bool, typer.Option("--manual", help="Queue every operation; auto-run none.")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Run the plan without confirming it first.")] = False,
) -> None:
    """Plan an objective, run the agents, and queue/execute the operations."""
    import asyncio

    from blackarch_ai.cli.orch_views import plan_table, print_orchestration
    from blackarch_ai.llm.gateway import GatewayError
    from blackarch_ai.orchestrator.plan import PlanError

    if not ctx.ensure_registry():
        raise typer.Exit(1)
    eng, scope = _engagement_or_exit(engagement)
    orch = ctx.orchestrator_for(eng, scope)
    if not orch.gateway.candidates("orchestrator"):
        err_console.print("[red]No usable model (no API key). Run `blackarch-ai setup`.[/]")
        raise typer.Exit(1)
    names = {a.id: a.name for a in ctx.domains.agents}
    goal = " ".join(objective)

    try:
        with console.status("planning…"):
            plan_row, plan_out, warnings = asyncio.run(orch.make_plan(goal))
    except (GatewayError, PlanError) as exc:
        err_console.print(f"[red]planning failed: {exc}[/]")
        raise typer.Exit(1) from None
    console.print(f"[dim]{escape(plan_out.summary)}[/]")
    console.print(plan_table(plan_out, names))
    for w in warnings:
        console.print(f"[yellow]⚠ {escape(w)}[/]")

    mode = "plan_only" if plan_only else ("manual" if manual else "auto_safe")
    if mode == "auto_safe" and not yes:
        console.print("[dim]Passive/low in-scope operations will run automatically; "
                      "intrusive/high-impact ones will be queued for your approval.[/]")
        if not typer.confirm("Run this plan?", default=True):
            console.print("Stopped after planning; nothing ran.")
            raise typer.Exit(0)

    def ev(msg: str) -> None:
        console.print(f"[dim]  {escape(msg)}[/]")

    try:
        result = asyncio.run(orch.run(plan_row, plan_out, mode=mode, on_event=ev))
    except KeyboardInterrupt:
        asyncio.run(orch.engine.stop_all())
        console.print("[yellow]⏹ stopped[/]")
        raise typer.Exit(130) from None
    print_orchestration(console, result, names)


@plan_app.command("list")
def plan_list(engagement: EngagementOpt = None,
              limit: Annotated[int, typer.Option("--limit", "-n")] = 15) -> None:
    """List orchestration plans."""
    from sqlalchemy import select

    from blackarch_ai.storage.models import Plan

    eng, _ = _engagement_or_exit(engagement)
    with ctx.store.session() as s:
        q = select(Plan).order_by(Plan.id.desc()).limit(limit)
        if eng is not None:
            q = q.where(Plan.engagement_id == eng.id)
        plans = list(s.scalars(q).all())
    if not plans:
        console.print("No plans yet. Create one with [bold]blackarch-ai orchestrate \"...\"[/]")
        return
    t = Table(title="Plans", title_justify="left")
    for c in ("ID", "Status", "Steps", "When", "Objective"):
        t.add_column(c)
    for p in plans:
        t.add_row(str(p.id), p.status, str(len(p.steps or [])),
                  p.created_at.strftime("%m-%d %H:%M"), escape(p.objective[:60]))
    console.print(t)


@plan_app.command("queue")
def plan_queue(engagement: EngagementOpt = None) -> None:
    """Show operations awaiting approval."""
    from blackarch_ai.cli.orch_views import proposals_table

    eng, scope = _engagement_or_exit(engagement)
    orch = ctx.orchestrator_for(eng, scope)
    rows = orch.pending()
    if not rows:
        console.print("Approval queue is empty.")
        return
    console.print(proposals_table(rows, "Approval queue (pending)"))
    console.print("[dim]Approve with: blackarch-ai plan approve ID  ·  reject: plan reject ID[/]")


@plan_app.command("approve")
def plan_approve(
    op_id: Annotated[int, typer.Argument(help="Proposed operation ID (see `plan queue`).")],
    engagement: EngagementOpt = None,
) -> None:
    """Approve and run a queued operation."""
    import asyncio

    from blackarch_ai.execution.engine import ExecutionError

    eng, scope = _engagement_or_exit(engagement)
    orch = ctx.orchestrator_for(eng, scope)
    row = orch.get_proposal(op_id)
    if row is None:
        err_console.print(f"[red]no proposed operation #{op_id}[/]")
        raise typer.Exit(1)
    console.print(f"[bold]{row.operation}[/] on {escape(row.target or '—')}  "
                  f"[{_perm_style(row.permission)}]{row.permission}[/]")
    console.print(f"Command: [dim]{escape(' '.join(row.argv))}[/]")
    try:
        with console.status(f"running {row.operation}…"):
            res = asyncio.run(orch.approve(op_id))
    except ExecutionError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    colour = "green" if res.ok else "yellow"
    console.print(f"[{colour}]{res.status}[/] · exit {res.exit_code} · execution #{res.execution_id}")
    if res.stdout.strip():
        console.print(res.stdout.rstrip()[:4000], markup=False, highlight=False)


@plan_app.command("reject")
def plan_reject(
    op_id: Annotated[int, typer.Argument(help="Proposed operation ID.")],
    engagement: EngagementOpt = None,
) -> None:
    """Reject a queued operation."""
    from blackarch_ai.execution.engine import ExecutionError

    eng, scope = _engagement_or_exit(engagement)
    orch = ctx.orchestrator_for(eng, scope)
    try:
        orch.reject(op_id)
    except ExecutionError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    console.print(f"[dim]rejected #{op_id}[/]")
