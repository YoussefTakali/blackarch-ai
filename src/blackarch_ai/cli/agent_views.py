"""Rendering agent consultations."""

from __future__ import annotations

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from blackarch_ai.agents.consult import Consultation
from blackarch_ai.agents.schema import CheckedReport, CheckedStep
from blackarch_ai.cli.common import fmt_cost, fmt_tokens

PERM_STYLE = {"passive": "green", "low": "cyan", "intrusive": "yellow", "high_impact": "bold red"}
TOOL_STYLE = {"installed": "green", "other_agent": "yellow", "not_installed": "red", "none": "dim"}
SCOPE_STYLE = {"in_scope": "green", "out_of_scope": "bold red", "no_engagement": "yellow",
               "none": "dim"}


def _step_row(i: int, s: CheckedStep) -> list[str]:
    tool = "—" if not s.tool else f"[{TOOL_STYLE[s.tool_status]}]{escape(s.tool)}[/]"
    if s.tool_status == "not_installed":
        tool += " [red](not installed)[/]"
    target = "—" if not s.target else f"[{SCOPE_STYLE[s.scope_status]}]{escape(s.target)}[/]"
    if s.scope_status == "out_of_scope":
        target += " [red](out of scope)[/]"
    elif s.scope_status == "no_engagement":
        target += " [yellow](no engagement)[/]"
    perm = f"[{PERM_STYLE[s.permission.value]}]{s.permission.value}[/]"
    if s.blocked:
        status = "[bold red]blocked[/]"
    elif not s.target and s.permission.rank > 0:
        status = "[yellow]target TBD[/]"
    elif s.requires_approval:
        status = "[yellow]needs approval[/]"
    else:
        status = "[green]ok[/]"
    what = f"[bold]{escape(s.title)}[/]\n{escape(s.purpose)}"
    if s.notes:
        what += "\n[dim]" + escape("; ".join(s.notes)) + "[/]"
    return [str(i), what, tool, target, perm, status]


def report_renderable(r: CheckedReport, title: str, footer: str = "") -> Panel:
    parts: list = [Markdown(f"**{r.summary}**")]
    if r.analysis.strip():
        parts.append(Markdown(r.analysis))
    if r.steps:
        t = Table(title="Recommended steps (not executed)", title_justify="left", expand=True)
        for col, kw in [("#", {"justify": "right"}), ("Step", {"ratio": 4}), ("Tool", {"ratio": 1}),
                        ("Target", {"ratio": 2, "overflow": "fold"}), ("Level", {}), ("Status", {})]:
            t.add_column(col, **kw)
        for i, s in enumerate(r.steps, 1):
            t.add_row(*_step_row(i, s))
        parts.append(t)
    if r.hypotheses:
        t = Table(title="Hypotheses (unverified)", title_justify="left", expand=True)
        t.add_column("Confidence")
        t.add_column("Statement", ratio=3)
        t.add_column("Basis", ratio=2)
        for h in r.hypotheses:
            t.add_row(h.confidence, escape(h.statement), escape(h.basis))
        parts.append(t)
    if r.out_of_scope_notes:
        parts.append("[red]Out of scope:[/] " + escape("; ".join(r.out_of_scope_notes)))
    if r.help_requests:
        parts.append("[cyan]Asked:[/] " + "; ".join(
            f"{h.to_agent} — {escape(h.question)}" for h in r.help_requests))
    for issue in r.issues:
        parts.append(f"[yellow]⚠ {escape(issue)}[/]")
    if footer:
        parts.append(f"[dim]{footer}[/]")
    return Panel(Group(*parts), title=title, title_align="left", border_style="cyan")


def _footer(c: Consultation) -> str:
    r = c.result
    if r is None:
        return ""
    bits = [r.model, f"{fmt_tokens(r.usage.prompt_tokens)} in / "
                     f"{fmt_tokens(r.usage.completion_tokens)} out", fmt_cost(r.cost_usd),
            f"{r.latency_ms / 1000:.1f}s", f"task #{c.task_id}"]
    if r.fell_back:
        bits.append("fallback used")
    return " · ".join(bits)


def print_consultation(console: Console, c: Consultation, names: dict[str, str]) -> None:
    label = names.get(c.agent_id, c.agent_id)
    if not c.ok:
        console.print(f"[red]✗ {label} agent failed:[/] {escape(c.error or '')}")
        return
    console.print(report_renderable(c.report, f"[bold]{label}[/] agent", _footer(c)))
    for reply in c.replies:
        rl = names.get(reply.agent_id, reply.agent_id)
        if not reply.ok:
            console.print(f"[red]✗ {rl} (asked by {label}) failed:[/] {escape(reply.error or '')}")
            continue
        console.print(report_renderable(reply.report, f"[bold]{rl}[/] agent ← asked by {label}",
                                        _footer(reply)))
