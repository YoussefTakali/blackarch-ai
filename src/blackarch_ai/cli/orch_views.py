"""Rendering for orchestration plans and the approval queue."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from blackarch_ai.orchestrator.orchestrator import OrchestrationResult
from blackarch_ai.orchestrator.plan import PlanOutput
from blackarch_ai.storage.models import ProposedOperation

STATUS_STYLE = {
    "pending": "yellow", "executed": "green", "rejected": "dim", "blocked": "red",
    "needs_params": "magenta", "approved": "cyan",
}
PERM_STYLE = {"passive": "green", "low": "cyan", "intrusive": "yellow", "high_impact": "bold red"}


def plan_table(plan_out: PlanOutput, names: dict[str, str]) -> Table:
    t = Table(title="Task plan", title_justify="left")
    t.add_column("#", justify="right")
    t.add_column("Agent")
    t.add_column("Objective")
    t.add_column("Depends on")
    for i, step in enumerate(plan_out.steps, 1):
        deps = ", ".join(str(d) for d in step.depends_on) or "—"
        t.add_row(str(i), names.get(step.agent_id, step.agent_id), escape(step.objective), deps)
    return t


def proposals_table(rows: list[ProposedOperation], title: str = "Proposed operations") -> Table:
    t = Table(title=title, title_justify="left")
    for c in ("ID", "Operation", "Target", "Level", "Status", "From", "Note"):
        t.add_column(c)
    for r in rows:
        perm = f"[{PERM_STYLE.get(r.permission, 'white')}]{r.permission}[/]"
        status = f"[{STATUS_STYLE.get(r.status, 'white')}]{r.status}[/]"
        extra = r.note or (f"→ execution #{r.execution_id}" if r.execution_id else "")
        t.add_row(str(r.id), r.operation, escape(r.target or "—"), perm, status,
                  r.source_agent, escape(extra[:60]))
    return t


def print_orchestration(console: Console, result: OrchestrationResult,
                        names: dict[str, str]) -> None:
    for w in result.warnings:
        console.print(f"[yellow]⚠ {escape(w)}[/]")
    for c in result.consultations:
        label = names.get(c.agent_id, c.agent_id)
        if c.ok:
            console.print(f"[cyan]●[/] [bold]{label}[/] (task #{c.task_id}): "
                          f"{escape(c.report.summary)}")
        else:
            console.print(f"[red]✗ {label}: {escape(c.error or '')}[/]")
    if not result.proposed:
        console.print("[dim]No operations were proposed.[/]")
        return
    t = Table(title="Operations from this plan", title_justify="left")
    for col in ("ID", "Operation", "Target", "Level", "Status", "From"):
        t.add_column(col)
    for p in result.proposed:
        perm = f"[{PERM_STYLE.get(p.permission, 'white')}]{p.permission}[/]"
        status = f"[{STATUS_STYLE.get(p.status, 'white')}]{p.status}[/]"
        if p.execution_id:
            status += f" [dim]#{p.execution_id}[/]"
        t.add_row(str(p.id), p.operation, escape(p.target or "—"), perm, status, p.source_agent)
    console.print(t)
    n_exec = len(result.by_status("executed"))
    n_pending = len(result.by_status("pending"))
    msg = []
    if n_exec:
        msg.append(f"[green]{n_exec} auto-run[/] (passive/low, in scope)")
    if n_pending:
        msg.append(f"[yellow]{n_pending} awaiting approval[/] — "
                   "blackarch-ai plan approve ID (or /approve in chat)")
    if msg:
        console.print(" · ".join(msg))
