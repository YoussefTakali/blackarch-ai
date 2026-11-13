"""Rich renderables shared by subcommands and interactive slash commands."""

from __future__ import annotations

from rich.table import Table

from blackarch_ai.cli.common import Context, fmt_cost
from blackarch_ai.llm.pricing import has_price
from blackarch_ai.llm.providers import PROVIDERS, has_key, provider_of
from blackarch_ai.storage.models import Engagement
from blackarch_ai.tools.pacman import PacmanUnavailable, group_inventory


def providers_table() -> Table:
    t = Table(title="Providers", title_justify="left")
    t.add_column("Provider")
    t.add_column("Key variable")
    t.add_column("Configured")
    for p in PROVIDERS.values():
        t.add_row(p.name, " / ".join(p.key_env),
                  "[green]yes[/]" if has_key(p.id) else "[dim]no[/]")
    return t


def models_table(ctx: Context) -> Table:
    llm = ctx.settings.llm
    t = Table(title="Model routing (tried in order)", title_justify="left")
    t.add_column("Role")
    t.add_column("#", justify="right")
    t.add_column("Model", overflow="fold")
    t.add_column("Provider")
    t.add_column("Key")
    t.add_column("Pricing")
    for role, prof in llm.profiles.items():
        for i, model in enumerate(prof.chain()):
            prov = provider_of(model)
            t.add_row(
                role if i == 0 else "",
                str(i + 1),
                model,
                prov,
                "[green]✓[/]" if has_key(prov) else "[red]✗ skipped[/]",
                "known" if has_price(model, llm.pricing) else "[dim]unknown[/]",
                end_section=i == len(prof.chain()) - 1,
            )
    return t


def agents_table(ctx: Context, *, check_pacman: bool = True) -> tuple[Table, list[str]]:
    """Agent → categories table. Also returns warnings about the mapping."""
    d = ctx.domains
    inv = None
    warnings: list[str] = []
    if check_pacman:
        try:
            inv = group_inventory()
        except (PacmanUnavailable, OSError) as exc:
            warnings.append(f"Could not read pacman groups: {exc}")

    t = Table(title="Agents and BlackArch categories", title_justify="left")
    t.add_column("Agent")
    t.add_column("Categories")
    if inv:
        t.add_column("Tools installed", justify="right")

    def cats_cell(cats: tuple[str, ...]) -> str:
        if not cats:
            return "[dim]—[/]"
        parts = []
        for c in cats:
            label = f"[red]{c}[/]" if c in d.high_impact else c
            if inv is not None:
                n_i = len(inv.installed.get(c, ()))
                n_a = len(inv.available.get(c, ()))
                if n_a == 0:
                    label += " [dim](not in repo)[/]"
                elif n_i == 0:
                    label += " [yellow](0)[/]"
            parts.append(label)
        return ", ".join(parts)

    def count_cell(cats: tuple[str, ...], keywords: tuple[str, ...]) -> str:
        if inv is None:
            return ""
        if not cats:
            return "[dim]by keyword[/]" if keywords else "[dim]—[/]"
        n_i = len(set().union(*(inv.installed.get(c, set()) for c in cats)))
        n_a = len(set().union(*(inv.available.get(c, set()) for c in cats)))
        return f"{n_i}/{n_a}"

    for a in d.agents:
        row = [f"[bold]{a.name}[/]\n[dim]{a.id}[/]", cats_cell(a.categories)]
        if inv:
            row.append(count_cell(a.categories, a.keywords))
        t.add_row(*row, end_section=True)
    shared_row = ["[bold]Shared[/]\n[dim]all agents[/]", cats_cell(d.shared)]
    if inv:
        shared_row.append(count_cell(d.shared, ()))
    t.add_row(*shared_row)

    if inv is not None:
        unassigned = sorted(set(inv.available) - d.all_categories())
        stale = sorted(d.all_categories() - set(inv.available))
        if unassigned:
            warnings.append("Categories in the repo but not assigned to any agent: "
                            + ", ".join(unassigned))
        if stale:
            warnings.append("Assigned categories not present in the repo: " + ", ".join(stale))
    return t, warnings


def engagements_table(ctx: Context, engagements: list[Engagement]) -> Table:
    t = Table(title="Engagements", title_justify="left")
    t.add_column("ID", justify="right")
    t.add_column("Name")
    t.add_column("Scope")
    t.add_column("Status")
    t.add_column("Created")
    t.add_column("Model spend", justify="right")
    for e in engagements:
        totals = ctx.store.usage_totals(engagement_id=e.id)
        t.add_row(str(e.id), e.name, ctx.store.scope_of(e).summary(), e.status,
                  e.created_at.strftime("%Y-%m-%d %H:%M"),
                  fmt_cost(totals.cost_usd) if totals.unpriced_calls == 0 else "unknown")
    return t
