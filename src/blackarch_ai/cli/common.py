"""Shared CLI state and formatting helpers."""

from __future__ import annotations

from functools import cached_property

from rich.console import Console

from blackarch_ai.config import Settings, load_settings
from blackarch_ai.core.domains import DomainMap, load_domains
from blackarch_ai.storage.store import Store, UsageTotals

console = Console()
err_console = Console(stderr=True)


class Context:
    """Lazily-built application objects shared by CLI commands."""

    @cached_property
    def settings(self) -> Settings:
        return load_settings()

    @cached_property
    def store(self) -> Store:
        return Store(self.settings.db_path)

    @cached_property
    def domains(self) -> DomainMap:
        return load_domains()

    @cached_property
    def registry(self):  # -> Registry (imported lazily: keeps `--help` fast)
        from blackarch_ai.tools.registry import Registry

        return Registry(self.store)

    def scan_tools(self, *, quiet: bool = False):
        """Run discovery and save it. Returns the ToolScan row."""
        from blackarch_ai.tools.discovery import Discovery

        disc = Discovery(self.domains)
        if quiet or not console.is_terminal:
            result = disc.scan()
        else:
            with console.status("scanning installed tools…") as status:
                def progress(stage: str, done: int, total: int) -> None:
                    status.update(f"{stage}… {done}/{total}" if total else f"{stage}…")

                result = disc.scan(progress)
        return self.registry.save(result)

    @cached_property
    def catalogue(self):  # -> OperationCatalogue
        from blackarch_ai.execution.operations import load_operations

        return load_operations()

    def engine(self):  # -> ExecutionEngine
        from blackarch_ai.execution.engine import ExecutionEngine

        return ExecutionEngine(self.settings, self.store, self.registry, self.catalogue)

    def orchestrator_for(self, engagement, scope, *, session_id: int | None = None):
        """Build an Orchestrator (directory + engine + bus) for an engagement."""
        from blackarch_ai.agents.bus import MessageBus
        from blackarch_ai.agents.directory import AgentDirectory
        from blackarch_ai.execution.engine import ExecutionEngine
        from blackarch_ai.llm.gateway import ModelGateway
        from blackarch_ai.orchestrator.orchestrator import Orchestrator

        eng_id = engagement.id if engagement is not None else None
        gw = ModelGateway(self.settings,
                          recorder=self.store.recorder(engagement_id=eng_id, session_id=session_id))
        directory = AgentDirectory(self.domains, self.settings, gw, self.registry)
        engine = ExecutionEngine(self.settings, self.store, self.registry, self.catalogue)
        bus = MessageBus(self.store, eng_id)
        return Orchestrator(directory=directory, engine=engine, bus=bus, gateway=gw,
                            registry=self.registry, engagement=engagement, scope=scope)

    def agents_for(self, engagement, *, session_id: int | None = None):
        """(AgentDirectory, MessageBus) bound to an engagement (or none)."""
        from blackarch_ai.agents.bus import MessageBus
        from blackarch_ai.agents.directory import AgentDirectory
        from blackarch_ai.llm.gateway import ModelGateway

        eng_id = engagement.id if engagement is not None else None
        gw = ModelGateway(self.settings,
                          recorder=self.store.recorder(engagement_id=eng_id, session_id=session_id))
        registry = self.registry if self.ensure_registry() else None
        return (AgentDirectory(self.domains, self.settings, gw, registry),
                MessageBus(self.store, eng_id))

    def ensure_registry(self) -> bool:
        """Scan on first use. Returns False if discovery is impossible (no pacman)."""
        from blackarch_ai.tools.pacman import PacmanUnavailable

        reg = self.registry
        if reg.last_scan() is None:
            console.print("[dim]No tool registry yet — scanning installed packages…[/]")
            try:
                self.scan_tools()
            except PacmanUnavailable as exc:
                err_console.print(f"[red]{exc}[/]")
                return False
        elif reg.is_stale():
            console.print("[yellow]Packages changed since the last scan — run "
                          "[bold]blackarch-ai tools scan[/] to refresh.[/]")
        return True


def fmt_cost(cost: float | None) -> str:
    if cost is None:
        return "cost unknown"
    if cost == 0:
        return "$0"
    return f"${cost:.4f}" if cost < 1 else f"${cost:.2f}"


def fmt_tokens(n: int) -> str:
    return f"{n / 1000:.1f}k" if n >= 10_000 else str(n)


def fmt_totals(t: UsageTotals) -> str:
    cost = fmt_cost(t.cost_usd) if t.unpriced_calls == 0 else (
        f"{fmt_cost(t.cost_usd)} + {t.unpriced_calls} unpriced call(s)"
        if t.cost_usd else "cost unknown"
    )
    failed = f", {t.failed} failed" if t.failed else ""
    return (f"{t.calls} call(s){failed} · {fmt_tokens(t.prompt_tokens)} in / "
            f"{fmt_tokens(t.completion_tokens)} out · {cost}")


def not_yet(feature: str, phase: str) -> str:
    return f"[yellow]{feature} is not implemented yet[/] (planned for {phase})."
