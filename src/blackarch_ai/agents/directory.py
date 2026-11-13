"""Agent registration.

Every domain in data/agents.toml becomes an `Agent`. A specialised subclass can
replace the default for one id:

    @register_agent("web")
    class WebAgent(Agent):
        ...

Agents disabled in config.toml ([agents.<id>] enabled = false) are left out.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from blackarch_ai.agents.base import Agent
from blackarch_ai.config import Settings
from blackarch_ai.core.domains import DomainMap
from blackarch_ai.llm.gateway import ModelGateway

if TYPE_CHECKING:
    from blackarch_ai.tools.registry import Registry

_CUSTOM: dict[str, type[Agent]] = {}


def register_agent(agent_id: str):
    def deco(cls: type[Agent]) -> type[Agent]:
        if not issubclass(cls, Agent):
            raise TypeError("registered agents must subclass Agent")
        _CUSTOM[agent_id] = cls
        return cls

    return deco


class UnknownAgent(KeyError):
    pass


class AgentDirectory:
    def __init__(
        self,
        domains: DomainMap,
        settings: Settings,
        gateway: ModelGateway,
        registry: Registry | None,
    ) -> None:
        self.domains = domains
        self.settings = settings
        self._agents: dict[str, Agent] = {}
        self.disabled: list[str] = []
        known = {d.id for d in domains.agents}
        unknown = set(settings.agents) - known
        if unknown:
            raise UnknownAgent(f"[agents.*] in config.toml names unknown agents: {sorted(unknown)}")
        for d in domains.agents:
            override = settings.agent(d.id)
            if not override.enabled:
                self.disabled.append(d.id)
                continue
            cls = _CUSTOM.get(d.id, Agent)
            self._agents[d.id] = cls(d, gateway=gateway, registry=registry, override=override)

    def ids(self) -> list[str]:
        return list(self._agents)

    def all(self) -> list[Agent]:
        return list(self._agents.values())

    def get(self, agent_id: str) -> Agent:
        if agent_id in self._agents:
            return self._agents[agent_id]
        if agent_id in self.disabled:
            raise UnknownAgent(f"agent {agent_id!r} is disabled in config.toml")
        raise UnknownAgent(f"no agent {agent_id!r}; available: {', '.join(self._agents)}")
