"""Agent domains: which BlackArch categories each agent owns (data/agents.toml)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from blackarch_ai.security.permissions import Permission


@dataclass(frozen=True)
class AgentDomain:
    id: str
    name: str
    description: str
    categories: tuple[str, ...]
    keywords: tuple[str, ...] = ()
    max_permission: Permission = Permission.LOW


@dataclass
class DomainMap:
    agents: list[AgentDomain]
    shared: tuple[str, ...]
    high_impact: frozenset[str]
    owner: dict[str, str] = field(default_factory=dict)  # category -> agent id | "shared"

    def agent(self, agent_id: str) -> AgentDomain:
        for a in self.agents:
            if a.id == agent_id:
                return a
        raise KeyError(agent_id)

    def all_categories(self) -> set[str]:
        return set(self.owner)


class DomainConfigError(ValueError):
    pass


def _permission(raw: dict) -> Permission:
    value = raw.get("max_permission", "low")
    try:
        return Permission(value)
    except ValueError:
        raise DomainConfigError(
            f"agent {raw.get('id')!r}: max_permission must be one of "
            f"{', '.join(p.value for p in Permission)}"
        ) from None


def load_domains(path: Path | None = None) -> DomainMap:
    if path is None:
        raw = tomllib.loads(
            resources.files("blackarch_ai").joinpath("data/agents.toml").read_text()
        )
    else:
        raw = tomllib.loads(path.read_text())

    agents = [
        AgentDomain(
            id=a["id"], name=a["name"], description=a.get("description", ""),
            categories=tuple(a.get("categories", [])), keywords=tuple(a.get("keywords", [])),
            max_permission=_permission(a),
        )
        for a in raw.get("agent", [])
    ]
    shared = tuple(raw.get("shared", {}).get("categories", []))
    high = frozenset(raw.get("policy", {}).get("high_impact_categories", []))

    ids = [a.id for a in agents]
    if len(ids) != len(set(ids)):
        raise DomainConfigError("duplicate agent id in agents.toml")

    owner: dict[str, str] = {}
    for owner_id, cats in [*((a.id, a.categories) for a in agents), ("shared", shared)]:
        for c in cats:
            if c in owner:
                raise DomainConfigError(
                    f"category {c!r} is assigned to both {owner[c]!r} and {owner_id!r}"
                )
            owner[c] = owner_id
    unknown_high = high - set(owner)
    if unknown_high:
        raise DomainConfigError(f"high_impact_categories not assigned to any agent: {sorted(unknown_high)}")
    return DomainMap(agents=agents, shared=shared, high_impact=high, owner=owner)
