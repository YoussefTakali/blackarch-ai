"""Permission levels, ordered from least to most intrusive."""

from __future__ import annotations

from enum import StrEnum


class Permission(StrEnum):
    PASSIVE = "passive"          # analysis of data already collected; no contact with targets
    LOW = "low"                  # light, standard interaction (e.g. a single service probe)
    INTRUSIVE = "intrusive"      # active testing that may affect targets or raise alerts
    HIGH_IMPACT = "high_impact"  # could disrupt services or change data/systems

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    def exceeds(self, ceiling: Permission) -> bool:
        return self.rank > ceiling.rank

    @property
    def needs_approval(self) -> bool:
        return self.rank >= Permission.INTRUSIVE.rank


_ORDER = [Permission.PASSIVE, Permission.LOW, Permission.INTRUSIVE, Permission.HIGH_IMPACT]


def highest(*levels: Permission) -> Permission:
    return max(levels, key=lambda p: p.rank)
