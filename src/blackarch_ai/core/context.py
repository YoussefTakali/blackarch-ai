"""Shared engagement context: assets and findings agents accumulate.

Later agent tasks receive a digest of what earlier ones found, plus any tool
output recorded as findings, so they don't rediscover the same ground.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from blackarch_ai.storage.models import Asset, Finding
from blackarch_ai.storage.store import Store

SEVERITIES = ["info", "low", "medium", "high", "critical"]
CONFIDENCES = ["low", "medium", "high"]


@dataclass
class ContextStore:
    store: Store
    engagement_id: int | None

    # -- assets

    def add_asset(self, kind: str, value: str, *, source: str = "", notes: str = "") -> Asset:
        value = value.strip()
        with self.store.session() as s, s.begin():
            existing = s.scalars(
                select(Asset).where(Asset.engagement_id == self.engagement_id)
                .where(Asset.kind == kind).where(Asset.value == value)
            ).first()
            if existing is not None:
                return existing
            asset = Asset(engagement_id=self.engagement_id, kind=kind, value=value,
                          source=source, notes=notes)
            s.add(asset)
        return asset

    def assets(self, limit: int = 100) -> list[Asset]:
        with self.store.session() as s:
            q = select(Asset).where(Asset.engagement_id == self.engagement_id).limit(limit)
            return list(s.scalars(q).all())

    # -- findings

    def add_finding(self, title: str, *, description: str = "", severity: str = "info",
                    confidence: str = "low", verified: bool = False, agent: str = "",
                    plan_id: int | None = None, source_task_id: int | None = None) -> Finding:
        if severity not in SEVERITIES:
            severity = "info"
        if confidence not in CONFIDENCES:
            confidence = "low"
        finding = Finding(engagement_id=self.engagement_id, title=title.strip()[:300],
                          description=description, severity=severity, confidence=confidence,
                          verified=verified, agent=agent, plan_id=plan_id,
                          source_task_id=source_task_id)
        with self.store.session() as s, s.begin():
            s.add(finding)
        return finding

    def findings(self, limit: int = 200) -> list[Finding]:
        with self.store.session() as s:
            q = (select(Finding).where(Finding.engagement_id == self.engagement_id)
                 .order_by(Finding.id).limit(limit))
            return list(s.scalars(q).all())

    # -- digest for agents

    def digest(self, max_assets: int = 40, max_findings: int = 40) -> str:
        assets = self.assets(max_assets)
        findings = self.findings(max_findings)
        if not assets and not findings:
            return ""
        lines = ["Shared engagement context so far:"]
        if assets:
            lines.append("Known assets:")
            lines += [f"- {a.kind}: {a.value}" + (f" ({a.notes})" if a.notes else "")
                      for a in assets]
        if findings:
            lines.append("Findings (unverified unless marked):")
            for f in findings:
                mark = "verified" if f.verified else f"{f.confidence} confidence"
                lines.append(f"- [{f.severity}, {mark}] {f.title}"
                             + (f" — {f.description[:200]}" if f.description else ""))
        return "\n".join(lines)
