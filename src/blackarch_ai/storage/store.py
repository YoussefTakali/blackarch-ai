"""Data access for the CLI and orchestrator. One Store per process."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from blackarch_ai.llm.gateway import CallRecord
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import (
    AuditEvent,
    Base,
    ChatMessage,
    ChatSession,
    Engagement,
    ModelUsage,
    ToolExecution,
)


class StoreError(RuntimeError):
    pass


@dataclass
class UsageTotals:
    calls: int
    failed: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    unpriced_calls: int  # successful calls whose cost is unknown


class Store:
    def __init__(self, db_path: Path | str) -> None:
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}", future=True)

        @event.listens_for(self.engine, "connect")
        def _pragmas(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

        Base.metadata.create_all(self.engine)
        self._session = sessionmaker(self.engine, expire_on_commit=False)

    def session(self) -> Session:
        return self._session()

    # -- audit

    def audit(
        self,
        actor: str,
        action: str,
        details: dict[str, Any] | None = None,
        *,
        engagement_id: int | None = None,
        session_id: int | None = None,
    ) -> None:
        with self.session() as s, s.begin():
            s.add(AuditEvent(actor=actor, action=action, details=details or {},
                             engagement_id=engagement_id, session_id=session_id))

    def audit_events(self, engagement_id: int | None = None, limit: int = 50) -> list[AuditEvent]:
        with self.session() as s:
            q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
            if engagement_id is not None:
                q = q.where(AuditEvent.engagement_id == engagement_id)
            return list(reversed(s.scalars(q).all()))

    # -- engagements

    def create_engagement(
        self, name: str, scope: Scope, *, objective: str = "", authorized_by: str = ""
    ) -> Engagement:
        name = name.strip()
        if not name:
            raise StoreError("engagement name cannot be empty")
        eng = Engagement(name=name, objective=objective, authorized_by=authorized_by,
                         scope=scope.model_dump())
        try:
            with self.session() as s, s.begin():
                s.add(eng)
        except IntegrityError:
            raise StoreError(f"an engagement named {name!r} already exists") from None
        self.audit("user", "engagement.create",
                   {"name": name, "scope": scope.summary(), "authorized_by": authorized_by,
                    "objective": objective},
                   engagement_id=eng.id)
        return eng

    def list_engagements(self) -> list[Engagement]:
        with self.session() as s:
            return list(s.scalars(select(Engagement).order_by(Engagement.id)).all())

    def get_engagement(self, name_or_id: str | int) -> Engagement:
        with self.session() as s:
            if isinstance(name_or_id, int) or str(name_or_id).isdigit():
                eng = s.get(Engagement, int(name_or_id))
            else:
                eng = s.scalars(select(Engagement).where(Engagement.name == name_or_id)).first()
        if eng is None:
            raise StoreError(f"no engagement {name_or_id!r}")
        return eng

    @staticmethod
    def scope_of(eng: Engagement) -> Scope:
        return Scope.model_validate(eng.scope)

    # -- chat

    def create_chat_session(self, engagement_id: int | None, title: str = "") -> ChatSession:
        cs = ChatSession(engagement_id=engagement_id, title=title)
        with self.session() as s, s.begin():
            s.add(cs)
        self.audit("user", "chat.start", {"title": title},
                   engagement_id=engagement_id, session_id=cs.id)
        return cs

    def get_chat_session(self, session_id: int) -> ChatSession:
        with self.session() as s:
            cs = s.get(ChatSession, session_id)
        if cs is None:
            raise StoreError(f"no chat session {session_id}")
        return cs

    def latest_chat_session(self, engagement_id: int | None) -> ChatSession | None:
        with self.session() as s:
            q = select(ChatSession).order_by(ChatSession.id.desc()).limit(1)
            q = q.where(ChatSession.engagement_id.is_(None) if engagement_id is None
                        else ChatSession.engagement_id == engagement_id)
            return s.scalars(q).first()

    def list_chat_sessions(self, engagement_id: int | None = None, limit: int = 20) -> list[tuple[ChatSession, int]]:
        with self.session() as s:
            q = (
                select(ChatSession, func.count(ChatMessage.id))
                .outerjoin(ChatMessage)
                .group_by(ChatSession.id)
                .order_by(ChatSession.id.desc())
                .limit(limit)
            )
            if engagement_id is not None:
                q = q.where(ChatSession.engagement_id == engagement_id)
            return [(cs, n) for cs, n in s.execute(q).all()]

    def set_session_title(self, session_id: int, title: str) -> None:
        with self.session() as s, s.begin():
            cs = s.get(ChatSession, session_id)
            if cs is not None and not cs.title:
                cs.title = title[:200]

    def add_message(
        self, session_id: int, role: str, content: str, *, model: str | None = None,
        interrupted: bool = False,
    ) -> ChatMessage:
        msg = ChatMessage(session_id=session_id, role=role, content=content, model=model,
                          interrupted=interrupted)
        with self.session() as s, s.begin():
            s.add(msg)
        return msg

    def messages(self, session_id: int) -> list[ChatMessage]:
        with self.session() as s:
            return list(s.scalars(
                select(ChatMessage).where(ChatMessage.session_id == session_id)
                .order_by(ChatMessage.id)
            ).all())

    # -- model usage

    def recorder(self, *, engagement_id: int | None = None, session_id: int | None = None):
        """A gateway Recorder bound to an engagement/session."""

        def record(rec: CallRecord) -> None:
            with self.session() as s, s.begin():
                s.add(ModelUsage(
                    engagement_id=engagement_id, session_id=session_id, role=rec.role,
                    model=rec.model, provider=rec.provider, success=rec.success,
                    prompt_tokens=rec.usage.prompt_tokens,
                    completion_tokens=rec.usage.completion_tokens,
                    reasoning_tokens=rec.usage.reasoning_tokens,
                    tokens_estimated=rec.usage.estimated, cost_usd=rec.cost_usd,
                    latency_ms=rec.latency_ms, error=rec.error,
                ))
                s.add(AuditEvent(
                    actor=rec.role, action="llm.call" if rec.success else "llm.call_failed",
                    engagement_id=engagement_id, session_id=session_id,
                    details={"model": rec.model, "tokens": rec.usage.total,
                             "cost_usd": rec.cost_usd, "latency_ms": rec.latency_ms,
                             "error": rec.error, "redactions": rec.redactions},
                ))

        return record

    # -- executions

    def list_executions(self, *, engagement_id: int | None = None,
                        limit: int = 20) -> list[ToolExecution]:
        with self.session() as s:
            q = select(ToolExecution).order_by(ToolExecution.id.desc()).limit(limit)
            if engagement_id is not None:
                q = q.where(ToolExecution.engagement_id == engagement_id)
            return list(s.scalars(q).all())

    def get_execution(self, exec_id: int) -> ToolExecution | None:
        from sqlalchemy.orm import selectinload

        with self.session() as s:
            return s.scalars(
                select(ToolExecution).where(ToolExecution.id == exec_id)
                .options(selectinload(ToolExecution.evidence))
            ).first()

    def usage_totals(self, *, session_id: int | None = None,
                     engagement_id: int | None = None) -> UsageTotals:
        with self.session() as s:
            q = select(ModelUsage)
            if session_id is not None:
                q = q.where(ModelUsage.session_id == session_id)
            if engagement_id is not None:
                q = q.where(ModelUsage.engagement_id == engagement_id)
            rows = s.scalars(q).all()
        return UsageTotals(
            calls=len(rows),
            failed=sum(not r.success for r in rows),
            prompt_tokens=sum(r.prompt_tokens for r in rows),
            completion_tokens=sum(r.completion_tokens for r in rows),
            cost_usd=sum(r.cost_usd or 0.0 for r in rows),
            unpriced_calls=sum(1 for r in rows if r.success and r.cost_usd is None),
        )
