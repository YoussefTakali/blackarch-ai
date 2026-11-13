"""Persistent message bus and task log for agents.

Messages are append-only records; nothing here lets one agent change another
agent's state.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select

from blackarch_ai.storage.models import AgentMessage, AgentTask, utcnow
from blackarch_ai.storage.store import Store

KINDS = {"task", "result", "help_request", "help_reply", "error"}


class MessageBus:
    def __init__(self, store: Store, engagement_id: int | None) -> None:
        self.store = store
        self.engagement_id = engagement_id

    # -- messages

    def post(self, sender: str, recipient: str, kind: str, content: str,
             *, task_id: int | None = None) -> AgentMessage:
        if kind not in KINDS:
            raise ValueError(f"unknown message kind {kind!r}")
        msg = AgentMessage(engagement_id=self.engagement_id, task_id=task_id, sender=sender,
                           recipient=recipient, kind=kind, content=content)
        with self.store.session() as s, s.begin():
            s.add(msg)
        return msg

    def _scoped(self, q):  # noqa: ANN001
        if self.engagement_id is None:
            return q.where(AgentMessage.engagement_id.is_(None))
        return q.where(AgentMessage.engagement_id == self.engagement_id)

    def inbox(self, recipient: str, limit: int = 10) -> list[AgentMessage]:
        """Recent help replies and results addressed to `recipient` in this engagement."""
        q = self._scoped(
            select(AgentMessage)
            .where(AgentMessage.recipient == recipient)
            .where(AgentMessage.kind.in_(["help_reply", "result"]))
            .order_by(AgentMessage.id.desc()).limit(limit)
        )
        with self.store.session() as s:
            return list(reversed(s.scalars(q).all()))

    def thread(self, task_ids: list[int]) -> list[AgentMessage]:
        with self.store.session() as s:
            return list(s.scalars(
                select(AgentMessage).where(AgentMessage.task_id.in_(task_ids))
                .order_by(AgentMessage.id)
            ).all())

    def recent(self, agent_id: str | None = None, limit: int = 30) -> list[AgentMessage]:
        q = select(AgentMessage).order_by(AgentMessage.id.desc()).limit(limit)
        q = self._scoped(q)
        if agent_id:
            q = q.where(or_(AgentMessage.sender == agent_id, AgentMessage.recipient == agent_id))
        with self.store.session() as s:
            return list(reversed(s.scalars(q).all()))

    # -- tasks

    def create_task(self, agent_id: str, text: str, requested_by: str,
                    parent_id: int | None = None) -> AgentTask:
        task = AgentTask(engagement_id=self.engagement_id, agent_id=agent_id,
                         requested_by=requested_by, input=text, parent_id=parent_id)
        with self.store.session() as s, s.begin():
            s.add(task)
        self.store.audit(requested_by, "agent.task", {"agent": agent_id, "task": task.id},
                         engagement_id=self.engagement_id)
        return task

    def finish_task(self, task_id: int, report: dict[str, Any], issues: list[str],
                    model: str) -> None:
        with self.store.session() as s, s.begin():
            t = s.get(AgentTask, task_id)
            t.status, t.report, t.issues, t.model = "done", report, issues, model
            t.finished_at = utcnow()

    def fail_task(self, task_id: int, error: str) -> None:
        with self.store.session() as s, s.begin():
            t = s.get(AgentTask, task_id)
            t.status, t.error, t.finished_at = "failed", error[:2000], utcnow()

    def tasks(self, limit: int = 20) -> list[AgentTask]:
        q = select(AgentTask).order_by(AgentTask.id.desc()).limit(limit)
        q = (q.where(AgentTask.engagement_id.is_(None)) if self.engagement_id is None
             else q.where(AgentTask.engagement_id == self.engagement_id))
        with self.store.session() as s:
            return list(s.scalars(q).all())

    def get_task(self, task_id: int) -> AgentTask | None:
        with self.store.session() as s:
            return s.get(AgentTask, task_id)

    def children(self, task_id: int) -> list[AgentTask]:
        with self.store.session() as s:
            return list(s.scalars(select(AgentTask).where(AgentTask.parent_id == task_id)
                                  .order_by(AgentTask.id)).all())
