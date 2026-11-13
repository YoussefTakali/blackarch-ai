"""SQLite schema.

Later phases add the
reporting layer on top of these.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class Engagement(Base):
    __tablename__ = "engagement"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    objective: Mapped[str] = mapped_column(Text, default="")
    authorized_by: Mapped[str] = mapped_column(String(200), default="")
    # Serialized blackarch_ai.security.scope.Scope
    scope: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions: Mapped[list[ChatSession]] = relationship(back_populates="engagement")


class ChatSession(Base):
    __tablename__ = "chat_session"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    engagement: Mapped[Engagement | None] = relationship(back_populates="sessions")
    messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="session", order_by="ChatMessage.id"
    )


class ChatMessage(Base):
    __tablename__ = "chat_message"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("chat_session.id"), index=True)
    role: Mapped[str] = mapped_column(String(20))  # user | assistant
    content: Mapped[str] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    interrupted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    session: Mapped[ChatSession] = relationship(back_populates="messages")


class ModelUsage(Base):
    __tablename__ = "model_usage"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("chat_session.id"), nullable=True)
    role: Mapped[str] = mapped_column(String(50))
    model: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(50))
    success: Mapped[bool] = mapped_column(Boolean)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0)
    reasoning_tokens: Mapped[int] = mapped_column(Integer, default=0)
    tokens_estimated: Mapped[bool] = mapped_column(Boolean, default=False)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    session_id: Mapped[int | None] = mapped_column(ForeignKey("chat_session.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(50))  # user | system | orchestrator | <agent id>
    action: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Tool(Base):
    """One installed package from the latest discovery scan (Phase 2)."""

    __tablename__ = "tool"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    version: Mapped[str] = mapped_column(String(80), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(300), default="")
    source: Mapped[str] = mapped_column(String(20))  # blackarch | arch
    categories: Mapped[list[Any]] = mapped_column(JSON, default=list)
    agents: Mapped[list[Any]] = mapped_column(JSON, default=list)
    executables: Mapped[list[Any]] = mapped_column(JSON, default=list)
    man_pages: Mapped[list[Any]] = mapped_column(JSON, default=list)
    permission: Mapped[str] = mapped_column(String(20), default="unclassified")
    summary: Mapped[str] = mapped_column(Text, default="")
    installed: Mapped[bool] = mapped_column(Boolean, default=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolScan(Base):
    __tablename__ = "tool_scan"

    id: Mapped[int] = mapped_column(primary_key=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    duration_s: Mapped[float] = mapped_column(Float)
    tools: Mapped[int] = mapped_column(Integer)
    executables: Mapped[int] = mapped_column(Integer)
    man_pages: Mapped[int] = mapped_column(Integer)
    pacman_db_mtime: Mapped[float | None] = mapped_column(Float, nullable=True)
    warnings: Mapped[list[Any]] = mapped_column(JSON, default=list)


class AgentTask(Base):
    """One unit of work given to an agent (Phase 3)."""

    __tablename__ = "agent_task"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("agent_task.id"), nullable=True)
    agent_id: Mapped[str] = mapped_column(String(50), index=True)
    requested_by: Mapped[str] = mapped_column(String(50))  # user | orchestrator | <agent id>
    input: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running|done|failed
    report: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    issues: Mapped[list[Any]] = mapped_column(JSON, default=list)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentMessage(Base):
    """Immutable inter-agent message. Agents communicate only through these."""

    __tablename__ = "agent_message"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("agent_task.id"), nullable=True)
    sender: Mapped[str] = mapped_column(String(50))
    recipient: Mapped[str] = mapped_column(String(50), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # task | result | help_request | help_reply
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    """A user decision on a proposed execution (Phase 5)."""

    __tablename__ = "approval"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    operation: Mapped[str] = mapped_column(String(80))
    argv: Mapped[list[Any]] = mapped_column(JSON)
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    permission: Mapped[str] = mapped_column(String(20))
    decision: Mapped[str] = mapped_column(String(20))  # approved | rejected
    decided_by: Mapped[str] = mapped_column(String(50), default="user")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolExecution(Base):
    """One run of a registered operation through the execution engine (Phase 5)."""

    __tablename__ = "tool_execution"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("approval.id"), nullable=True)
    requested_by: Mapped[str] = mapped_column(String(50), default="user")
    operation: Mapped[str] = mapped_column(String(80))
    tool: Mapped[str] = mapped_column(String(120))
    argv: Mapped[list[Any]] = mapped_column(JSON)
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    permission: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))  # success|failed|timeout|cancelled|error
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    stdout_bytes: Mapped[int] = mapped_column(Integer, default=0)
    stderr_bytes: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence: Mapped[list[Evidence]] = relationship(back_populates="execution")


class Evidence(Base):
    """A file produced by an execution (stdout/stderr or an output artifact)."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("tool_execution.id"), index=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(20))  # stdout | stderr | artifact
    path: Mapped[str] = mapped_column(String(500))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    execution: Mapped[ToolExecution] = relationship(back_populates="evidence")


class Plan(Base):
    """An orchestration plan: a goal broken into agent tasks (Phase 4)."""

    __tablename__ = "plan"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    objective: Mapped[str] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, default="")
    steps: Mapped[list[Any]] = mapped_column(JSON, default=list)   # as generated, for display
    status: Mapped[str] = mapped_column(String(20), default="planned")  # planned|running|done|failed
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ProposedOperation(Base):
    """An operation an agent recommended, awaiting a decision (the approval queue)."""

    __tablename__ = "proposed_operation"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plan.id"), nullable=True)
    source_agent: Mapped[str] = mapped_column(String(50))
    source_task_id: Mapped[int | None] = mapped_column(ForeignKey("agent_task.id"), nullable=True)
    operation: Mapped[str] = mapped_column(String(80))
    target: Mapped[str | None] = mapped_column(String(300), nullable=True)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    permission: Mapped[str] = mapped_column(String(20))
    rationale: Mapped[str] = mapped_column(Text, default="")
    argv: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # pending | approved | rejected | executed | blocked | needs_params | auto
    status: Mapped[str] = mapped_column(String(20), default="pending")
    note: Mapped[str] = mapped_column(Text, default="")
    execution_id: Mapped[int | None] = mapped_column(ForeignKey("tool_execution.id"), nullable=True)
    decided_by: Mapped[str] = mapped_column(String(50), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    """Something discovered in scope during an engagement (shared context)."""

    __tablename__ = "asset"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(20))  # host|service|url|domain
    value: Mapped[str] = mapped_column(String(300))
    source: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    """A recorded observation. Agent findings are unverified until execution confirms."""

    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    engagement_id: Mapped[int | None] = mapped_column(ForeignKey("engagement.id"), nullable=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plan.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info")  # info|low|medium|high|critical
    confidence: Mapped[str] = mapped_column(String(20), default="low")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    agent: Mapped[str] = mapped_column(String(50), default="")
    source_task_id: Mapped[int | None] = mapped_column(ForeignKey("agent_task.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
