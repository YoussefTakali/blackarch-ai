"""Structured agent input/output.

`AgentReport` is what the model must return (validated by the gateway).
`CheckedStep`/`CheckedReport` are the same data after local policy checks —
the only form the rest of the application uses.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from blackarch_ai.security.permissions import Permission

Confidence = Literal["low", "medium", "high"]


# ---------------------------------------------------------------- model output


class RecommendedStep(BaseModel):
    title: str = Field(description="Short name of the step")
    purpose: str = Field(description="What this step establishes and why it is needed")
    tool: str | None = Field(None, description="Exact installed package or command name, or null")
    target: str | None = Field(None, description="Host, network or URL the step touches, or null")
    permission: Permission = Field(description="passive | low | intrusive | high_impact")


class Hypothesis(BaseModel):
    statement: str
    confidence: Confidence
    basis: str = Field(description="The evidence or reasoning behind it")


class HelpRequest(BaseModel):
    to_agent: str = Field(description="Agent id of the specialist to ask")
    question: str


class AgentReport(BaseModel):
    summary: str = Field(description="Two or three sentences answering the task")
    analysis: str = Field(description="Reasoning, in Markdown")
    steps: list[RecommendedStep] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    help_requests: list[HelpRequest] = Field(default_factory=list)
    out_of_scope_notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- after local checks


ToolStatus = Literal["installed", "other_agent", "not_installed", "none"]
ScopeStatus = Literal["in_scope", "out_of_scope", "no_engagement", "none"]


class CheckedStep(RecommendedStep):
    tool_status: ToolStatus = "none"
    tool_package: str | None = None
    scope_status: ScopeStatus = "none"
    scope_reason: str = ""
    requires_approval: bool = False
    exceeds_ceiling: bool = False
    blocked: bool = False  # never eligible for execution (e.g. out of scope)
    notes: list[str] = Field(default_factory=list)


class CheckedHypothesis(Hypothesis):
    verified: Literal[False] = False  # nothing can be verified without execution


class CheckedReport(BaseModel):
    agent_id: str
    summary: str
    analysis: str
    steps: list[CheckedStep]
    hypotheses: list[CheckedHypothesis]
    help_requests: list[HelpRequest]
    out_of_scope_notes: list[str]
    issues: list[str] = Field(default_factory=list)  # problems the local checks found
