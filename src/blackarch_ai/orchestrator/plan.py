"""The orchestrator's task plan (its structured LLM output) and validation."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PlanStepOut(BaseModel):
    agent_id: str = Field(description="Which specialist agent handles this step")
    objective: str = Field(description="What this agent should investigate or determine")
    depends_on: list[int] = Field(
        default_factory=list,
        description="1-based indices of earlier steps whose results this one needs",
    )


class PlanOutput(BaseModel):
    summary: str = Field(description="One or two sentences describing the approach")
    steps: list[PlanStepOut] = Field(description="Ordered steps; keep it focused (2–6 steps)")


class PlanError(ValueError):
    pass


def validate_plan(plan: PlanOutput, valid_agents: set[str]) -> list[str]:
    """Drop impossible steps; return warnings. Never raises for model mistakes."""
    warnings: list[str] = []
    kept: list[PlanStepOut] = []
    index_map: dict[int, int] = {}  # old 1-based index -> new 1-based index
    for i, step in enumerate(plan.steps, 1):
        if step.agent_id not in valid_agents:
            warnings.append(f"step {i}: unknown or disabled agent {step.agent_id!r} — dropped")
            continue
        deps = []
        for d in step.depends_on:
            if d >= i:
                warnings.append(f"step {i}: dependency {d} is not an earlier step — ignored")
            elif d in index_map:
                deps.append(index_map[d])
            elif 1 <= d < i:
                warnings.append(f"step {i}: depends on dropped step {d} — ignored")
            else:
                warnings.append(f"step {i}: bad dependency {d} — ignored")
        step.depends_on = deps
        kept.append(step)
        index_map[i] = len(kept)
    plan.steps = kept
    if not kept:
        raise PlanError("the plan had no runnable steps")
    return warnings
