"""Optional model-written executive summary, drawn only from the report data."""

from __future__ import annotations

from pydantic import BaseModel, Field

from blackarch_ai.llm.gateway import ModelGateway
from blackarch_ai.reports.report import ExecSummary, ReportData

_PROMPT = """\
You are the reporting agent for an AUTHORIZED security assessment. Write a brief \
executive summary from ONLY the data provided — do not invent findings, CVEs, \
hosts or results. Treat hypotheses as unverified and say so; never present them \
as confirmed vulnerabilities. Prioritise remediation by the evidence actually \
collected. Be concise and factual."""


class _Summary(BaseModel):
    overview: str = Field(description="3–5 sentences summarising scope, what was done and found")
    recommendations: list[str] = Field(default_factory=list,
                                        description="Prioritised, concrete next steps")


def _facts(r: ReportData) -> str:
    lines = [f"Engagement: {r.engagement_name}", f"Objective: {r.objective or '—'}",
             f"Scope: {r.scope}", "", "Assets:"]
    lines += [f"- {a.kind}: {a.value}" for a in r.assets] or ["- none"]
    lines += ["", "Verified results:"]
    lines += [f"- [{f.severity}] {f.title}" + (f" — {f.description[:200]}" if f.description else "")
              for f in r.verified] or ["- none"]
    lines += ["", "Hypotheses (UNVERIFIED):"]
    lines += [f"- [{f.severity}, {f.confidence}] {f.title}" for f in r.hypotheses] or ["- none"]
    lines += ["", "Operations run:"]
    lines += [f"- #{e.id} {e.operation} on {e.target or '—'}: {e.status}" for e in r.executions] \
        or ["- none"]
    return "\n".join(lines)


async def generate_summary(gateway: ModelGateway, r: ReportData,
                           role: str = "reporting") -> ExecSummary:
    result = await gateway.complete(
        [{"role": "system", "content": _PROMPT},
         {"role": "user", "content": _facts(r)}],
        role=role, response_model=_Summary,
    )
    s: _Summary = result.parsed
    return ExecSummary(overview=s.overview, recommendations=s.recommendations, model=result.model)
