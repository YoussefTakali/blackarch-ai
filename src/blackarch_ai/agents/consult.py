"""Consult an agent, delivering its help requests to peer agents.

One hop only: an agent's help requests are answered by the peers, but the
peers' own help requests are not followed (the Phase 4 orchestrator will own
multi-step coordination and dependencies). Every hand-off is a bus message.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from blackarch_ai.agents.base import AgentContext
from blackarch_ai.agents.bus import MessageBus
from blackarch_ai.agents.directory import AgentDirectory
from blackarch_ai.agents.schema import CheckedReport
from blackarch_ai.llm.gateway import GatewayError, LLMResult
from blackarch_ai.security.scope import Scope
from blackarch_ai.storage.models import Engagement


@dataclass
class Consultation:
    agent_id: str
    task_id: int
    question: str
    report: CheckedReport | None = None
    result: LLMResult | None = None
    error: str | None = None
    asked_by: str = "user"
    replies: list[Consultation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.report is not None


def _help_task(asker: str, question: str, original: str) -> str:
    return (f"The {asker} agent asks for your expertise:\n{question}\n\n"
            f"Context — the task {asker} is working on:\n{original}")


async def consult(
    directory: AgentDirectory,
    bus: MessageBus,
    agent_id: str,
    question: str,
    *,
    engagement: Engagement | None,
    scope: Scope | None,
    requested_by: str = "user",
    follow_help: bool = True,
    parent_id: int | None = None,
) -> Consultation:
    agent = directory.get(agent_id)
    task = bus.create_task(agent.id, question, requested_by, parent_id)
    kind = "task" if parent_id is None else "help_request"
    bus.post(requested_by, agent.id, kind, question, task_id=task.id)
    ctx = AgentContext(engagement=engagement, scope=scope, inbox=bus.inbox(agent.id),
                       peers=directory.ids())
    out = Consultation(agent.id, task.id, question, asked_by=requested_by)
    try:
        report, result = await agent.run(question, ctx)
    except GatewayError as exc:
        bus.fail_task(task.id, str(exc))
        bus.post(agent.id, requested_by, "error", str(exc)[:1000], task_id=task.id)
        out.error = str(exc)
        return out

    out.report, out.result = report, result
    bus.finish_task(task.id, report.model_dump(mode="json"), report.issues, result.model)
    reply_kind = "result" if parent_id is None else "help_reply"
    bus.post(agent.id, requested_by, reply_kind, report.summary, task_id=task.id)

    if follow_help and report.help_requests:
        out.replies = list(await asyncio.gather(*(
            consult(directory, bus, h.to_agent, _help_task(agent.id, h.question, question),
                    engagement=engagement, scope=scope, requested_by=agent.id,
                    follow_help=False, parent_id=task.id)
            for h in report.help_requests
        )))
    return out


def all_results(c: Consultation) -> list[LLMResult]:
    out = [c.result] if c.result else []
    for r in c.replies:
        out.extend(all_results(r))
    return out
