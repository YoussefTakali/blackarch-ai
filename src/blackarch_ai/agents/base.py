"""Base specialist agent.

An agent turns a task into an `AgentReport` using its own model profile, then
the report goes through local policy checks that do not depend on the model:

* recommended tools must exist in the registry,
* targets must be inside the engagement scope (otherwise the step is blocked),
* a step above the agent's permission ceiling is blocked,
* intrusive and high-impact steps are marked as needing approval,
* tools from high-impact categories raise the step to high_impact,
* hypotheses are always unverified (agents cannot execute anything yet),
* help requests may only go to other enabled agents.

Agents never touch each other's state; they communicate through the message
bus (see `consult.py`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from blackarch_ai.agents.schema import (
    AgentReport,
    CheckedHypothesis,
    CheckedReport,
    CheckedStep,
    HelpRequest,
)
from blackarch_ai.config import AgentOverride
from blackarch_ai.core.domains import AgentDomain
from blackarch_ai.llm.gateway import LLMResult, ModelGateway
from blackarch_ai.llm.rewriter import COMPLIANCE_CONTEXT, rewrite
from blackarch_ai.security.permissions import Permission, highest
from blackarch_ai.security.scope import Scope

if TYPE_CHECKING:
    from blackarch_ai.storage.models import AgentMessage, Engagement
    from blackarch_ai.tools.registry import Registry

MAX_HELP_REQUESTS = 3
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVE_RULE_OTHERS = ("Do not cite CVE identifiers or claim specific vulnerabilities from memory. "
                   "For version/vulnerability questions send a help_request to vulnintel.")
CVE_RULE_VULNINTEL = ("CVE identifiers you cite come from memory and are unverified: give each "
                      "as a hypothesis with its affected version range, never above medium "
                      "confidence, and say it must be checked against NVD or the vendor "
                      "advisory. If unsure of an ID, describe the issue without one.")

BASE_PROMPT = """\
You are the {name} agent ({id}) in BlackArch AI, a team of specialist agents \
supporting an AUTHORIZED security assessment run from a BlackArch Linux machine.

Your domain: {description}

How you work:
- You advise. You cannot execute commands or reach any system, and you have not \
observed anything that isn't in the context below. Anything you infer is a \
hypothesis with a confidence level, never a confirmed finding.
- Plan only against targets in the authorized scope. Put anything outside it in \
out_of_scope_notes and do not plan steps for it.
- Prefer tools from the installed list below; name them exactly as listed. If \
nothing installed fits, set tool to null and describe the technique.
- Classify every step: passive (analysing data already collected, no contact \
with targets), low (light standard interaction such as a single service probe), \
intrusive (active testing that may affect targets or raise alerts), high_impact \
(could disrupt services or change data/systems).
- Your ceiling is {ceiling}. Do not propose steps above it; if one is needed, \
ask the right specialist with a help_request instead.
- A step that sends anything to a target is at least low; passive means no \
contact with the target at all.
- {cve_rule}
- Choose the least intrusive way to answer. No persistence, evasion, or \
destructive actions.
- {compliance}
- Ask another specialist (help_requests, at most {max_help}) only when their \
expertise is genuinely needed. Valid agent ids: {peers}.

{engagement}

Installed tools in your domain ({n_tools}): {tool_names}

{tool_matches}{extra}"""


@dataclass
class AgentContext:
    """Read-only view of the engagement given to an agent for one task."""

    engagement: Engagement | None
    scope: Scope | None
    inbox: list[AgentMessage] = field(default_factory=list)  # messages addressed to this agent
    peers: list[str] = field(default_factory=list)  # enabled agent ids it may ask


class Agent:
    def __init__(
        self,
        domain: AgentDomain,
        *,
        gateway: ModelGateway,
        registry: Registry | None,
        override: AgentOverride | None = None,
    ) -> None:
        self.domain = domain
        self.gateway = gateway
        self.registry = registry
        self.override = override or AgentOverride()
        ceiling = domain.max_permission
        if self.override.max_permission:
            lowered = Permission(self.override.max_permission)
            # Config may lower a ceiling but never raise it.
            ceiling = lowered if lowered.rank < ceiling.rank else ceiling
        self.max_permission = ceiling

    # -- identity

    @property
    def id(self) -> str:
        return self.domain.id

    @property
    def name(self) -> str:
        return self.domain.name

    @property
    def description(self) -> str:
        return self.domain.description

    def __repr__(self) -> str:
        return f"<Agent {self.id}>"

    # -- tools

    def tool_names(self) -> list[str]:
        if self.registry is None:
            return []
        names = {t.name for t in self.registry.list(agent=self.id)}
        names |= {t.name for t in self.registry.list(agent="shared")}
        return sorted(names)

    def _tool_matches(self, task: str) -> str:
        if self.registry is None:
            return ""
        hits = [h for h in self.registry.search(task, 25)
                if self.id in h.tool.agents or "shared" in h.tool.agents][:6]
        if not hits:
            return ""
        lines = []
        for h in hits:
            t = h.tool
            cmds = ", ".join(p.rsplit("/", 1)[-1] for p in t.executables[:3]) or "no command"
            flag = " [HIGH-IMPACT]" if t.permission == "high_impact" else ""
            lines.append(f"- {t.name} {t.version}{flag} (commands: {cmds}): {t.description}")
        return "Installed tools most relevant to this task:\n" + "\n".join(lines) + "\n\n"

    # -- prompting

    def system_prompt(self, ctx: AgentContext, task: str = "") -> str:
        if ctx.engagement is None or ctx.scope is None:
            engagement = ("No engagement is selected, so no target is authorized. Give "
                          "methodology only; any step with a target will be blocked.")
        else:
            engagement = (f"Engagement: {ctx.engagement.name}\n"
                          f"Objective: {ctx.engagement.objective or '(not stated)'}\n"
                          f"Authorized scope — {ctx.scope.summary()}")
        names = self.tool_names()
        shown = names[: self.override.max_tool_names]
        tool_names = ", ".join(shown) if shown else "(registry unavailable)"
        if len(names) > len(shown):
            tool_names += f", … (+{len(names) - len(shown)} more)"
        extra = f"Additional instructions:\n{self.override.extra_instructions}\n" \
            if self.override.extra_instructions else ""
        return BASE_PROMPT.format(
            name=self.name, id=self.id, description=self.description,
            ceiling=self.max_permission.value, max_help=MAX_HELP_REQUESTS,
            peers=", ".join(p for p in ctx.peers if p != self.id) or "(none)",
            engagement=engagement, n_tools=len(names), tool_names=tool_names,
            tool_matches=self._tool_matches(task) if task else "", extra=extra,
            cve_rule=CVE_RULE_VULNINTEL if self.id == "vulnintel" else CVE_RULE_OTHERS,
            compliance=COMPLIANCE_CONTEXT,
        ).strip()

    def messages(self, task: str, ctx: AgentContext) -> list[dict]:
        msgs = [{"role": "system", "content": self.system_prompt(ctx, task)}]
        if ctx.inbox:
            notes = "\n".join(f"- from {m.sender} ({m.kind}): {m.content[:1500]}"
                              for m in ctx.inbox)
            msgs.append({"role": "user",
                         "content": "Earlier messages addressed to you in this engagement:\n"
                                    + notes})
            msgs.append({"role": "assistant", "content": "Noted."})
        msgs.append({"role": "user", "content": rewrite(task)})
        return msgs

    # -- running

    async def run(self, task: str, ctx: AgentContext) -> tuple[CheckedReport, LLMResult]:
        result = await self.gateway.complete(
            self.messages(task, ctx), role=self.id, response_model=AgentReport
        )
        return self.check(result.parsed, ctx), result

    # -- local policy checks

    def _check_step(self, step, ctx: AgentContext) -> CheckedStep:  # noqa: ANN001
        c = CheckedStep(**step.model_dump())
        level = step.permission

        if step.tool:
            tool = self.registry.get(step.tool) if self.registry is not None else None
            if tool is None:
                c.tool_status = "not_installed"
                c.notes.append(f"{step.tool!r} is not in the tool registry")
            else:
                c.tool_package = tool.name
                c.tool_status = ("installed" if self.id in tool.agents or "shared" in tool.agents
                                 else "other_agent")
                if c.tool_status == "other_agent":
                    c.notes.append(f"{tool.name} belongs to: {', '.join(tool.agents)}")
                if tool.permission == "high_impact" and level != Permission.HIGH_IMPACT:
                    level = Permission.HIGH_IMPACT
                    c.notes.append(f"{tool.name} is a high-impact tool; raised to high_impact")

        if step.target and level == Permission.PASSIVE:
            level = Permission.LOW
            c.notes.append("touches a target, so at least low (passive means no contact)")

        if step.target:
            if ctx.scope is None:
                c.scope_status, c.blocked = "no_engagement", True
                c.scope_reason = "no engagement selected"
            else:
                ok, reason = ctx.scope.check(step.target)
                c.scope_status = "in_scope" if ok else "out_of_scope"
                c.scope_reason = reason
                c.blocked = c.blocked or not ok
        elif level.rank > Permission.PASSIVE.rank:
            c.notes.append("no target given for an active step")

        c.permission = highest(level, step.permission)
        c.requires_approval = c.permission.needs_approval
        if c.permission.exceeds(self.max_permission):
            c.exceeds_ceiling = True
            c.blocked = True
            c.notes.append(f"above this agent's ceiling ({self.max_permission.value})")
        return c

    def check(self, report: AgentReport, ctx: AgentContext) -> CheckedReport:
        issues: list[str] = []
        steps = [self._check_step(s, ctx) for s in report.steps]
        for i, s in enumerate(steps, 1):
            if s.scope_status == "out_of_scope":
                issues.append(f"step {i} targets {s.target!r} outside the scope — blocked")
            if s.exceeds_ceiling:
                issues.append(f"step {i} is {s.permission.value}, above the "
                              f"{self.max_permission.value} ceiling — blocked")
            if s.tool_status == "not_installed":
                issues.append(f"step {i} uses {s.tool!r}, which is not installed")

        text = " ".join([report.summary, report.analysis,
                         *(h.statement + " " + h.basis for h in report.hypotheses),
                         *(s.title + " " + s.purpose for s in report.steps)])
        cves = sorted({m.upper() for m in CVE_RE.findall(text)})
        if cves:
            issues.append(f"cites {', '.join(cves)} from model memory — unverified; check NVD "
                          "or the vendor advisory before relying on it")

        allowed = set(ctx.peers) - {self.id}
        help_requests: list[HelpRequest] = []
        for h in report.help_requests:
            if h.to_agent not in allowed:
                issues.append(f"dropped help request to unknown or unavailable agent "
                              f"{h.to_agent!r}")
            elif len(help_requests) >= MAX_HELP_REQUESTS:
                issues.append(f"dropped extra help request to {h.to_agent!r} "
                              f"(limit {MAX_HELP_REQUESTS})")
            else:
                help_requests.append(h)

        return CheckedReport(
            agent_id=self.id, summary=report.summary, analysis=report.analysis, steps=steps,
            hypotheses=[CheckedHypothesis(**h.model_dump()) for h in report.hypotheses],
            help_requests=help_requests, out_of_scope_notes=report.out_of_scope_notes,
            issues=issues,
        )
